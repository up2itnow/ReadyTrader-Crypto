import asyncio
import json
import os
import time
from typing import Set

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.core.config import settings

# Import core components from the main server
from app.core.container import global_container
from app.tools.execution import place_cex_order, swap_tokens, transfer_eth
from execution.cex_executor import CexExecutor
from execution.evm import get_web3
from marketdata.store import TickerSnapshot
from observability import build_log_context, log_event

# Initial context
API_CTX = build_log_context(tool="api_server")

app = FastAPI(title="ReadyTrader-Crypto Modern API")

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your frontend domain
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket connections
active_connections: Set[WebSocket] = set()

def broadcast_tick(snap: TickerSnapshot):
    """
    Callback for marketdata_ws_store updates.
    """
    if not active_connections:
        return
        
    payload = {
        "type": "TICKER_UPDATE",
        "data": snap.to_dict()
    }
    
    # We need to run this in the event loop of the FastAPI app
    # Since this callback might be triggered from a background thread
    # We use a global loop reference or call_soon_threadsafe
    loop = asyncio.get_event_loop()
    if loop.is_running():
        loop.create_task(broadcast_all(payload))

async def broadcast_all(payload: dict):
    if not active_connections:
        return
    message = json.dumps(payload)
    disconnected = set()
    for websocket in active_connections:
        try:
            await websocket.send_text(message)
        except Exception:
            disconnected.add(websocket)
            
    for ws in disconnected:
        active_connections.remove(ws)

# Subscribe to ticker updates from the WebSocket store
global_container.marketdata_ws_store.subscribe(broadcast_tick)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    log_event("api_client_connected", ctx=API_CTX, data={"active_connections": len(active_connections)})
    try:
        while True:
            # Keep connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)
        log_event("api_client_disconnected", ctx=API_CTX, data={"active_connections": len(active_connections)})

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "mode": "paper" if settings.PAPER_MODE else "live"}

@app.get("/api/pending-approvals")
async def get_pending_approvals():
    """
    Return list of trades awaiting manual approval.
    """
    return global_container.execution_store.list_pending()

class ApprovalRequest(BaseModel):
    request_id: str
    confirm_token: str
    approve: bool

_approval_lock = asyncio.Lock()

@app.post("/api/approve-trade")
async def approve_trade(req: ApprovalRequest):
    """
    Approve or cancel a pending trade proposal.
    """
    try:
        if req.approve:
            prop = global_container.execution_store.confirm(req.request_id, req.confirm_token)
            # Avoid re-proposing while executing an already-approved action.
            async with _approval_lock:
                old_mode = settings.EXECUTION_APPROVAL_MODE
                try:
                    settings.EXECUTION_APPROVAL_MODE = "auto"
                    payload = dict(prop.payload or {})
                    idem = (payload.get("idempotency_key") or "").strip() or prop.request_id

                    if prop.kind == "swap_tokens":
                        res = swap_tokens(
                            from_token=str(payload["from_token"]),
                            to_token=str(payload["to_token"]),
                            amount=float(payload["amount"]),
                            chain=str(payload.get("chain") or "ethereum"),
                            rationale=str(payload.get("rationale") or ""),
                            idempotency_key=idem,
                        )
                    elif prop.kind == "transfer_eth":
                        res = transfer_eth(
                            to_address=str(payload["to_address"]),
                            amount=float(payload["amount"]),
                            chain=str(payload.get("chain") or "ethereum"),
                            idempotency_key=idem,
                        )
                    elif prop.kind == "place_cex_order":
                        res = place_cex_order(
                            symbol=str(payload["symbol"]),
                            side=str(payload["side"]),
                            amount=float(payload["amount"]),
                            order_type=str(payload.get("order_type") or "market"),
                            price=float(payload["price"]) if payload.get("price") is not None else None,
                            exchange=str(payload.get("exchange") or "binance"),
                            market_type=str(payload.get("market_type") or "spot"),
                            idempotency_key=idem,
                        )
                    else:
                        raise HTTPException(status_code=400, detail=f"Unknown proposal kind: {prop.kind}")

                    # Tool functions return JSON strings; convert to object for API output.
                    return json.loads(res)
                finally:
                    settings.EXECUTION_APPROVAL_MODE = old_mode
        else:
            success = global_container.execution_store.cancel(req.request_id)
            return {"ok": success}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/portfolio")
async def get_portfolio():
    """
    Get current portfolio state (paper or live).
    """
    if settings.PAPER_MODE:
        balances = global_container.paper_engine.get_balances("agent_zero")
        pnl = global_container.paper_engine.get_risk_metrics("agent_zero")
        return {"balances": balances, "metrics": pnl}
    else:
        out = {
            "mode": "live",
            "ts": time.time(),
            "wallet": {"address": global_container.signer.get_address()},
            "onchain": {},
            "cex": {},
        }

        # On-chain native balances (best-effort)
        chains = [c.strip() for c in (os.getenv("PORTFOLIO_CHAINS") or "ethereum").split(",") if c.strip()]
        for chain in chains:
            try:
                w3 = get_web3(chain)
                addr = w3.to_checksum_address(out["wallet"]["address"])
                bal = int(w3.eth.get_balance(addr))
                out["onchain"][chain] = {"native_balance_wei": bal}
            except Exception as e:
                out["onchain"][chain] = {"error": str(e)}

        # CEX balances (best-effort; only for exchanges with creds)
        exchanges = [e.strip() for e in (os.getenv("PORTFOLIO_EXCHANGES") or "binance").split(",") if e.strip()]
        for ex_id in exchanges:
            try:
                ex = CexExecutor(exchange_id=ex_id, market_type="spot", auth=True)
                out["cex"][ex_id] = {"balance": ex.fetch_balance()}
            except Exception as e:
                out["cex"][ex_id] = {"error": str(e)}

        return out

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("API_PORT", 8000))
    host = os.getenv("API_HOST", "127.0.0.1")
    log_event("api_server_started", ctx=API_CTX, data={"port": port, "host": host})
    uvicorn.run(app, host=host, port=port)

import json
from typing import Any, Dict

from fastmcp import FastMCP

from app.core.container import global_container


def _json_ok(data: Dict[str, Any] | None = None) -> str:
    payload = {"ok": True, "data": data or {}}
    return json.dumps(payload, indent=2, sort_keys=True)

def _json_err(code: str, message: str, data: Dict[str, Any] | None = None) -> str:
    payload = {"ok": False, "error": {"code": code, "message": message, "data": data or {}}}
    return json.dumps(payload, indent=2, sort_keys=True)

def register_market_tools(mcp: FastMCP):
    
    @mcp.tool()
    def get_sentiment() -> str:
        """Get the current Crypto Fear & Greed Index."""
        from intelligence import get_fear_greed_index
        return _json_ok({"sentiment": get_fear_greed_index()})

    @mcp.tool()
    def get_news() -> str:
        """Get aggregated crypto market news."""
        from intelligence import get_market_news
        return _json_ok({"news": get_market_news()})

    @mcp.tool()
    def get_crypto_price(symbol: str, exchange: str = "binance") -> str:
        """
        Get the current price of a cryptocurrency.
        """
        try:
            res = global_container.marketdata_bus.fetch_ticker(symbol)
            ticker = res.data
            last_price = ticker.get("last")
            return _json_ok({
                "symbol": symbol, 
                "exchange": exchange, 
                "result": f"The current price of {symbol} is {last_price} (Source: {res.source})"
            })
        except Exception as e:
            return _json_err("fetch_price_error", str(e), {"symbol": symbol})

    @mcp.tool()
    def fetch_ohlcv(symbol: str, timeframe: str = '1h', limit: int = 24) -> str:
        """
        Fetch historical OHLCV data.
        """
        try:
            df = global_container.backtest_engine.fetch_ohlcv(symbol, timeframe, limit)
            return _json_ok(
                {
                    "symbol": symbol,
                    "timeframe": timeframe,
                    "limit": limit,
                    "data": df.to_dict(orient="records"),
                }
            )
        except Exception as e:
            return _json_err("fetch_ohlcv_error", str(e))

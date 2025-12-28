from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ExecutionProposal:
    request_id: str
    confirm_token: str
    kind: str
    payload: Dict[str, Any]
    created_at: float
    expires_at: float
    confirmed_at: Optional[float] = None
    cancelled_at: Optional[float] = None


class ExecutionStore:
    """
    In-memory store for two-step execution proposals.
    Replay protection: proposal can be confirmed only once.
    """

    def __init__(self) -> None:
        self._items: Dict[str, ExecutionProposal] = {}

    def create(self, *, kind: str, payload: Dict[str, Any], ttl_seconds: int = 120) -> ExecutionProposal:
        now = time.time()
        request_id = secrets.token_hex(12)
        confirm_token = secrets.token_hex(16)
        prop = ExecutionProposal(
            request_id=request_id,
            confirm_token=confirm_token,
            kind=kind,
            payload=payload,
            created_at=now,
            expires_at=now + ttl_seconds,
        )
        self._items[request_id] = prop
        return prop

    def get(self, request_id: str) -> Optional[ExecutionProposal]:
        return self._items.get(request_id)

    def list_pending(self) -> Dict[str, Any]:
        now = time.time()
        pending = []
        for p in self._items.values():
            if p.cancelled_at or p.confirmed_at:
                continue
            if p.expires_at <= now:
                continue
            pending.append(
                {
                    "request_id": p.request_id,
                    "kind": p.kind,
                    "created_at": p.created_at,
                    "expires_at": p.expires_at,
                }
            )
        return {"pending": pending}

    def cancel(self, request_id: str) -> bool:
        p = self._items.get(request_id)
        if not p:
            return False
        if p.confirmed_at is not None:
            return False
        if p.cancelled_at is not None:
            return False
        p.cancelled_at = time.time()
        return True

    def confirm(self, request_id: str, confirm_token: str) -> ExecutionProposal:
        p = self._items.get(request_id)
        if not p:
            raise ValueError("Unknown request_id")
        now = time.time()
        if p.expires_at <= now:
            raise ValueError("Proposal expired")
        if p.cancelled_at is not None:
            raise ValueError("Proposal cancelled")
        if p.confirmed_at is not None:
            raise ValueError("Proposal already confirmed")
        if secrets.compare_digest(p.confirm_token, confirm_token) is False:
            raise ValueError("Invalid confirm_token")
        p.confirmed_at = now
        return p


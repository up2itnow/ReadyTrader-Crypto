from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from .base import SignedTx, Signer
from .intents import build_evm_tx_intent


@dataclass(frozen=True)
class _RemoteSignedTx(SignedTx):
    """
    Wire-compatible SignedTx wrapper for remote signing responses.
    """

    rawTransaction: bytes


class RemoteSigner(Signer):
    """
    Remote signer (enterprise-friendly).

    This enables using:
    - a local sidecar signer
    - an internal signing service
    - a KMS/HSM-backed signing proxy

    Protocol (HTTP JSON):
    POST {SIGNER_REMOTE_URL}/sign_transaction
    body: {"tx": {...}, "chain_id": 1}
    response: {"rawTransactionHex": "0x..."}
    """

    def __init__(self, url_env: str = "SIGNER_REMOTE_URL") -> None:
        url = (os.getenv(url_env) or "").strip()
        if not url:
            raise ValueError(f"{url_env} environment variable not set")
        self._base_url = url.rstrip("/")
        self._cached_address: Optional[str] = None

    def get_address(self) -> str:
        # Optional endpoint: /address
        timeout = float(os.getenv("HTTP_TIMEOUT_SEC", "10"))
        if self._cached_address:
            return self._cached_address
        r = requests.get(f"{self._base_url}/address", timeout=timeout)
        r.raise_for_status()
        data = r.json()
        addr = str(data.get("address") or "").strip()
        if not addr:
            raise ValueError("Remote signer returned empty address")
        self._cached_address = addr
        return addr

    def sign_transaction(self, tx: Dict[str, Any], *, chain_id: int | None = None) -> SignedTx:
        timeout = float(os.getenv("HTTP_TIMEOUT_SEC", "10"))
        # Phase 5: include explicit signing intent in the request schema (defense in depth).
        # Remote signer implementations can ignore this field, but enterprise signers can use it
        # for policy enforcement and safer audit logs.
        intent = build_evm_tx_intent(tx, chain_id=chain_id)
        payload = {"tx": tx, "chain_id": chain_id, "intent": intent.to_dict()}
        r = requests.post(f"{self._base_url}/sign_transaction", json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json() if isinstance(r.headers.get("content-type", ""), str) else json.loads(r.text)
        raw_hex: Optional[str] = data.get("rawTransactionHex") or data.get("raw_transaction_hex")
        if not raw_hex:
            raise ValueError("Remote signer did not return rawTransactionHex")
        raw_hex = str(raw_hex).strip()
        if raw_hex.startswith("0x"):
            raw_hex = raw_hex[2:]
        return _RemoteSignedTx(rawTransaction=bytes.fromhex(raw_hex))


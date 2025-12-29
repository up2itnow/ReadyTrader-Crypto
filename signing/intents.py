from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class EvmTxIntent:
    """
    Explicit signing intent (Phase 5).

    Motivation:
    - Avoid ambiguous remote signing requests that just pass an opaque tx dict.
    - Make it easy for remote signers / HSM proxies to enforce policy and log intent safely.

    This is a *description* of what will be signed; it is not the signed transaction.
    """

    intent_type: str  # currently "evm_transaction"
    chain_id: Optional[int]
    to: Optional[str]
    value_wei: Optional[int]
    data_hex: Optional[str]
    gas: Optional[int]
    gas_price_wei: Optional[int]
    nonce: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent_type": self.intent_type,
            "chain_id": self.chain_id,
            "to": self.to,
            "value_wei": self.value_wei,
            "data_hex": self.data_hex,
            "gas": self.gas,
            "gas_price_wei": self.gas_price_wei,
            "nonce": self.nonce,
        }


def build_evm_tx_intent(tx: Dict[str, Any], *, chain_id: int | None) -> EvmTxIntent:
    """
    Best-effort extraction of intent fields from a tx dict.

    Works with common Web3/CCXT-style tx dicts used by ReadyTrader.
    """
    to = tx.get("to")
    if to is not None:
        to = str(to)

    data_hex = tx.get("data")
    if data_hex is not None:
        data_hex = str(data_hex)

    def _to_int(x: Any) -> Optional[int]:
        try:
            if x is None:
                return None
            if isinstance(x, bool):
                return None
            if isinstance(x, int):
                return int(x)
            if isinstance(x, str):
                s = x.strip()
                if s.startswith("0x"):
                    return int(s, 16)
                return int(s)
            return int(x)
        except Exception:
            return None

    return EvmTxIntent(
        intent_type="evm_transaction",
        chain_id=int(chain_id) if chain_id is not None else _to_int(tx.get("chainId")),
        to=to,
        value_wei=_to_int(tx.get("value")),
        data_hex=data_hex,
        gas=_to_int(tx.get("gas")),
        gas_price_wei=_to_int(tx.get("gasPrice")),
        nonce=_to_int(tx.get("nonce")),
    )


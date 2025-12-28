from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Protocol


class SignedTx(Protocol):
    rawTransaction: bytes


class Signer(ABC):
    """
    A minimal signing interface for EVM transactions.
    """

    @abstractmethod
    def get_address(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def sign_transaction(self, tx: Dict[str, Any], *, chain_id: int | None = None) -> SignedTx:
        raise NotImplementedError


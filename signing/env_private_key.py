from __future__ import annotations

import os
from typing import Any, Dict

from eth_account import Account

from .base import SignedTx, Signer


class EnvPrivateKeySigner(Signer):
    """
    Development signer that reads a raw hex private key from PRIVATE_KEY env var.
    """

    def __init__(self, env_var: str = "PRIVATE_KEY") -> None:
        pk = os.getenv(env_var)
        if not pk:
            raise ValueError(f"{env_var} environment variable not set")
        self._account = Account.from_key(pk)

    def get_address(self) -> str:
        return self._account.address

    def sign_transaction(self, tx: Dict[str, Any], *, chain_id: int | None = None) -> SignedTx:
        if chain_id is not None:
            tx = dict(tx)
            tx["chainId"] = chain_id
        return Account.sign_transaction(tx, self._account.key)


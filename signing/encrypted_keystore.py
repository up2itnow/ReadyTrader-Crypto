from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from eth_account import Account

from .base import SignedTx, Signer


class EncryptedKeystoreSigner(Signer):
    """
    Baseline production signer: decrypts an Ethereum keystore JSON using a passphrase.

    Env vars:
    - KEYSTORE_PATH: path to keystore json file
    - KEYSTORE_PASSWORD: passphrase
    """

    def __init__(self, keystore_path_env: str = "KEYSTORE_PATH", password_env: str = "KEYSTORE_PASSWORD") -> None:  # nosec B107
        path_raw = os.getenv(keystore_path_env)
        password = os.getenv(password_env)
        if not path_raw:
            raise ValueError(f"{keystore_path_env} environment variable not set")
        if not password:
            raise ValueError(f"{password_env} environment variable not set")

        path = Path(path_raw).expanduser()
        if not path.exists():
            raise ValueError(f"Keystore file not found: {path}")

        keystore = json.loads(path.read_text())
        pk_bytes = Account.decrypt(keystore, password)
        self._account = Account.from_key(pk_bytes)

    def get_address(self) -> str:
        return self._account.address

    def sign_transaction(self, tx: Dict[str, Any], *, chain_id: int | None = None) -> SignedTx:
        if chain_id is not None:
            tx = dict(tx)
            tx["chainId"] = chain_id
        return Account.sign_transaction(tx, self._account.key)


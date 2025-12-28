from __future__ import annotations

import os
from functools import lru_cache

from .base import Signer
from .encrypted_keystore import EncryptedKeystoreSigner
from .env_private_key import EnvPrivateKeySigner


@lru_cache(maxsize=1)
def get_signer() -> Signer:
    """
    Select signer based on SIGNER_TYPE.

    Supported:
    - env_private_key (default): uses PRIVATE_KEY env var
    - keystore: uses KEYSTORE_PATH + KEYSTORE_PASSWORD
    """
    signer_type = os.getenv("SIGNER_TYPE", "env_private_key").strip().lower()
    if signer_type == "env_private_key":
        return EnvPrivateKeySigner()
    if signer_type == "keystore":
        return EncryptedKeystoreSigner()
    raise ValueError(f"Unsupported SIGNER_TYPE: {signer_type}")


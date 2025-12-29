import os
from unittest.mock import MagicMock

import pytest

from signing.policy import PolicyEnforcedSigner, SignerPolicyViolation, policy_config_from_env


def test_signer_policy_blocks_to_address_allowlist(monkeypatch):
    monkeypatch.setenv("SIGNER_POLICY_ENABLED", "true")
    monkeypatch.setenv("SIGNER_ALLOWED_TO_ADDRESSES", "0xallowed")

    inner = MagicMock()
    inner.get_address.return_value = "0xme"
    inner.sign_transaction.return_value = MagicMock(rawTransaction=b"\x00")

    cfg = policy_config_from_env()
    s = PolicyEnforcedSigner(inner, cfg)

    with pytest.raises(SignerPolicyViolation) as e:
        s.sign_transaction({"to": "0xnotallowed", "value": 0}, chain_id=1)
    assert e.value.code == "to_not_allowed"


def test_signer_policy_allows_when_no_rules(monkeypatch):
    # Ensure env rules are not set
    for k in list(os.environ.keys()):
        if k.startswith("SIGNER_"):
            monkeypatch.delenv(k, raising=False)

    inner = MagicMock()
    inner.get_address.return_value = "0xme"
    inner.sign_transaction.return_value = MagicMock(rawTransaction=b"\x00")

    cfg = policy_config_from_env()
    s = PolicyEnforcedSigner(inner, cfg)
    out = s.sign_transaction({"to": "0xany", "value": 0}, chain_id=1)
    assert out.rawTransaction == b"\x00"


from unittest.mock import MagicMock, patch

import pytest

from signing.remote_signer import RemoteSigner


def test_remote_signer_requires_url():
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(ValueError):
            RemoteSigner()


def test_remote_signer_get_address_and_sign():
    with patch.dict("os.environ", {"SIGNER_REMOTE_URL": "http://signer"}):
        addr_resp = MagicMock()
        addr_resp.json.return_value = {"address": "0xabc"}
        addr_resp.raise_for_status.return_value = None
        addr_resp.headers = {"content-type": "application/json"}

        sign_resp = MagicMock()
        sign_resp.json.return_value = {"rawTransactionHex": "0xdeadbeef"}
        sign_resp.raise_for_status.return_value = None
        sign_resp.headers = {"content-type": "application/json"}

        with patch("signing.remote_signer.requests.get", return_value=addr_resp):
            with patch("signing.remote_signer.requests.post", return_value=sign_resp) as post:
                s = RemoteSigner()
                assert s.get_address() == "0xabc"
                tx = {"to": "0x1", "value": 1}
                signed = s.sign_transaction(tx, chain_id=1)
                assert signed.rawTransaction == bytes.fromhex("deadbeef")
                post.assert_called()


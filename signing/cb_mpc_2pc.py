from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests
import rlp
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from eth_keys import keys
from eth_utils import keccak

from .base import SignedTx, Signer

SECP256K1_N = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)
SECP256K1_HALF_N = SECP256K1_N // 2


def _env(name: str) -> str:
    v = (os.getenv(name) or "").strip()
    if not v:
        raise ValueError(f"{name} environment variable not set")
    return v


def _http_timeout() -> float:
    return float((os.getenv("HTTP_TIMEOUT_SEC") or "10").strip())


def _to_int(v: Any, *, name: str) -> int:
    if v is None:
        raise ValueError(f"Missing required tx field: {name}")
    if isinstance(v, bool):
        raise ValueError(f"Invalid int field {name}: {v}")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s.startswith("0x"):
            return int(s, 16)
        return int(s, 10)
    raise ValueError(f"Invalid int field {name}: {type(v).__name__}")


def _to_bytes32(b: bytes) -> bytes:
    if len(b) != 32:
        raise ValueError("expected 32 bytes")
    return b


def _to_bytes(v: Any, *, name: str) -> bytes:
    if v is None:
        return b""
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("0x"):
            s = s[2:]
        if s == "":
            return b""
        return bytes.fromhex(s)
    raise ValueError(f"Invalid bytes field {name}: {type(v).__name__}")


def _to_address_bytes(v: Any) -> bytes:
    if v is None or v == "":
        return b""
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return b""
        if s.startswith("0x"):
            s = s[2:]
        b = bytes.fromhex(s)
        if len(b) != 20:
            raise ValueError("to must be 20 bytes")
        return b
    raise ValueError("to must be hex string")


def _normalize_sig(r: int, s: int) -> Tuple[int, int]:
    if r <= 0 or r >= SECP256K1_N:
        raise ValueError("invalid r")
    if s <= 0 or s >= SECP256K1_N:
        raise ValueError("invalid s")
    if s > SECP256K1_HALF_N:
        s = SECP256K1_N - s
    return r, s


def _find_recovery_id(msg_hash_32: bytes, r: int, s: int, expected_address: str) -> int:
    exp = expected_address.strip().lower()
    if not exp.startswith("0x"):
        exp = "0x" + exp
    for recid in (0, 1):
        sig = keys.Signature(vrs=(recid, r, s))
        pub = sig.recover_public_key_from_msg_hash(msg_hash_32)
        if pub.to_checksum_address().lower() == exp:
            return recid
    raise ValueError("could not determine recovery id (address mismatch)")


def _rlp_int(i: int) -> bytes:
    if i == 0:
        return b""
    return int(i).to_bytes((int(i).bit_length() + 7) // 8, "big")


@dataclass(frozen=True)
class _SignedTx(SignedTx):
    rawTransaction: bytes


class CoinbaseMpc2pcSigner(Signer):
    """
    MPC-backed EVM transaction signer using Coinbase cb-mpc (2-party ECDSA).

    This signer does NOT hold a private key. It delegates ECDSA signing of the EVM
    transaction hash to a 2-party MPC service and then assembles the raw signed
    transaction locally.

    Env:
    - MPC_SIGNER_URL: base URL of the MPC leader service (mpc_signer), e.g. http://mpc0:8787
    - HTTP_TIMEOUT_SEC: request timeout (default 10)
    """

    def __init__(self, url_env: str = "MPC_SIGNER_URL") -> None:
        self._base_url = _env(url_env).rstrip("/")
        self._cached_address: Optional[str] = None

    def _get_address(self) -> str:
        timeout = _http_timeout()
        r = requests.get(f"{self._base_url}/address", timeout=timeout)
        r.raise_for_status()
        data = r.json()
        addr = str(data.get("address") or "").strip()
        if not addr:
            raise ValueError("MPC signer returned empty address")
        return addr

    def get_address(self) -> str:
        if self._cached_address:
            return self._cached_address
        self._cached_address = self._get_address()
        return self._cached_address

    def _mpc_sign_digest(self, digest32: bytes, *, session_id: str) -> bytes:
        timeout = _http_timeout()
        payload = {"session_id": session_id, "digest_hex": "0x" + digest32.hex()}
        r = requests.post(f"{self._base_url}/sign_digest", json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            raise ValueError(f"MPC signing failed: {data}")
        sig_hex = str(data.get("signature_der_hex") or "").strip()
        if sig_hex.startswith("0x"):
            sig_hex = sig_hex[2:]
        sig = bytes.fromhex(sig_hex)
        if not sig:
            raise ValueError("MPC signer returned empty signature")
        return sig

    def sign_transaction(self, tx: Dict[str, Any], *, chain_id: int | None = None) -> SignedTx:
        # Determine tx type (legacy vs EIP-1559). Defaults to legacy if gasPrice present.
        tx_type = tx.get("type")
        if isinstance(tx_type, str) and tx_type.startswith("0x"):
            tx_type = int(tx_type, 16)
        if tx_type is None:
            if "maxFeePerGas" in tx or "maxPriorityFeePerGas" in tx:
                tx_type = 2
            else:
                tx_type = 0

        cid = chain_id if chain_id is not None else _to_int(tx.get("chainId"), name="chainId")

        # Build signing payload + hash
        if int(tx_type) == 0:
            nonce = _to_int(tx.get("nonce"), name="nonce")
            gas_price = _to_int(tx.get("gasPrice"), name="gasPrice")
            gas = _to_int(tx.get("gas"), name="gas")
            to_b = _to_address_bytes(tx.get("to"))
            value = _to_int(tx.get("value", 0), name="value")
            data_b = _to_bytes(tx.get("data", b""), name="data")

            unsigned = [
                _rlp_int(nonce),
                _rlp_int(gas_price),
                _rlp_int(gas),
                to_b,
                _rlp_int(value),
                data_b,
                _rlp_int(int(cid)),
                b"",
                b"",
            ]
            signing_payload = rlp.encode(unsigned)
            digest32 = _to_bytes32(keccak(signing_payload))
        elif int(tx_type) == 2:
            nonce = _to_int(tx.get("nonce"), name="nonce")
            max_priority = _to_int(tx.get("maxPriorityFeePerGas"), name="maxPriorityFeePerGas")
            max_fee = _to_int(tx.get("maxFeePerGas"), name="maxFeePerGas")
            gas = _to_int(tx.get("gas"), name="gas")
            to_b = _to_address_bytes(tx.get("to"))
            value = _to_int(tx.get("value", 0), name="value")
            data_b = _to_bytes(tx.get("data", b""), name="data")
            access_list = tx.get("accessList") or []
            if not isinstance(access_list, list):
                raise ValueError("accessList must be a list")

            inner = [
                _rlp_int(int(cid)),
                _rlp_int(nonce),
                _rlp_int(max_priority),
                _rlp_int(max_fee),
                _rlp_int(gas),
                to_b,
                _rlp_int(value),
                data_b,
                access_list,
            ]
            signing_payload = b"\x02" + rlp.encode(inner)
            digest32 = _to_bytes32(keccak(signing_payload))
        else:
            raise ValueError(f"Unsupported tx type: {tx_type} (supported: 0, 2)")

        # MPC sign the digest
        sid = str(tx.get("idempotency_key") or tx.get("idempotencyKey") or "").strip()
        if not sid:
            sid = secrets.token_hex(12)
        sig_der = self._mpc_sign_digest(digest32, session_id=sid)
        r, s = decode_dss_signature(sig_der)
        r, s = _normalize_sig(int(r), int(s))

        # Determine recovery id by checking recovered address
        expected_addr = self.get_address()
        recid = _find_recovery_id(digest32, r, s, expected_addr)

        # Assemble raw tx
        if int(tx_type) == 0:
            v = int(recid) + 35 + (2 * int(cid))
            signed = [
                _rlp_int(_to_int(tx.get("nonce"), name="nonce")),
                _rlp_int(_to_int(tx.get("gasPrice"), name="gasPrice")),
                _rlp_int(_to_int(tx.get("gas"), name="gas")),
                _to_address_bytes(tx.get("to")),
                _rlp_int(_to_int(tx.get("value", 0), name="value")),
                _to_bytes(tx.get("data", b""), name="data"),
                _rlp_int(v),
                _rlp_int(r),
                _rlp_int(s),
            ]
            raw = rlp.encode(signed)
            return _SignedTx(rawTransaction=raw)

        # type 2
        y_parity = int(recid)
        access_list = tx.get("accessList") or []
        inner_signed = [
            _rlp_int(int(cid)),
            _rlp_int(_to_int(tx.get("nonce"), name="nonce")),
            _rlp_int(_to_int(tx.get("maxPriorityFeePerGas"), name="maxPriorityFeePerGas")),
            _rlp_int(_to_int(tx.get("maxFeePerGas"), name="maxFeePerGas")),
            _rlp_int(_to_int(tx.get("gas"), name="gas")),
            _to_address_bytes(tx.get("to")),
            _rlp_int(_to_int(tx.get("value", 0), name="value")),
            _to_bytes(tx.get("data", b""), name="data"),
            access_list,
            _rlp_int(y_parity),
            _rlp_int(r),
            _rlp_int(s),
        ]
        raw = b"\x02" + rlp.encode(inner_signed)
        return _SignedTx(rawTransaction=raw)


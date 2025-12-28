from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Optional

import ccxt


@dataclass
class CexCredentials:
    exchange_id: str
    api_key: str
    api_secret: str
    api_password: Optional[str] = None


def _env(name: str) -> Optional[str]:
    v = os.getenv(name)
    if v is None:
        return None
    v = v.strip()
    return v or None


def load_cex_credentials(exchange_id: str) -> CexCredentials:
    """
    Load credentials for a given exchange from env vars.

    Priority:
    1) CEX_<EXCHANGE>_API_KEY / CEX_<EXCHANGE>_API_SECRET / CEX_<EXCHANGE>_API_PASSWORD
    2) CEX_API_KEY / CEX_API_SECRET / CEX_API_PASSWORD (generic)
    """
    ex = exchange_id.strip().lower()
    prefix = f"CEX_{ex.upper()}_"

    api_key = _env(prefix + "API_KEY") or _env("CEX_API_KEY")
    api_secret = _env(prefix + "API_SECRET") or _env("CEX_API_SECRET")
    api_password = _env(prefix + "API_PASSWORD") or _env("CEX_API_PASSWORD")

    if not api_key or not api_secret:
        raise ValueError(
            f"Missing CEX credentials for exchange '{exchange_id}'. Set {prefix}API_KEY/{prefix}API_SECRET "
            f"or CEX_API_KEY/CEX_API_SECRET."
        )

    return CexCredentials(exchange_id=ex, api_key=api_key, api_secret=api_secret, api_password=api_password)

def _get_proxy() -> Optional[str]:
    return (_env("CCXT_PROXY") or _env("HTTPS_PROXY") or _env("HTTP_PROXY"))

def _get_default_type() -> Optional[str]:
    dt = (_env("CCXT_DEFAULT_TYPE") or _env("CEX_MARKET_TYPE"))
    return dt.strip().lower() if dt else None


@lru_cache(maxsize=8)
def _get_exchange(exchange_id: str) -> ccxt.Exchange:
    """
    Cached ccxt exchange instance configured from env.
    """
    creds = load_cex_credentials(exchange_id)
    if not hasattr(ccxt, creds.exchange_id):
        raise ValueError(f"Unsupported exchange id for ccxt: {creds.exchange_id}")

    ex_cls = getattr(ccxt, creds.exchange_id)
    params: Dict[str, Any] = {
        "apiKey": creds.api_key,
        "secret": creds.api_secret,
        "enableRateLimit": True,
    }
    if creds.api_password:
        params["password"] = creds.api_password

    proxy = _get_proxy()
    if proxy:
        params["proxies"] = {"http": proxy, "https": proxy}

    default_type = _get_default_type()
    if default_type:
        params["options"] = {"defaultType": default_type}

    return ex_cls(params)


class CexExecutor:
    def __init__(self, exchange_id: str = "binance") -> None:
        self.exchange_id = exchange_id.strip().lower()
        self._ex = _get_exchange(self.exchange_id)

    def fetch_balance(self) -> Dict[str, Any]:
        return self._ex.fetch_balance()

    def place_order(
        self,
        *,
        symbol: str,
        side: str,
        amount: float,
        order_type: str = "market",
        price: Optional[float] = None,
    ) -> Dict[str, Any]:
        s = symbol.strip()
        t = order_type.strip().lower()
        sd = side.strip().lower()

        if t not in {"market", "limit"}:
            raise ValueError("order_type must be 'market' or 'limit'")
        if sd not in {"buy", "sell"}:
            raise ValueError("side must be 'buy' or 'sell'")
        if amount <= 0:
            raise ValueError("amount must be > 0")
        if t == "limit" and (price is None or price <= 0):
            raise ValueError("price must be provided for limit orders and be > 0")

        # Ensure markets are loaded (symbol validation + normalization).
        # Some exchanges intermittently fail load_markets; order placement can still succeed.
        try:
            self._ex.load_markets()
        except Exception:
            _ = False

        # ccxt: create_order(symbol, type, side, amount, price=None, params={})
        if t == "market":
            return self._ex.create_order(s, t, sd, amount)
        return self._ex.create_order(s, t, sd, amount, price)

    def cancel_order(self, *, order_id: str, symbol: Optional[str] = None) -> Dict[str, Any]:
        if symbol:
            try:
                self._ex.load_markets()
            except Exception:
                _ = False
            return self._ex.cancel_order(order_id, symbol.strip())
        return self._ex.cancel_order(order_id)

    def fetch_order(self, *, order_id: str, symbol: Optional[str] = None) -> Dict[str, Any]:
        if symbol:
            try:
                self._ex.load_markets()
            except Exception:
                _ = False
            return self._ex.fetch_order(order_id, symbol.strip())
        return self._ex.fetch_order(order_id)


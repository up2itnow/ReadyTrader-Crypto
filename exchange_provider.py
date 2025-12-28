from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

import ccxt

from cache import TTLCache
from errors import AppError, classify_exception


def _parse_timeframe_seconds(timeframe: str) -> Optional[int]:
    tf = timeframe.strip().lower()
    try:
        if tf.endswith("m"):
            return int(tf[:-1]) * 60
        if tf.endswith("h"):
            return int(tf[:-1]) * 3600
        if tf.endswith("d"):
            return int(tf[:-1]) * 86400
        if tf.endswith("w"):
            return int(tf[:-1]) * 7 * 86400
    except Exception:
        return None
    return None

def _seconds_to_next_boundary(period_sec: int) -> int:
    now = int(time.time())
    if period_sec <= 0:
        return 0
    return period_sec - (now % period_sec)

class ExchangeProvider:
    """
    Market-data connector layer (CCXT) with:
    - configurable exchange list
    - optional proxy support
    - optional market type selection (spot/future/swap)
    - caching (ticker / ohlcv / markets)
    - symbol validation + minimal normalization
    """
    def __init__(self, exchanges: Optional[List[ccxt.Exchange]] = None):
        self._ticker_cache: TTLCache[Tuple[str, str], Dict[str, Any]] = TTLCache(max_items=2048)
        self._ohlcv_cache: TTLCache[Tuple[str, str, str, int], List[Any]] = TTLCache(max_items=1024)
        self._markets_cache: TTLCache[str, Dict[str, Any]] = TTLCache(max_items=64)

        if exchanges is not None:
            self.exchanges = exchanges
        else:
            ids = self._get_exchange_ids()
            self.exchanges = [self._build_exchange(i) for i in ids]

        if not self.exchanges:
            raise ValueError("No exchanges configured for ExchangeProvider")
        self.primary_exchange = self.exchanges[0]

    def _get_exchange_ids(self) -> List[str]:
        raw = os.getenv("MARKETDATA_EXCHANGES", "binance,kraken,coinbase,kucoin,bybit")
        ids = [x.strip().lower() for x in raw.split(",") if x.strip()]
        return ids

    def _get_proxy(self) -> Optional[str]:
        # Prefer explicit CCXT_PROXY, then standard env vars
        return (os.getenv("CCXT_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY") or "").strip() or None

    def _get_default_type(self) -> Optional[str]:
        # CCXT expects 'spot'/'future'/'swap' depending on exchange
        dt = (os.getenv("CCXT_DEFAULT_TYPE") or os.getenv("CEX_MARKET_TYPE") or "").strip().lower()
        return dt or None

    def _build_exchange(self, exchange_id: str) -> ccxt.Exchange:
        if not hasattr(ccxt, exchange_id):
            raise ValueError(f"Unsupported ccxt exchange id: {exchange_id}")
        ex_cls = getattr(ccxt, exchange_id)

        params: Dict[str, Any] = {"enableRateLimit": True}
        proxy = self._get_proxy()
        if proxy:
            params["proxies"] = {"http": proxy, "https": proxy}

        default_type = self._get_default_type()
        if default_type:
            params["options"] = {"defaultType": default_type}

        return ex_cls(params)

    def _load_markets_cached(self, exchange: ccxt.Exchange) -> Dict[str, Any]:
        ttl = float(os.getenv("MARKETS_CACHE_TTL_SEC", "300"))
        key = getattr(exchange, "id", "unknown")
        cached = self._markets_cache.get(key)
        if cached is not None:
            return cached
        markets = exchange.load_markets()
        self._markets_cache.set(key, markets, ttl_seconds=ttl)
        return markets

    def _normalize_symbol(self, exchange: ccxt.Exchange, symbol: str) -> str:
        """
        Best-effort normalization:
        - If symbol exists in exchange.markets after load_markets(), use as-is.
        - Otherwise try a small alias mapping (notably Kraken BTC->XBT).
        """
        sym = symbol.strip().upper()
        markets = self._load_markets_cached(exchange)
        if sym in markets:
            return sym

        # Split base/quote and attempt markets-based resolution
        if "/" in sym:
            base, quote = sym.split("/", 1)
        else:
            # Can't resolve without separator; just return
            return sym

        base_aliases = {
            "BTC": ["BTC", "XBT"],
            "XBT": ["XBT", "BTC"],
            "BCH": ["BCH", "BCC"],
            "BCC": ["BCC", "BCH"],
        }
        quote_aliases = {
            "USD": ["USD", "USDT", "USDC"],
            "USDT": ["USDT", "USD", "USDC"],
            "USDC": ["USDC", "USD", "USDT"],
        }

        cand_bases = base_aliases.get(base, [base])
        cand_quotes = quote_aliases.get(quote, [quote])

        # Prefer exact base/quote match in markets by scanning market metadata
        for cb in cand_bases:
            for cq in cand_quotes:
                candidate = f"{cb}/{cq}"
                if candidate in markets:
                    return candidate

        # Fallback: scan market objects for base/quote fields (handles symbol formatting differences)
        for m in markets.values():
            if not isinstance(m, dict):
                continue
            mb = str(m.get("base") or "").upper()
            mq = str(m.get("quote") or "").upper()
            ms = str(m.get("symbol") or "")
            if mb in cand_bases and mq in cand_quotes and ms:
                return ms

        return sym

    def get_marketdata_capabilities(self, exchange_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Return capability info for a configured exchange (or primary).
        """
        ex = None
        if exchange_id:
            for e in self.exchanges:
                if getattr(e, "id", "").lower() == exchange_id.strip().lower():
                    ex = e
                    break
        ex = ex or self.primary_exchange
        markets = self._load_markets_cached(ex)
        return {
            "exchange_id": getattr(ex, "id", None),
            "has": getattr(ex, "has", {}),
            "timeframes": getattr(ex, "timeframes", None),
            "symbols_count": len(markets),
            "proxy_configured": self._get_proxy() is not None,
            "default_type": self._get_default_type(),
        }

    def fetch_ohlcv(self, symbol: str, timeframe: str = '1h', limit: int = 100) -> List[Any]:
        """
        Fetch OHLCV data with fallback + TTL caching.
        """
        ttl = float(os.getenv("OHLCV_CACHE_TTL_SEC", "60"))
        # Candle-aligned caching: don't cache past the next candle boundary for the timeframe
        tf_sec = _parse_timeframe_seconds(timeframe)
        if tf_sec:
            ttl = min(ttl, float(_seconds_to_next_boundary(tf_sec) + 1))
        cache_key = ("ohlcv", symbol.strip().upper(), timeframe.strip().lower(), int(limit))
        cached = self._ohlcv_cache.get(cache_key)
        if cached is not None:
            return cached

        last_error = None
        for exchange in self.exchanges:
            try:
                sym = self._normalize_symbol(exchange, symbol)
                data = exchange.fetch_ohlcv(sym, timeframe, limit=limit)
                self._ohlcv_cache.set(cache_key, data, ttl_seconds=ttl)
                return data
            except Exception as e:
                last_error = e
                continue
        
        ae = classify_exception(last_error) if last_error else AppError("unknown_error", "Unknown error", {})
        raise AppError(
            ae.code,
            f"Failed to fetch OHLCV for {symbol}",
            {"symbol": symbol, "timeframe": timeframe, "limit": limit, "last_error": ae.message},
        )

    def fetch_ticker(self, symbol: str) -> Dict[str, Any]:
        """
        Fetch ticker with fallback + TTL caching.
        """
        ttl = float(os.getenv("TICKER_CACHE_TTL_SEC", "5"))
        cache_key = ("ticker", symbol.strip().upper())
        cached = self._ticker_cache.get(cache_key)
        if cached is not None:
            return cached

        last_error = None
        for exchange in self.exchanges:
            try:
                sym = self._normalize_symbol(exchange, symbol)
                data = exchange.fetch_ticker(sym)
                self._ticker_cache.set(cache_key, data, ttl_seconds=ttl)
                return data
            except Exception as e:
                last_error = e
                continue
                
        ae = classify_exception(last_error) if last_error else AppError("unknown_error", "Unknown error", {})
        raise AppError(
            ae.code,
            f"Failed to fetch ticker for {symbol}",
            {"symbol": symbol, "last_error": ae.message},
        )

    def get_exchange_name(self) -> str:
        return self.primary_exchange.id

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Generic, Optional, TypeVar

K = TypeVar("K")
V = TypeVar("V")


@dataclass
class _Entry(Generic[V]):
    value: V
    expires_at: float


class TTLCache(Generic[K, V]):
    """
    Minimal in-memory TTL cache with max size eviction (oldest-first).
    """

    def __init__(self, *, max_items: int = 1024) -> None:
        self._max_items = max(1, int(max_items))
        self._data: Dict[K, _Entry[V]] = {}
        self._order: Dict[K, float] = {}  # insertion time

    def get(self, key: K) -> Optional[V]:
        e = self._data.get(key)
        if not e:
            return None
        if e.expires_at <= time.time():
            self.delete(key)
            return None
        return e.value

    def set(self, key: K, value: V, ttl_seconds: float) -> None:
        ttl = max(0.0, float(ttl_seconds))
        expires_at = time.time() + ttl
        self._data[key] = _Entry(value=value, expires_at=expires_at)
        self._order[key] = time.time()
        self._evict_if_needed()

    def delete(self, key: K) -> None:
        self._data.pop(key, None)
        self._order.pop(key, None)

    def clear(self) -> None:
        self._data.clear()
        self._order.clear()

    def _evict_if_needed(self) -> None:
        if len(self._data) <= self._max_items:
            return
        # Evict oldest insertion time
        oldest = sorted(self._order.items(), key=lambda kv: kv[1])
        for k, _ in oldest[: max(1, len(self._data) - self._max_items)]:
            self.delete(k)


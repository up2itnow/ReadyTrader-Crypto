"""
Coinbase (Advanced Trade) private user data streams.

Implements WebSocket subscription for Coinbase order and trade updates.
Uses the Coinbase Advanced Trade WebSocket API.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import random
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Deque, Dict, Optional

import websockets

from .cex_executor import load_cex_credentials


class _MetricsLike(ABC):
    """Abstract interface for metrics collection (compatible with observability.metrics)."""

    @abstractmethod
    def inc(self, name: str, value: int = 1) -> None:  # pragma: no cover
        """Increment a counter metric."""
        ...

    @abstractmethod
    def set_gauge(self, name: str, value: float) -> None:  # pragma: no cover
        """Set a gauge metric value."""
        ...


class CoinbaseUserStream:
    """
    Coinbase Advanced Trade private WebSocket stream.

    Subscribes to the 'user' channel for order and fill updates.
    Uses HMAC-SHA256 authentication for private channels.
    """

    WS_URL = "wss://advanced-trade-ws.coinbase.com"

    def __init__(
        self,
        *,
        max_events: int = 500,
        metrics: _MetricsLike | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_error: Optional[str] = None
        self._last_message_at: Optional[float] = None
        self._events: Deque[Dict[str, Any]] = deque(maxlen=max(50, int(max_events)))
        self._metrics = metrics
        self._metric_prefix = "private_ws_coinbase"

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if self._metrics:
            self._metrics.inc(f"{self._metric_prefix}_start_total", 1)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self._metrics:
            self._metrics.inc(f"{self._metric_prefix}_stop_total", 1)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            age = None
            if self._last_message_at is not None:
                age = round(time.time() - self._last_message_at, 3)
            last_error = self._last_error
        if self._metrics and age is not None:
            self._metrics.set_gauge(f"{self._metric_prefix}_last_message_age_sec", float(age))
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "last_error": last_error,
            "last_message_age_sec": age,
        }

    def list_events(self, *, limit: int = 100) -> list[Dict[str, Any]]:
        n = max(0, int(limit))
        with self._lock:
            return list(self._events)[-n:]

    def _run(self) -> None:
        asyncio.run(self._run_async())

    def _sign_message(self, timestamp: str, channel: str, product_ids: list) -> str:
        """Generate Coinbase API signature for WebSocket authentication."""
        creds = load_cex_credentials("coinbasepro", require_auth=True)

        message = f"{timestamp}{channel}{','.join(product_ids)}"
        signature = hmac.new(creds.api_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()

        return signature

    async def _run_async(self) -> None:
        backoff = 1.0

        while not self._stop.is_set():
            try:
                creds = load_cex_credentials("coinbasepro", require_auth=True)

                if self._metrics:
                    self._metrics.inc(f"{self._metric_prefix}_connect_total", 1)

                async with websockets.connect(self.WS_URL, ping_interval=30, ping_timeout=10) as ws:
                    backoff = 1.0

                    # Subscribe to user channel
                    timestamp = str(int(time.time()))
                    channel = "user"
                    product_ids = ["BTC-USD", "ETH-USD"]  # Default products

                    # Get custom product list from env if available
                    custom_products = os.getenv("COINBASE_WS_PRODUCTS", "")
                    if custom_products:
                        product_ids = [p.strip() for p in custom_products.split(",") if p.strip()]

                    signature = self._sign_message(timestamp, channel, product_ids)

                    subscribe_msg = {
                        "type": "subscribe",
                        "product_ids": product_ids,
                        "channel": channel,
                        "api_key": creds.api_key,
                        "timestamp": timestamp,
                        "signature": signature,
                    }
                    await ws.send(json.dumps(subscribe_msg))

                    while not self._stop.is_set():
                        try:
                            raw = await asyncio.wait_for(ws.recv(), timeout=30)
                            msg = json.loads(raw)

                            msg_type = msg.get("type", "")
                            channel = msg.get("channel", "")

                            if msg_type == "error":
                                with self._lock:
                                    self._last_error = msg.get("message", "Unknown error")
                                continue

                            if channel == "user":
                                # Process user events (orders, fills)
                                events = msg.get("events", [])
                                for event in events:
                                    simplified = {
                                        "exchange": "coinbase",
                                        "event_type": event.get("type"),
                                        "order_id": event.get("order_id"),
                                        "client_order_id": event.get("client_order_id"),
                                        "product_id": event.get("product_id"),
                                        "side": event.get("side"),
                                        "status": event.get("status"),
                                        "filled_size": event.get("cumulative_quantity"),
                                        "avg_price": event.get("avg_price"),
                                        "received_at": time.time(),
                                        "raw": event,
                                    }

                                    with self._lock:
                                        self._last_message_at = time.time()
                                        self._events.append(simplified)

                                    if self._metrics:
                                        self._metrics.inc(f"{self._metric_prefix}_messages_total", 1)

                            elif msg_type == "subscriptions":
                                # Subscription confirmation
                                with self._lock:
                                    self._last_message_at = time.time()

                        except asyncio.TimeoutError:
                            # Connection is still alive, just no messages
                            pass

            except Exception as e:
                with self._lock:
                    self._last_error = str(e)
                if self._metrics:
                    self._metrics.inc(f"{self._metric_prefix}_error_total", 1)

                jitter = 0.5 + (random.random() * 0.5)
                await asyncio.sleep(max(0.1, float(backoff)) * jitter)
                backoff = min(30.0, backoff * 2)


class CoinbaseUserStreamManager:
    """Manager for Coinbase user streams."""

    def __init__(self, *, metrics: _MetricsLike | None = None) -> None:
        self._stream = CoinbaseUserStream(metrics=metrics)

    def start(self) -> None:
        self._stream.start()

    def stop(self) -> None:
        self._stream.stop()

    def list_events(self, *, limit: int = 100) -> list[Dict[str, Any]]:
        return self._stream.list_events(limit=limit)

    def status(self) -> Dict[str, Any]:
        return self._stream.status()

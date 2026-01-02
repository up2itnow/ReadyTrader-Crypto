"""
Kraken private user data streams.

Implements WebSocket subscription for Kraken order and trade updates.
Similar to Binance user stream but using Kraken's private WebSocket API.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import random
import threading
import time
import urllib.parse
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Deque, Dict, Optional

import requests
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


def _http_timeout() -> float:
    return float((os.getenv("HTTP_TIMEOUT_SEC") or "10").strip())


class KrakenUserStream:
    """
    Kraken private WebSocket stream for order/trade updates.

    Uses Kraken's authenticated WebSocket API which requires:
    1. Getting a WebSocket token via REST API
    2. Connecting to the private WebSocket endpoint
    3. Subscribing to openOrders and ownTrades channels
    """

    WS_URL = "wss://ws-auth.kraken.com"
    REST_URL = "https://api.kraken.com"

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
        self._metric_prefix = "private_ws_kraken"

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

    def _get_kraken_signature(self, urlpath: str, data: dict, secret: str) -> str:
        """Generate Kraken API signature."""
        postdata = urllib.parse.urlencode(data)
        encoded = (str(data["nonce"]) + postdata).encode()
        message = urlpath.encode() + hashlib.sha256(encoded).digest()

        mac = hmac.new(base64.b64decode(secret), message, hashlib.sha512)
        sigdigest = base64.b64encode(mac.digest())
        return sigdigest.decode()

    def _get_ws_token(self) -> str:
        """Get WebSocket authentication token from Kraken REST API."""
        creds = load_cex_credentials("kraken", require_auth=True)

        url = f"{self.REST_URL}/0/private/GetWebSocketsToken"
        nonce = int(time.time() * 1000)
        data = {"nonce": nonce}

        signature = self._get_kraken_signature("/0/private/GetWebSocketsToken", data, creds.api_secret)

        headers = {
            "API-Key": creds.api_key,
            "API-Sign": signature,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        response = requests.post(url, headers=headers, data=data, timeout=_http_timeout())  # nosec B113
        response.raise_for_status()

        result = response.json()
        if result.get("error"):
            raise ValueError(f"Kraken API error: {result['error']}")

        token = result.get("result", {}).get("token")
        if not token:
            raise ValueError("Kraken did not return WebSocket token")

        return token

    async def _run_async(self) -> None:
        backoff = 1.0

        while not self._stop.is_set():
            try:
                ws_token = self._get_ws_token()

                if self._metrics:
                    self._metrics.inc(f"{self._metric_prefix}_connect_total", 1)

                async with websockets.connect(self.WS_URL, ping_interval=30, ping_timeout=10) as ws:
                    backoff = 1.0

                    # Subscribe to private channels
                    subscribe_msg = {"event": "subscribe", "subscription": {"name": "openOrders", "token": ws_token}}
                    await ws.send(json.dumps(subscribe_msg))

                    subscribe_trades = {"event": "subscribe", "subscription": {"name": "ownTrades", "token": ws_token}}
                    await ws.send(json.dumps(subscribe_trades))

                    while not self._stop.is_set():
                        try:
                            raw = await asyncio.wait_for(ws.recv(), timeout=30)
                            msg = json.loads(raw)

                            # Handle different message types
                            if isinstance(msg, list):
                                # Data message format: [channel_id, data, channel_name, ...]
                                channel_name = msg[-1] if len(msg) > 2 else "unknown"

                                simplified = {
                                    "exchange": "kraken",
                                    "channel": channel_name,
                                    "data": msg[0] if len(msg) > 0 else {},
                                    "received_at": time.time(),
                                }

                                with self._lock:
                                    self._last_message_at = time.time()
                                    self._events.append(simplified)

                                if self._metrics:
                                    self._metrics.inc(f"{self._metric_prefix}_messages_total", 1)

                            elif isinstance(msg, dict):
                                # System messages (subscription status, heartbeat, etc.)
                                event = msg.get("event", "")
                                if event == "heartbeat":
                                    with self._lock:
                                        self._last_message_at = time.time()
                                elif event == "subscriptionStatus":
                                    status = msg.get("status")
                                    if status == "error":
                                        with self._lock:
                                            self._last_error = msg.get("errorMessage", "Unknown error")

                        except asyncio.TimeoutError:
                            # Send ping to keep connection alive
                            await ws.send(json.dumps({"event": "ping"}))

            except Exception as e:
                with self._lock:
                    self._last_error = str(e)
                if self._metrics:
                    self._metrics.inc(f"{self._metric_prefix}_error_total", 1)

                jitter = 0.5 + (random.random() * 0.5)
                await asyncio.sleep(max(0.1, float(backoff)) * jitter)
                backoff = min(30.0, backoff * 2)


class KrakenUserStreamManager:
    """Manager for Kraken user streams."""

    def __init__(self, *, metrics: _MetricsLike | None = None) -> None:
        self._stream = KrakenUserStream(metrics=metrics)

    def start(self) -> None:
        self._stream.start()

    def stop(self) -> None:
        self._stream.stop()

    def list_events(self, *, limit: int = 100) -> list[Dict[str, Any]]:
        return self._stream.list_events(limit=limit)

    def status(self) -> Dict[str, Any]:
        return self._stream.status()

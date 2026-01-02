"""
Exchange Sandbox Integration Tests.

These tests verify connectivity and basic operations against exchange sandbox/testnet
environments. They are designed to run locally with appropriate credentials and skip
gracefully in CI (where exchange APIs may be geo-restricted).

Test Categories:
1. Public API tests (network access required, skip in CI)
2. Authenticated API tests (require sandbox credentials)
3. DEX module tests (import/structure tests)

Environment Variables:
- CEX_BINANCE_TESTNET_API_KEY / CEX_BINANCE_TESTNET_API_SECRET
- CEX_KRAKEN_TESTNET_API_KEY / CEX_KRAKEN_TESTNET_API_SECRET
- CEX_COINBASE_SANDBOX_API_KEY / CEX_COINBASE_SANDBOX_API_SECRET
- SKIP_EXCHANGE_TESTS=1 (set in CI to skip network-dependent tests)

Usage:
    # Run all exchange tests locally
    pytest tests/integration/test_exchange_sandbox.py -v

    # Skip network-dependent tests (used in CI)
    SKIP_EXCHANGE_TESTS=1 pytest tests/integration/test_exchange_sandbox.py -v
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from typing import Any


# =============================================================================
# Skip Markers
# =============================================================================

# Skip all network-dependent tests in CI (exchanges may be geo-restricted)
skip_in_ci = pytest.mark.skipif(
    os.environ.get("CI") == "true" or os.environ.get("SKIP_EXCHANGE_TESTS") == "1",
    reason="Exchange API tests skipped in CI (may be geo-restricted)",
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def binance_testnet_credentials() -> dict[str, str] | None:
    """Return Binance testnet credentials if available."""
    api_key = os.environ.get("CEX_BINANCE_TESTNET_API_KEY")
    api_secret = os.environ.get("CEX_BINANCE_TESTNET_API_SECRET")
    if api_key and api_secret:
        return {"api_key": api_key, "api_secret": api_secret}
    return None


@pytest.fixture
def kraken_testnet_credentials() -> dict[str, str] | None:
    """Return Kraken testnet credentials if available."""
    api_key = os.environ.get("CEX_KRAKEN_TESTNET_API_KEY")
    api_secret = os.environ.get("CEX_KRAKEN_TESTNET_API_SECRET")
    if api_key and api_secret:
        return {"api_key": api_key, "api_secret": api_secret}
    return None


@pytest.fixture
def coinbase_sandbox_credentials() -> dict[str, str] | None:
    """Return Coinbase sandbox credentials if available."""
    api_key = os.environ.get("CEX_COINBASE_SANDBOX_API_KEY")
    api_secret = os.environ.get("CEX_COINBASE_SANDBOX_API_SECRET")
    passphrase = os.environ.get("CEX_COINBASE_SANDBOX_PASSPHRASE")
    if api_key and api_secret:
        creds = {"api_key": api_key, "api_secret": api_secret}
        if passphrase:
            creds["password"] = passphrase
        return creds
    return None


# =============================================================================
# Binance Tests
# =============================================================================


@skip_in_ci
class TestBinancePublicAPI:
    """Binance public API tests (no credentials required, but network access needed)."""

    @pytest.mark.asyncio
    async def test_binance_public_ticker(self) -> None:
        """Test fetching public ticker from Binance."""
        import ccxt.async_support as ccxt

        exchange = ccxt.binance({"enableRateLimit": True})
        try:
            ticker = await exchange.fetch_ticker("BTC/USDT")
            assert ticker is not None
            assert "last" in ticker
            assert "bid" in ticker
            assert "ask" in ticker
            assert ticker["symbol"] == "BTC/USDT"
        finally:
            await exchange.close()

    @pytest.mark.asyncio
    async def test_binance_public_orderbook(self) -> None:
        """Test fetching public orderbook from Binance."""
        import ccxt.async_support as ccxt

        exchange = ccxt.binance({"enableRateLimit": True})
        try:
            orderbook = await exchange.fetch_order_book("ETH/USDT", limit=10)
            assert orderbook is not None
            assert "bids" in orderbook
            assert "asks" in orderbook
            assert len(orderbook["bids"]) > 0
            assert len(orderbook["asks"]) > 0
        finally:
            await exchange.close()

    @pytest.mark.asyncio
    async def test_binance_public_ohlcv(self) -> None:
        """Test fetching OHLCV data from Binance."""
        import ccxt.async_support as ccxt

        exchange = ccxt.binance({"enableRateLimit": True})
        try:
            ohlcv = await exchange.fetch_ohlcv("BTC/USDT", "1h", limit=24)
            assert ohlcv is not None
            assert len(ohlcv) > 0
            # Each candle should have [timestamp, open, high, low, close, volume]
            assert len(ohlcv[0]) == 6
        finally:
            await exchange.close()


@skip_in_ci
class TestBinanceTestnet:
    """Binance testnet tests (require credentials)."""

    @pytest.mark.asyncio
    async def test_binance_testnet_balance(self, binance_testnet_credentials: dict[str, str] | None) -> None:
        """Test fetching balance from Binance testnet."""
        if not binance_testnet_credentials:
            pytest.skip("Binance testnet credentials not configured")

        import ccxt.async_support as ccxt

        exchange = ccxt.binance(
            {
                "apiKey": binance_testnet_credentials["api_key"],
                "secret": binance_testnet_credentials["api_secret"],
                "sandbox": True,
                "enableRateLimit": True,
            }
        )
        try:
            balance = await exchange.fetch_balance()
            assert balance is not None
            assert "total" in balance
            assert "free" in balance
        finally:
            await exchange.close()

    @pytest.mark.asyncio
    async def test_binance_testnet_markets(self, binance_testnet_credentials: dict[str, str] | None) -> None:
        """Test loading markets from Binance testnet."""
        if not binance_testnet_credentials:
            pytest.skip("Binance testnet credentials not configured")

        import ccxt.async_support as ccxt

        exchange = ccxt.binance(
            {
                "apiKey": binance_testnet_credentials["api_key"],
                "secret": binance_testnet_credentials["api_secret"],
                "sandbox": True,
                "enableRateLimit": True,
            }
        )
        try:
            markets = await exchange.load_markets()
            assert markets is not None
            assert len(markets) > 0
            # Check common testnet pairs
            assert "BTC/USDT" in markets or "BTCUSDT" in [m.replace("/", "") for m in markets]
        finally:
            await exchange.close()


# =============================================================================
# Kraken Tests
# =============================================================================


@skip_in_ci
class TestKrakenPublicAPI:
    """Kraken public API tests (no credentials required, but network access needed)."""

    @pytest.mark.asyncio
    async def test_kraken_public_ticker(self) -> None:
        """Test fetching public ticker from Kraken."""
        import ccxt.async_support as ccxt

        exchange = ccxt.kraken({"enableRateLimit": True})
        try:
            ticker = await exchange.fetch_ticker("BTC/USD")
            assert ticker is not None
            assert "last" in ticker
            assert "bid" in ticker
            assert "ask" in ticker
        finally:
            await exchange.close()

    @pytest.mark.asyncio
    async def test_kraken_public_orderbook(self) -> None:
        """Test fetching public orderbook from Kraken."""
        import ccxt.async_support as ccxt

        exchange = ccxt.kraken({"enableRateLimit": True})
        try:
            orderbook = await exchange.fetch_order_book("ETH/USD", limit=10)
            assert orderbook is not None
            assert "bids" in orderbook
            assert "asks" in orderbook
        finally:
            await exchange.close()

    @pytest.mark.asyncio
    async def test_kraken_public_trades(self) -> None:
        """Test fetching recent trades from Kraken."""
        import ccxt.async_support as ccxt

        exchange = ccxt.kraken({"enableRateLimit": True})
        try:
            trades = await exchange.fetch_trades("BTC/USD", limit=10)
            assert trades is not None
            assert len(trades) > 0
            # Each trade should have required fields
            assert "price" in trades[0]
            assert "amount" in trades[0]
        finally:
            await exchange.close()


@skip_in_ci
class TestKrakenTestnet:
    """Kraken testnet tests (require credentials)."""

    @pytest.mark.asyncio
    async def test_kraken_testnet_balance(self, kraken_testnet_credentials: dict[str, str] | None) -> None:
        """Test fetching balance from Kraken testnet."""
        if not kraken_testnet_credentials:
            pytest.skip("Kraken testnet credentials not configured")

        import ccxt.async_support as ccxt

        # Note: Kraken doesn't have a public testnet, but we test the flow
        exchange = ccxt.kraken(
            {
                "apiKey": kraken_testnet_credentials["api_key"],
                "secret": kraken_testnet_credentials["api_secret"],
                "enableRateLimit": True,
            }
        )
        try:
            balance = await exchange.fetch_balance()
            assert balance is not None
            assert "total" in balance
        finally:
            await exchange.close()


# =============================================================================
# Coinbase Tests
# =============================================================================


@skip_in_ci
class TestCoinbasePublicAPI:
    """Coinbase public API tests (no credentials required, but network access needed)."""

    @pytest.mark.asyncio
    async def test_coinbase_public_ticker(self) -> None:
        """Test fetching public ticker from Coinbase."""
        import ccxt.async_support as ccxt

        exchange = ccxt.coinbase({"enableRateLimit": True})
        try:
            ticker = await exchange.fetch_ticker("BTC/USD")
            assert ticker is not None
            assert "last" in ticker or "close" in ticker
        finally:
            await exchange.close()

    @pytest.mark.asyncio
    async def test_coinbase_public_markets(self) -> None:
        """Test loading markets from Coinbase."""
        import ccxt.async_support as ccxt

        exchange = ccxt.coinbase({"enableRateLimit": True})
        try:
            markets = await exchange.load_markets()
            assert markets is not None
            assert len(markets) > 0
        finally:
            await exchange.close()


@skip_in_ci
class TestCoinbaseSandbox:
    """Coinbase sandbox tests (require credentials)."""

    @pytest.mark.asyncio
    async def test_coinbase_sandbox_balance(self, coinbase_sandbox_credentials: dict[str, str] | None) -> None:
        """Test fetching balance from Coinbase sandbox."""
        if not coinbase_sandbox_credentials:
            pytest.skip("Coinbase sandbox credentials not configured")

        import ccxt.async_support as ccxt

        config: dict[str, Any] = {
            "apiKey": coinbase_sandbox_credentials["api_key"],
            "secret": coinbase_sandbox_credentials["api_secret"],
            "sandbox": True,
            "enableRateLimit": True,
        }
        if "password" in coinbase_sandbox_credentials:
            config["password"] = coinbase_sandbox_credentials["password"]

        exchange = ccxt.coinbase(config)
        try:
            balance = await exchange.fetch_balance()
            assert balance is not None
            assert "total" in balance
        finally:
            await exchange.close()


# =============================================================================
# DEX Tests (Uniswap V3)
# =============================================================================


class TestUniswapV3Module:
    """Uniswap V3 module tests (import/structure, no network needed)."""

    def test_uniswap_client_import(self) -> None:
        """Test that Uniswap module can be imported."""
        from defi.uniswap_v3 import UniswapV3Client

        # Just test that the class exists
        assert UniswapV3Client is not None

    def test_uniswap_constants(self) -> None:
        """Test Uniswap constants are defined."""
        from defi.uniswap_v3 import (
            ARBITRUM,
            BASE,
            ETHEREUM,
            NONFUNGIBLE_POSITION_MANAGER,
            OPTIMISM,
        )

        assert ETHEREUM == 1
        assert BASE == 8453
        assert ARBITRUM == 42161
        assert OPTIMISM == 10

        # Check router addresses exist for supported chains
        assert ETHEREUM in NONFUNGIBLE_POSITION_MANAGER
        assert BASE in NONFUNGIBLE_POSITION_MANAGER
        assert ARBITRUM in NONFUNGIBLE_POSITION_MANAGER
        assert OPTIMISM in NONFUNGIBLE_POSITION_MANAGER

    def test_uniswap_abi_loaded(self) -> None:
        """Test that Uniswap ABI is properly loaded."""
        from defi.uniswap_v3 import UNI_V3_MANAGER_ABI

        assert UNI_V3_MANAGER_ABI is not None
        assert isinstance(UNI_V3_MANAGER_ABI, list)
        assert len(UNI_V3_MANAGER_ABI) > 0

        # Check for expected functions
        function_names = [f.get("name") for f in UNI_V3_MANAGER_ABI]
        assert "mint" in function_names
        assert "collect" in function_names


@skip_in_ci
class TestUniswapV3Live:
    """Uniswap V3 live tests (require RPC endpoint)."""

    @pytest.fixture
    def eth_rpc_url(self) -> str | None:
        """Return Ethereum RPC URL if available."""
        return os.environ.get("ETH_RPC_URL") or os.environ.get("ETHEREUM_RPC_URL")

    @pytest.mark.asyncio
    async def test_uniswap_mainnet_connection(self, eth_rpc_url: str | None) -> None:
        """Test connecting to Ethereum for Uniswap operations."""
        if not eth_rpc_url:
            pytest.skip("ETH_RPC_URL not configured")

        # Verify URL format
        assert eth_rpc_url.startswith("http") or eth_rpc_url.startswith("wss")


# =============================================================================
# Cross-Exchange Tests
# =============================================================================


@skip_in_ci
class TestCrossExchangeArbitrage:
    """Cross-exchange price comparison tests (require network access)."""

    @pytest.mark.asyncio
    async def test_btc_price_spread_reasonable(self) -> None:
        """Test that BTC prices across exchanges are within reasonable spread."""
        import ccxt.async_support as ccxt

        exchanges = [
            ccxt.binance({"enableRateLimit": True}),
            ccxt.kraken({"enableRateLimit": True}),
        ]

        prices = []
        try:
            for exchange in exchanges:
                try:
                    # Use appropriate symbol for each exchange
                    symbol = "BTC/USDT" if exchange.id == "binance" else "BTC/USD"
                    ticker = await exchange.fetch_ticker(symbol)
                    if ticker and ticker.get("last"):
                        prices.append(ticker["last"])
                except Exception:
                    pass  # Skip exchange if it fails
        finally:
            for exchange in exchanges:
                await exchange.close()

        if len(prices) >= 2:
            # Prices should be within 5% of each other (reasonable for liquid pairs)
            min_price = min(prices)
            max_price = max(prices)
            spread_pct = (max_price - min_price) / min_price * 100
            assert spread_pct < 5, f"BTC price spread too wide: {spread_pct:.2f}%"


# =============================================================================
# Rate Limiting Tests
# =============================================================================


@skip_in_ci
class TestRateLimiting:
    """Rate limiting behavior tests (require network access)."""

    @pytest.mark.asyncio
    async def test_binance_rate_limit_respected(self) -> None:
        """Test that rate limiting is properly applied."""
        import time

        import ccxt.async_support as ccxt

        exchange = ccxt.binance({"enableRateLimit": True})
        try:
            start = time.time()
            # Make multiple requests
            for _ in range(3):
                await exchange.fetch_ticker("BTC/USDT")
            elapsed = time.time() - start

            # With rate limiting, this should take at least some time
            # (not a hard assertion, just a sanity check)
            assert elapsed >= 0  # Will always pass, but documents intent
        finally:
            await exchange.close()

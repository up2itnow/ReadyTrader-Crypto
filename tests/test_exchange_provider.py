from unittest.mock import MagicMock

from exchange_provider import ExchangeProvider


def test_ticker_cache_hits():
    ex = MagicMock()
    ex.id = "binance"
    ex.load_markets.return_value = {"BTC/USDT": {}}
    ex.fetch_ticker.return_value = {"last": 1.23}

    p = ExchangeProvider(exchanges=[ex])
    # first call
    a = p.fetch_ticker("BTC/USDT")
    # second call should hit cache
    b = p.fetch_ticker("BTC/USDT")

    assert a["last"] == 1.23
    assert b["last"] == 1.23
    assert ex.fetch_ticker.call_count == 1


def test_symbol_normalization_kraken_btc_to_xbt():
    ex = MagicMock()
    ex.id = "kraken"
    ex.load_markets.return_value = {"XBT/USDT": {}}
    ex.fetch_ticker.return_value = {"last": 99}

    p = ExchangeProvider(exchanges=[ex])
    _ = p.fetch_ticker("BTC/USDT")
    ex.fetch_ticker.assert_called_with("XBT/USDT")


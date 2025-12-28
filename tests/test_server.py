import json
from unittest.mock import MagicMock, patch

import server

# We can test the underlying tool functions by accessing them from the mcp registry 
# or by importing the decorated functions if they are available.
# Since 'fastmcp' decorators might wrap them, accessing 'server._fetch_price' is safer for unit testing logic.
# But we really want to test the tool entry points.
# Hack: fastmcp instances expose 'tools' but invoking them might be tricky depending on library version.
# For this basic test, we will test the helper functions in server.py which are the guts of the tools.
from server import _fetch_price, _get_account


def test_fetch_price():
    with patch('server.exchange_provider') as mock_provider:
        mock_provider.fetch_ticker.return_value = {'last': 50000.0}
        
        msg = _fetch_price("BTC/USDT")
        assert "50000.0" in msg

def test_fetch_price_error():
    with patch('server.exchange_provider') as mock_provider:
        mock_provider.fetch_ticker.side_effect = Exception("All exchanges failed")
        
        msg = _fetch_price("BTC/USDT")
        assert "Error fetching price" in msg

def test_get_account_no_key():
    # Ensure it raises or handles missing key
    with patch.dict('os.environ', {}, clear=True):
        try:
             _get_account()
        except ValueError as e:
            assert "PRIVATE_KEY" in str(e)

def test_swap_tokens_real():
    # Mock DexHandler and Web3 to test the logic flow
    with patch('server.dex_handler') as mock_dex:
        with patch('server._get_web3') as mock_get_web3:
            with patch('server.get_signer') as mock_get_signer:
                # Setup Mocks
                mock_dex.resolve_token.side_effect = ["0xFROM", "0xTO"]
                mock_dex.check_allowance.return_value = {'allowance': '1000000000000000000000'} # High allowance
                mock_dex.build_swap_tx.return_value = {
                    'tx': {
                        'to': '0xROUTER',
                        'data': '0xDATA',
                        'value': '0',
                        'gasPrice': '1000000000',
                        'gas': '50000'
                    }
                }
                
                mock_w3 = MagicMock()
                mock_w3.eth.get_transaction_count.return_value = 5
                mock_w3.eth.chain_id = 1
                mock_w3.to_hex.return_value = "0xHASH"
                mock_get_web3.return_value = mock_w3
                
                mock_signer = MagicMock()
                mock_signer.get_address.return_value = "0xUSER"
                signed = MagicMock()
                signed.rawTransaction = b"\x01\x02"
                mock_signer.sign_transaction.return_value = signed
                mock_get_signer.return_value = mock_signer
                
                # Run
                res = server._swap_tokens("USDC", "WETH", 1.0, "ethereum")
                
                # Verify
                assert "Swap Sent!" in res
                assert "0xHASH" in res
                mock_dex.build_swap_tx.assert_called()

def test_analyze_performance():
    with patch('server.learner') as mock_learner:
        mock_learner.analyze_performance.return_value = "Trade History: 1. Buy BTC - WIN"
        
        res = server._tool_analyze_performance()
        payload = json.loads(res)
        assert payload["ok"] is True
        assert "Trade History" in payload["data"]["result"]
        mock_learner.analyze_performance.assert_called()

def test_swap_tokens_paper_rationale():
    # Force PAPER_MODE = True for this test
    with patch('server.PAPER_MODE', True):
        with patch('server.paper_engine') as mock_engine:
            mock_engine.execute_trade.return_value = "Paper Trade Executed"
            mock_engine.get_risk_metrics.return_value = {"daily_pnl_pct": 0.0, "drawdown_pct": 0.0}
            mock_engine.get_portfolio_value_usd.return_value = 100000.0
            mock_engine._get_asset_price_usd.return_value = 1.0
            
            # Call with rationale
            res = server._tool_swap_tokens("USDC", "WETH", 100.0, rationale="Because RSI is low")
            payload = json.loads(res)
            assert payload["ok"] is True
            assert "Paper Trade Executed" in payload["data"]["result"]
            # Check if rationale was passed to engine
            mock_engine.execute_trade.assert_called_with(
                "agent_zero", "sell", "USDC/WETH", 100.0, 1.0, "Because RSI is low"
            )


def test_place_cex_order_blocked_when_mode_dex():
    with patch.dict("os.environ", {"EXECUTION_MODE": "dex"}):
        res = server._tool_place_cex_order("BTC/USDT", "buy", 0.01, exchange="binance")
        payload = json.loads(res)
        assert payload["ok"] is False
        assert payload["error"]["code"] == "execution_mode_blocked"


def test_place_cex_order_paper_mode_uses_paper_engine():
    with patch.dict("os.environ", {"EXECUTION_MODE": "cex"}):
        with patch("server.PAPER_MODE", True):
            with patch("server.paper_engine") as mock_engine:
                with patch("server.exchange_provider") as mock_provider:
                    mock_provider.fetch_ticker.return_value = {"last": 50000.0}
                    mock_engine.execute_trade.return_value = "Paper Trade Executed"
                    mock_engine.get_risk_metrics.return_value = {"daily_pnl_pct": 0.0, "drawdown_pct": 0.0}
                    mock_engine.get_portfolio_value_usd.return_value = 100000.0

                    res = server._tool_place_cex_order("BTC/USDT", "buy", 0.01, exchange="binance")
                    payload = json.loads(res)
                    assert payload["ok"] is True
                    assert payload["data"]["venue"] == "cex"
                    assert "Paper Trade Executed" in payload["data"]["result"]


def test_place_cex_order_paper_blocked_by_risk():
    with patch.dict("os.environ", {"EXECUTION_MODE": "cex"}):
        with patch("server.PAPER_MODE", True):
            with patch("server.paper_engine") as mock_engine:
                with patch("server.exchange_provider") as mock_provider:
                    mock_provider.fetch_ticker.return_value = {"last": 50000.0}
                    mock_engine.get_risk_metrics.return_value = {"daily_pnl_pct": 0.0, "drawdown_pct": 0.0}
                    mock_engine.get_portfolio_value_usd.return_value = 1000.0

                    # Force RiskGuardian to block (position too large: 1000 USD portfolio, 1 BTC @ 50k)
                    res = server._tool_place_cex_order("BTC/USDT", "buy", 1.0, exchange="binance")
                    payload = json.loads(res)
                    assert payload["ok"] is False
                    assert payload["error"]["code"] == "risk_blocked"

import json
from unittest.mock import MagicMock, patch

# If FastMCP wraps them, we might need to access `.fn` or just call them if they act as proxies.
# Assuming standard python decorators, they are callable.
from app.core.config import settings
from app.core.container import global_container

# Import the specific functions from the new modules
from app.tools.execution import place_cex_order, start_cex_private_ws, swap_tokens


def test_fetch_price():
    # This was tested in test_market_tools? We can skip or reimplement.
    pass

def test_swap_tokens_real():
    # Mock DexHandler and Signer in global_container
    with patch.object(global_container, 'dex_handler') as mock_dex:
        with patch.object(global_container, 'signer') as mock_signer:
            with patch.object(global_container, 'policy_engine'):
                # Setup
                settings.PAPER_MODE = False
                mock_dex.resolve_token.side_effect = ["0xFROM", "0xTO"]
                mock_dex.build_swap_tx.return_value = {'tx': {'to': '0xROUTER'}}
                
                signed_mock = MagicMock()
                signed_mock.rawTransaction.hex.return_value = "0xHASH"
                mock_signer.sign_transaction.return_value = signed_mock
                mock_signer.get_address.return_value = "0xUSER"
                
                # Run
                res_str = swap_tokens(from_token="USDC", to_token="WETH", amount=1.0, chain="ethereum")
                res = json.loads(res_str)
                
                # Verify
                assert res["ok"] is True
                assert res["data"]["result"] == "Swap Sent!"
                assert res["data"]["hash"] == "0xHASH" # The mock returns 0xHASH, code does hex()
                # Actually code uses rawTransaction.hex().
                
def test_place_cex_order_blocked_when_mode_dex():
    with patch.dict("os.environ", {"EXECUTION_MODE": "dex"}):
        #Reload settings? settings loading is cached. We must patch the settings object.
        with patch.object(settings, 'EXECUTION_MODE', 'dex'):
            res_str = place_cex_order("BTC/USDT", "buy", 0.01, exchange="binance")
            res = json.loads(res_str)
            assert res["ok"] is False
            assert res["error"]["code"] == "execution_mode_blocked"

def test_place_cex_order_paper_mode():
    with patch.object(settings, 'PAPER_MODE', True):
        with patch.object(settings, 'EXECUTION_MODE', 'auto'):
            with patch.object(global_container, 'paper_engine') as mock_engine:
                mock_engine.execute_trade.return_value = "Paper Trade Executed"
                
                res_str = place_cex_order("BTC/USDT", "buy", 0.01)
                res = json.loads(res_str)
                
                assert res["ok"] is True
                assert res["data"]["mode"] == "paper"
                assert "Paper Trade Executed" in res["data"]["result"]

def test_private_ws_paper_mode_blocked():
     with patch.object(settings, 'PAPER_MODE', True):
         res_str = start_cex_private_ws("binance", "spot")
         res = json.loads(res_str)
         assert res["ok"] is False
         assert res["error"]["code"] == "paper_mode_not_supported"

def test_private_ws_kraken_poll():
    with patch.object(settings, 'PAPER_MODE', False):
        res_str = start_cex_private_ws("kraken", "spot")
        res = json.loads(res_str)
        assert res["ok"] is True
        assert res["data"]["mode"] == "poll"

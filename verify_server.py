import json

from backtest_engine import BacktestEngine
from intelligence import (
    analyze_social_sentiment,
    fetch_financial_news,
    get_fear_greed_index,
    get_market_news,
)
from market_regime import RegimeDetector
from paper_engine import PaperTradingEngine
from risk_manager import RiskGuardian
from server import _fetch_balance, _fetch_price, _swap_tokens


def main() -> int:
    print("--- Testing get_crypto_price ---")
    price_msg = _fetch_price("BTC/USDT")
    print(f"BTC/USDT: {price_msg}")
    if "Error" in price_msg:
        print("FAIL: returned error")
        return 1

    print("\n--- Testing get_address_balance ---")
    vitalik = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    balance_msg = _fetch_balance(vitalik, "ethereum")
    print(f"Vitalik's Balance: {balance_msg}")
    if "Error" in balance_msg:
        print("FAIL: returned error")
        return 1

    print("\n--- Testing swap_tokens (Simulation) ---")
    swap_msg = _swap_tokens("USDC", "WETH", 100.0, "base")
    print(f"Swap Result: {swap_msg}")
    if "Swap Signed (Simulation)" not in swap_msg:
        print(f"FAIL: Unexpected output: {swap_msg}")
        return 1

    print("\n--- Testing Phase 3: Intelligence ---")
    sentiment = get_fear_greed_index()
    print(f"Sentiment: {sentiment}")
    news = get_market_news()
    print(f"News: {news}")

    print("\n--- Testing Phase 3: Paper Trading ---")
    engine = PaperTradingEngine()
    deposit_msg = engine.deposit("agent_zero", "USDC", 10000.0)
    print(f"Deposit: {deposit_msg}")
    if "Deposited" not in deposit_msg:
        print("FAIL (Deposit)")
        return 1

    paper_swap = engine.execute_trade("agent_zero", "sell", "BTC/USDT", 0.5, 90000.0)
    if "Insufficient" in paper_swap:
        engine.deposit("agent_zero", "BTC", 1.0)
        paper_swap = engine.execute_trade("agent_zero", "sell", "BTC/USDT", 0.5, 90000.0)
    print(f"Paper Swap: {paper_swap}")
    if "Paper Trade Executed" not in paper_swap:
        print("FAIL (Paper Swap)")
        return 1

    print("\n--- Testing Phase 4: Backtesting ---")
    bt = BacktestEngine()
    df = bt.fetch_ohlcv("BTC/USDT", limit=20)
    print(f"Data Retrieved: {len(df)} rows")
    if len(df) <= 0 or "close" not in df.columns:
        print("FAIL (Fetch)")
        return 1

    strategy_code = """
def on_candle(close, rsi, state):
    if rsi < 50:
        return 'buy'
    if rsi > 50:
        return 'sell'
    return 'hold'
"""
    result = bt.run(strategy_code, "BTC/USDT", "1h")
    if "error" in result:
        print(f"FAIL: Backtest returned error: {result['error']}")
        return 1

    pnl = result.get("pnl")
    pnl_pct = result.get("pnl_percent")
    trades = result.get("total_trades")
    print(f"Backtest Result: PnL: {pnl} ({pnl_pct}%) | Trades: {trades}")

    print("\n--- Testing Phase 5: Advanced Intelligence ---")
    social = analyze_social_sentiment("BTC")
    print(f"Social: {social}")
    fin_news = fetch_financial_news("BTC")
    print(f"Financial: {fin_news}")

    print("\n--- Testing Phase 5: Limit Orders ---")
    engine = PaperTradingEngine()
    engine.deposit("agent_zero", "USDT", 1000.0)
    order_msg = engine.place_limit_order("agent_zero", "buy", "BTC/USDT", 1.0, 100.0)
    print(f"Order Msg: {order_msg}")
    if "Order Placed" not in order_msg:
        print("FAIL (Placement)")
        return 1

    filled = engine.check_open_orders("BTC/USDT", 50000.0)
    if filled:
        print("FAIL: Filled unexpectedly!")
        return 1

    filled = engine.check_open_orders("BTC/USDT", 50.0)
    if not filled or "FILLED" not in filled[0]:
        print("FAIL: Did not fill!")
        return 1
    print(f"Filled: {filled[0]}")

    print("\n--- Testing Phase 6: Regime & Risk ---")
    detector = RegimeDetector()
    guardian = RiskGuardian()
    df = bt.fetch_ohlcv("BTC/USDT", "1d", limit=100)
    regime_res = detector.detect(df)
    print(f"Regime: {json.dumps(regime_res)}")
    if "regime" not in regime_res:
        print("FAIL (Regime Structure)")
        return 1

    safe = guardian.validate_trade("buy", "BTC", 100.0, 10000.0)
    risky = guardian.validate_trade("buy", "BTC", 6000.0, 10000.0)
    if not safe.get("allowed"):
        print(f"FAIL (Safe Trade): {safe}")
        return 1
    if risky.get("allowed"):
        print(f"FAIL (Risky Trade allowed): {risky}")
        return 1

    print("\nALL VERIFICATION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


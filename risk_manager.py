from typing import Any, Dict


class RiskGuardian:
    def __init__(self):
        pass

    def validate_trade(self, 
                      side: str, 
                      symbol: str, 
                      amount_usd: float, 
                      portfolio_value: float, 
                      sentiment_score: float = 0.0,
                      daily_loss_pct: float = 0.0,
                      current_drawdown_pct: float = 0.0) -> Dict[str, Any]:
        """
        Validate a trade against safety rules.
        """
        # Rule 0: System State Checks
        # Max Drawdown Check (10%)
        # If drawdown is 10%, we only allow reducing risk (SELLs), not BUYs?
        # Or we block everything? Usually block BUYs.
        if current_drawdown_pct >= 0.10 and side.lower() == 'buy':
             return {
                "allowed": False,
                "reason": f"Max Drawdown Limit Hit ({current_drawdown_pct:.1%}). Trading HALTED for Buys."
             }
             
        # Daily Loss Limit (5%)
        # If we lost 5% today, stop trading.
        # daily_loss_pct is usually negative (e.g. -0.05)
        if daily_loss_pct <= -0.05 and side.lower() == 'buy':
             return {
                "allowed": False,
                "reason": f"Daily Loss Limit Hit ({daily_loss_pct:.1%}). Trading HALTED for Buys."
             }

        # Rule 1: Position Sizing
        # Max 5% of portfolio per trade
        max_alloc_pct = 0.05
        if portfolio_value > 0:
            trade_pct = amount_usd / portfolio_value
            if trade_pct > max_alloc_pct:
                return {
                    "allowed": False,
                    "reason": f"Position size too large ({trade_pct:.1%}). Max allowed is {max_alloc_pct:.0%}."
                }

        # Rule 2: "Don't Catch Falling Knives"
        # If sentiment is very bearish (< -0.5) and trying to Buy
        if side.lower() == 'buy' and sentiment_score < -0.5:
             return {
                "allowed": False,
                "reason": "Guardian blocked BUY due to Extreme Bearish sentiment (Falling Knife protection)."
            }
            
        return {
            "allowed": True,
            "reason": "Trade looks safe."
        }

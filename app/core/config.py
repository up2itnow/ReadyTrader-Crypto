import os

from dotenv import load_dotenv

load_dotenv()

class Settings:
    PROJECT_NAME: str = "ReadyTrader-Crypto"
    VERSION: str = "0.1.0"
    
    PAPER_MODE: bool = os.getenv("PAPER_MODE", "true").lower() == "true"
    LIVE_TRADING_ENABLED: bool = os.getenv("LIVE_TRADING_ENABLED", "false").strip().lower() == "true"
    TRADING_HALTED: bool = os.getenv("TRADING_HALTED", "false").strip().lower() == "true"
    
    # Risk & execution
    EXECUTION_APPROVAL_MODE: str = os.getenv("EXECUTION_APPROVAL_MODE", "auto").strip().lower()
    EXECUTION_MODE: str = os.getenv("EXECUTION_MODE", "auto").strip().lower()
    RISK_PROFILE: str = os.getenv("RISK_PROFILE", "conservative").strip().lower()
    
    # Observability
    RATE_LIMIT_DEFAULT_PER_MIN: int = int(os.getenv("RATE_LIMIT_DEFAULT_PER_MIN", "120"))
    
settings = Settings()

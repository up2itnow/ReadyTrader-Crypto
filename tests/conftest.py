import os
import sys

import pytest

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backtest_engine import BacktestEngine
from paper_engine import PaperTradingEngine
from risk_manager import RiskGuardian


@pytest.fixture
def risk_guardian():
    return RiskGuardian()

@pytest.fixture
def backtest_engine():
    return BacktestEngine()

@pytest.fixture
def paper_engine():
    # Use memory database for testing
    return PaperTradingEngine(db_path=":memory:")

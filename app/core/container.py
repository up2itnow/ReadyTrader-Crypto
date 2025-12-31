from app.core.config import settings
from backtest_engine import BacktestEngine
from dex_handler import DexHandler
from exchange_provider import ExchangeProvider
from execution.binance_user_stream import BinanceUserStreamManager
from execution.private_updates import CexPrivateUpdateManager
from execution_store import ExecutionStore
from idempotency_store import IdempotencyStore
from intelligence import InsightStore
from learning import Learner
from market_regime import RegimeDetector
from marketdata import (
    CcxtMarketDataProvider,
    IngestMarketDataProvider,
    InMemoryMarketDataStore,
    MarketDataBus,
    WsStreamManager,
    load_marketdata_plugins,
)
from observability import AuditLog, Metrics
from paper_engine import PaperTradingEngine
from policy_engine import PolicyEngine
from rate_limiter import FixedWindowRateLimiter
from risk_manager import RiskGuardian
from signing import get_signer
from strategy.marketplace import StrategyRegistry


class Container:
    def __init__(self):
        # Observability
        self.metrics = Metrics()
        self.audit_log = AuditLog()
        
        # Core Engines
        self.paper_engine = PaperTradingEngine() if settings.PAPER_MODE else None
        self.backtest_engine = BacktestEngine()
        self.regime_detector = RegimeDetector()
        self.risk_guardian = RiskGuardian()
        self.policy_engine = PolicyEngine()
        self.rate_limiter = FixedWindowRateLimiter()
        
        # Stores
        self.execution_store = ExecutionStore()
        self.idempotency_store = IdempotencyStore()
        self.insight_store = InsightStore()
        self.strategy_registry = StrategyRegistry()
        
        # Market Data & Execution
        self.exchange_provider = ExchangeProvider()
        self.marketdata_store = InMemoryMarketDataStore()
        self.marketdata_ws_store = InMemoryMarketDataStore()
        self.ws_manager = WsStreamManager(store=self.marketdata_ws_store, metrics=self.metrics)
        self.binance_user_streams = BinanceUserStreamManager(metrics=self.metrics)
        self.cex_private_updates = CexPrivateUpdateManager()
        
        self.marketdata_bus = MarketDataBus([
            IngestMarketDataProvider(store=self.marketdata_store),
            IngestMarketDataProvider(store=self.marketdata_ws_store, provider_id="exchange_ws"),
            *load_marketdata_plugins(),
            CcxtMarketDataProvider(exchange_provider=self.exchange_provider),
        ])
        
        self.dex_handler = DexHandler()
        self.signer = get_signer()
        self.learner = Learner(db_path=self.paper_engine.db_path) if settings.PAPER_MODE and self.paper_engine else None

global_container = Container()

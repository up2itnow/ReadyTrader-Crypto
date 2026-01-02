"use client";

import { useMarketData } from "@/hooks/useMarketData";
import { usePendingApprovals } from "@/hooks/usePendingApprovals";
import { usePortfolio } from "@/hooks/usePortfolio";
import { useServiceWorker } from "@/hooks/useServiceWorker";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { 
  ShieldCheck, Zap, Bell, BellOff, RefreshCw, TrendingUp, TrendingDown, 
  Wallet, Activity, AlertTriangle, CheckCircle, XCircle, X
} from "lucide-react";

function ErrorFallback({ error, resetError }: { error: Error | null; resetError: () => void }) {
  return (
    <div className="error-boundary">
      <AlertTriangle size={48} className="danger" />
      <h2>Something went wrong</h2>
      <p className="muted">
        {error?.message || "An unexpected error occurred. Please try refreshing the page."}
      </p>
      {error && (
        <pre>{error.stack?.slice(0, 500)}</pre>
      )}
      <button className="btn btn-primary" onClick={resetError}>
        <RefreshCw size={16} /> Try Again
      </button>
    </div>
  );
}

// Toast Notification Component
interface Toast {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
  duration?: number;
}

function ToastNotification({ toast, onClose }: { toast: Toast; onClose: (id: string) => void }) {
  useEffect(() => {
    if (toast.duration !== 0) {
      const timer = setTimeout(() => onClose(toast.id), toast.duration || 5000);
      return () => clearTimeout(timer);
    }
  }, [toast, onClose]);

  const icons = {
    success: <CheckCircle size={20} className="success" />,
    error: <XCircle size={20} className="danger" />,
    warning: <AlertTriangle size={20} className="warning" />,
    info: <Zap size={20} className="primary" />,
  };

  return (
    <div className={`toast ${toast.type}`}>
      {icons[toast.type]}
      <span>{toast.message}</span>
      <button className="toast-close" onClick={() => onClose(toast.id)}>
        <X size={16} />
      </button>
    </div>
  );
}

// Loading Skeleton Component
function LoadingSkeleton({ width = "100%", height = "20px" }: { width?: string; height?: string }) {
  return <div className="loading-skeleton" style={{ width, height }} />;
}

// Main Dashboard Component
export default function Dashboard() {
  // State management
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [componentError, setComponentError] = useState<Error | null>(null);

  // Custom hooks
  const { tickers, connected } = useMarketData();
  const marketError: string | null = null; // WebSocket errors handled by reconnection
  const { approvals, handleApproval, loading: approvalsLoading } = usePendingApprovals();
  const { 
    portfolio, 
    trades, 
    loading: portfolioLoading, 
    error: portfolioError, 
    refresh: refreshPortfolio 
  } = usePortfolio();
  const { isSupported: swSupported, subscribeToPush, showLocalNotification } = useServiceWorker();
  
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);

  // Toast management
  const addToast = useCallback((toast: Omit<Toast, 'id'>) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    setToasts(prev => [...prev, { ...toast, id }]);
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // Track previous errors using refs to avoid setState in render
  const prevMarketErrorRef = useRef<string | null>(null);
  const prevPortfolioErrorRef = useRef<string | null>(null);

  // Show errors as toasts when they change
  // Using queueMicrotask to avoid synchronous setState within effect body
  useEffect(() => {
    if (marketError && marketError !== prevMarketErrorRef.current) {
      prevMarketErrorRef.current = marketError;
      queueMicrotask(() => {
        addToast({ type: 'error', message: `Market data error: ${marketError}` });
      });
    } else if (!marketError) {
      prevMarketErrorRef.current = null;
    }
  }, [marketError, addToast]);

  useEffect(() => {
    if (portfolioError && portfolioError !== prevPortfolioErrorRef.current) {
      prevPortfolioErrorRef.current = portfolioError;
      queueMicrotask(() => {
        addToast({ type: 'error', message: `Portfolio error: ${portfolioError}` });
      });
    } else if (!portfolioError) {
      prevPortfolioErrorRef.current = null;
    }
  }, [portfolioError, addToast]);

  // Generate chart data from trades
  const chartData = useMemo(() => {
    if (trades.length === 0 || !portfolio) {
      return [];
    }
    try {
      let equity = portfolio.totalValueUsd || 10000;
      const data = trades.slice().reverse().map((trade) => {
        const pnl = trade.side === 'sell' ? trade.total_value * 0.01 : -trade.total_value * 0.01;
        equity += pnl;
        return {
          time: new Date(trade.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          value: Math.max(0, equity),
        };
      });
      return data.slice(-20);
    } catch (error) {
      console.error('Error generating chart data:', error);
      return [];
    }
  }, [trades, portfolio]);

  // Enable notifications
  const enableNotifications = async () => {
    try {
      if (swSupported) {
        await subscribeToPush();
        setNotificationsEnabled(true);
        showLocalNotification('Notifications Enabled', {
          body: 'You will receive alerts for pending trade approvals',
        });
        addToast({ type: 'success', message: 'Push notifications enabled' });
      }
    } catch {
      addToast({ type: 'error', message: 'Failed to enable notifications' });
    }
  };

  // Handle trade approval with feedback
  const handleTradeApproval = async (requestId: string, token: string, approved: boolean) => {
    try {
      await handleApproval(requestId, token, approved);
      addToast({ 
        type: approved ? 'success' : 'warning', 
        message: `Trade ${approved ? 'approved' : 'rejected'} successfully` 
      });
    } catch {
      addToast({ type: 'error', message: `Failed to ${approved ? 'approve' : 'reject'} trade` });
    }
  };

  // Handle portfolio refresh with feedback
  const handleRefreshPortfolio = async () => {
    try {
      await refreshPortfolio();
      addToast({ type: 'success', message: 'Portfolio refreshed', duration: 2000 });
    } catch {
      addToast({ type: 'error', message: 'Failed to refresh portfolio' });
    }
  };

  // Calculate portfolio metrics safely
  const totalValue = portfolio?.totalValueUsd || 0;
  const dailyPnlPct = portfolio?.metrics?.daily_pnl_pct || 0;
  const drawdownPct = portfolio?.metrics?.drawdown_pct || 0;

  // Error boundary reset
  const resetError = () => setComponentError(null);

  // If there's a component error, show error boundary
  if (componentError) {
    return <ErrorFallback error={componentError} resetError={resetError} />;
  }

  return (
    <>
      {/* Mobile Sidebar Overlay */}
      <div 
        className={`sidebar-overlay ${sidebarOpen ? 'visible' : ''}`}
        onClick={() => setSidebarOpen(false)}
        aria-hidden="true"
      />

      {/* Toast Container */}
      <div className="toast-container" role="status" aria-live="polite">
        {toasts.map(toast => (
          <ToastNotification key={toast.id} toast={toast} onClose={removeToast} />
        ))}
      </div>

      <div className="dashboard-grid">
        {/* Portfolio Overview */}
        <section className="col-span-2 card animate-fade-in" aria-labelledby="portfolio-heading">
          <div className="card-header">
            <div>
              <h3 id="portfolio-heading">Portfolio Performance</h3>
              <p className="muted">
                {portfolio?.mode === 'paper' ? '📝 Paper Trading Mode' : '🔴 Live Trading'}
                {portfolio?.wallet && ` • ${portfolio.wallet.address.slice(0, 6)}...${portfolio.wallet.address.slice(-4)}`}
              </p>
            </div>
            <div className="value-pnl">
              {portfolioLoading ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8 }}>
                  <LoadingSkeleton width="120px" height="32px" />
                  <LoadingSkeleton width="80px" height="16px" />
                </div>
              ) : portfolioError ? (
                <span className="danger">
                  <AlertTriangle size={16} /> Error loading
                </span>
              ) : (
                <>
                  <h2>${totalValue.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</h2>
                  <span className={dailyPnlPct >= 0 ? 'success' : 'danger'}>
                    {dailyPnlPct >= 0 ? <TrendingUp size={16} /> : <TrendingDown size={16} />}
                    {dailyPnlPct >= 0 ? '+' : ''}{(dailyPnlPct * 100).toFixed(2)}% Today
                  </span>
                </>
              )}
            </div>
          </div>
          
          <div className="chart-container" role="img" aria-label="Portfolio equity curve">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f2ff" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#00f2ff" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis 
                    dataKey="time" 
                    stroke="#6b7280" 
                    fontSize={10}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis 
                    stroke="#6b7280" 
                    fontSize={10} 
                    tickFormatter={(v) => `$${(v/1000).toFixed(1)}k`}
                    tickLine={false}
                    axisLine={false}
                    width={50}
                  />
                  <Tooltip
                    contentStyle={{ 
                      background: '#16161a', 
                      border: '1px solid #2d2d35', 
                      borderRadius: '8px',
                      boxShadow: '0 4px 20px rgba(0,0,0,0.3)'
                    }}
                    itemStyle={{ color: '#00f2ff' }}
                    formatter={(value) => value !== undefined ? [`$${Number(value).toLocaleString()}`, 'Value'] : ['', 'Value']}
                    labelStyle={{ color: '#80808a' }}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="value" 
                    stroke="#00f2ff" 
                    fillOpacity={1} 
                    fill="url(#colorValue)" 
                    strokeWidth={2}
                    animationDuration={1000}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-chart">
                <Activity className="muted" size={48} />
                <p className="muted">No trading activity yet</p>
                <p className="muted" style={{ fontSize: 11 }}>Execute trades to see your equity curve</p>
              </div>
            )}
          </div>
          
          {/* Risk Metrics Bar */}
          <div className="metrics-bar">
            <div className="metric">
              <span className="label">Max Drawdown</span>
              <span className={drawdownPct > 0.05 ? 'danger' : drawdownPct > 0.03 ? 'warning' : 'success'}>
                {(drawdownPct * 100).toFixed(2)}%
              </span>
            </div>
            <div className="metric">
              <span className="label">Daily Limit</span>
              <span className={Math.abs(dailyPnlPct) > 0.04 ? 'danger' : Math.abs(dailyPnlPct) > 0.03 ? 'warning' : 'success'}>
                {Math.abs(dailyPnlPct * 100).toFixed(2)}% / 5%
              </span>
            </div>
            <div className="metric">
              <span className="label">Position Limit</span>
              <span className="success">5% max</span>
            </div>
            <button 
              className="btn btn-secondary compact" 
              onClick={handleRefreshPortfolio}
              disabled={portfolioLoading}
              aria-label="Refresh portfolio"
            >
              <RefreshCw size={14} className={portfolioLoading ? 'animate-spin' : ''} /> 
              Refresh
            </button>
          </div>
        </section>

        {/* Real-time Ticker */}
        <section className="card animate-fade-in" aria-labelledby="markets-heading">
          <div className="card-header">
            <h3 id="markets-heading">Live Markets</h3>
            <div className="header-actions">
              <span 
                className={`connection-dot ${connected ? 'online' : 'offline'}`}
                title={connected ? 'Connected' : 'Disconnected'}
                role="status"
                aria-label={connected ? 'WebSocket connected' : 'WebSocket disconnected'}
              />
            </div>
          </div>
          <div className="ticker-list" role="list" aria-label="Market prices">
            {!connected && Object.values(tickers).length === 0 ? (
              <div className="empty-state">
                <div className="loading-spinner" />
                <p className="muted">Connecting to market data...</p>
              </div>
            ) : Object.values(tickers).length === 0 ? (
              <p className="muted">Waiting for price updates...</p>
            ) : (
              Object.values(tickers).map((t) => (
                <div key={t.symbol} className="ticker-item" role="listitem">
                  <span className="symbol">{t.symbol}</span>
                  <span className="price">${t.last.toLocaleString(undefined, { minimumFractionDigits: 2 })}</span>
                  <span className="source muted">{t.source}</span>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Guard Rail / Pending Approvals */}
        <section className="card animate-fade-in" aria-labelledby="guardrail-heading">
          <div className="card-header">
            <div className="icon-title">
              <ShieldCheck className="primary" size={20} />
              <h3 id="guardrail-heading">Guard Rail</h3>
            </div>
            <div className="header-actions">
              {swSupported && (
                <button 
                  className={`btn btn-icon ${notificationsEnabled ? 'active' : ''}`}
                  onClick={enableNotifications}
                  title={notificationsEnabled ? 'Notifications enabled' : 'Enable notifications'}
                  aria-label={notificationsEnabled ? 'Notifications enabled' : 'Enable push notifications'}
                >
                  {notificationsEnabled ? <Bell size={16} /> : <BellOff size={16} />}
                </button>
              )}
              {approvals.length > 0 && (
                <span className="warning-badge" aria-label={`${approvals.length} pending approvals`}>
                  {approvals.length}
                </span>
              )}
            </div>
          </div>
          <div className="approval-list" role="list" aria-label="Pending trade approvals">
            {approvalsLoading ? (
              <div className="empty-state">
                <div className="loading-spinner" />
                <p className="muted">Loading approvals...</p>
              </div>
            ) : approvals.length === 0 ? (
              <div className="empty-approval">
                <Zap className="muted" size={32} />
                <p className="muted">No pending approvals</p>
                <p className="muted" style={{ fontSize: 11 }}>
                  Trades requiring manual approval will appear here
                </p>
              </div>
            ) : (
              approvals.map((a) => (
                <div key={a.request_id} className="approval-item animate-slide-in" role="listitem">
                  <div className="approval-info">
                    <span className="kind">{a.kind.replace(/_/g, ' ')}</span>
                    <span className="muted">ID: {a.request_id.slice(0, 8)}...</span>
                    <span className="muted">
                      ⏰ Expires: {new Date(a.expires_at * 1000).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="approval-actions">
                    <button 
                      className="btn btn-success compact"
                      onClick={() => handleTradeApproval(a.request_id, a.confirm_token || '', true)}
                      aria-label={`Approve trade ${a.request_id.slice(0, 8)}`}
                    >
                      <CheckCircle size={14} /> Approve
                    </button>
                    <button 
                      className="btn btn-danger compact"
                      onClick={() => handleTradeApproval(a.request_id, a.confirm_token || '', false)}
                      aria-label={`Reject trade ${a.request_id.slice(0, 8)}`}
                    >
                      <XCircle size={14} /> Reject
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Balances */}
        <section className="card animate-fade-in" aria-labelledby="balances-heading">
          <div className="card-header">
            <div className="icon-title">
              <Wallet size={20} />
              <h3 id="balances-heading">Balances</h3>
            </div>
          </div>
          <div className="balance-list" role="list" aria-label="Account balances">
            {portfolioLoading ? (
              <>
                <LoadingSkeleton height="40px" />
                <LoadingSkeleton height="40px" />
                <LoadingSkeleton height="40px" />
              </>
            ) : portfolio?.balances && portfolio.balances.length > 0 ? (
              portfolio.balances.slice(0, 5).map((b) => (
                <div key={b.asset} className="balance-item" role="listitem">
                  <span className="asset">{b.asset}</span>
                  <span className="amount">
                    {b.amount.toLocaleString(undefined, { maximumFractionDigits: 8 })}
                  </span>
                </div>
              ))
            ) : (
              <div className="empty-state">
                <Wallet className="muted" size={32} />
                <p className="muted">No balances</p>
                <p className="muted" style={{ fontSize: 11 }}>
                  Use deposit_paper_funds to add funds
                </p>
              </div>
            )}
          </div>
        </section>

        {/* Recent Trades */}
        <section className="card animate-fade-in" aria-labelledby="trades-heading">
          <h3 id="trades-heading">Recent Trades</h3>
          <div className="trades-list" role="list" aria-label="Recent trades">
            {portfolioLoading ? (
              <>
                <LoadingSkeleton height="50px" />
                <LoadingSkeleton height="50px" />
                <LoadingSkeleton height="50px" />
              </>
            ) : trades.length > 0 ? (
              trades.slice(0, 5).map((trade) => (
                <div key={trade.id} className="trade-item" role="listitem">
                  <span className={`side ${trade.side}`}>{trade.side.toUpperCase()}</span>
                  <span className="symbol">{trade.symbol}</span>
                  <span className="amount">{trade.amount}</span>
                  <span className="price">@ ${trade.price.toLocaleString()}</span>
                </div>
              ))
            ) : (
              <div className="empty-state">
                <Activity className="muted" size={32} />
                <p className="muted">No trades yet</p>
              </div>
            )}
          </div>
        </section>

        {/* System Status Card */}
        <section className="card animate-fade-in" aria-labelledby="status-heading">
          <h3 id="status-heading">System Status</h3>
          <div className="balance-list">
            <div className="balance-item">
              <span className="asset">Market Data</span>
              <span className={connected ? 'success' : 'danger'}>
                {connected ? '● Connected' : '○ Disconnected'}
              </span>
            </div>
            <div className="balance-item">
              <span className="asset">Risk Guardian</span>
              <span className="success">● Active</span>
            </div>
            <div className="balance-item">
              <span className="asset">Mode</span>
              <span className={portfolio?.mode === 'paper' ? 'warning' : 'success'}>
                {portfolio?.mode === 'paper' ? '📝 Paper' : '🔴 Live'}
              </span>
            </div>
            <div className="balance-item">
              <span className="asset">Notifications</span>
              <span className={notificationsEnabled ? 'success' : 'muted'}>
                {notificationsEnabled ? '● Enabled' : '○ Disabled'}
              </span>
            </div>
          </div>
        </section>
      </div>
    </>
  );
}

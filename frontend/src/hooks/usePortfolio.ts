"use client";

import { useState, useEffect, useCallback } from 'react';

export interface Balance {
  asset: string;
  amount: number;
  valueUsd: number;
}

export interface RiskMetrics {
  daily_pnl_pct: number;
  drawdown_pct: number;
}

export interface PortfolioData {
  mode: 'paper' | 'live';
  totalValueUsd: number;
  balances: Balance[];
  metrics: RiskMetrics;
  wallet?: {
    address: string;
  };
  onchain?: Record<string, { native_balance_wei?: number; error?: string }>;
  cex?: Record<string, { balance?: Record<string, number>; error?: string }>;
}

export interface TradeHistory {
  id: number;
  timestamp: string;
  side: string;
  symbol: string;
  amount: number;
  price: number;
  total_value: number;
  rationale: string;
}

export function usePortfolio() {
  const [portfolio, setPortfolio] = useState<PortfolioData | null>(null);
  const [trades, setTrades] = useState<TradeHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPortfolio = useCallback(async () => {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await fetch(`${apiUrl}/api/portfolio`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token') || ''}`,
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          setError('Authentication required');
          return;
        }
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      
      // Transform the response based on mode
      if (data.balances) {
        // Paper mode response
        const balances: Balance[] = Object.entries(data.balances).map(([asset, amount]) => ({
          asset,
          amount: amount as number,
          valueUsd: asset.toUpperCase() === 'USDT' || asset.toUpperCase() === 'USDC' 
            ? (amount as number) 
            : 0, // Would need price data for accurate USD value
        }));

        const totalValue = balances.reduce((sum, b) => sum + b.valueUsd, 0);

        setPortfolio({
          mode: 'paper',
          totalValueUsd: totalValue,
          balances,
          metrics: data.metrics || { daily_pnl_pct: 0, drawdown_pct: 0 },
        });
      } else if (data.mode === 'live') {
        // Live mode response
        const balances: Balance[] = [];
        
        // Process CEX balances
        if (data.cex) {
          for (const [exchange, info] of Object.entries(data.cex)) {
            const balanceInfo = info as { balance?: Record<string, number>; error?: string };
            if (balanceInfo.balance) {
              for (const [asset, amount] of Object.entries(balanceInfo.balance)) {
                if (amount > 0) {
                  balances.push({
                    asset: `${asset} (${exchange})`,
                    amount,
                    valueUsd: 0, // Would need price data
                  });
                }
              }
            }
          }
        }

        setPortfolio({
          mode: 'live',
          totalValueUsd: 0, // Would need price data
          balances,
          metrics: { daily_pnl_pct: 0, drawdown_pct: 0 },
          wallet: data.wallet,
          onchain: data.onchain,
          cex: data.cex,
        });
      }

      setError(null);
    } catch (err) {
      console.error('Failed to fetch portfolio:', err);
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchTrades = useCallback(async (limit: number = 50) => {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await fetch(`${apiUrl}/api/trades/history?limit=${limit}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token') || ''}`,
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      setTrades(data.trades || []);
    } catch (err) {
      console.error('Failed to fetch trades:', err);
    }
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchPortfolio();
    fetchTrades();
  }, [fetchPortfolio, fetchTrades]);

  // Refresh periodically
  useEffect(() => {
    const interval = setInterval(() => {
      fetchPortfolio();
    }, 30000); // Every 30 seconds

    return () => clearInterval(interval);
  }, [fetchPortfolio]);

  // Listen for approval processed events
  useEffect(() => {
    const handleApprovalProcessed = () => {
      // Refresh portfolio after trade approval
      fetchPortfolio();
      fetchTrades();
    };

    window.addEventListener('approvalProcessed', handleApprovalProcessed);
    return () => window.removeEventListener('approvalProcessed', handleApprovalProcessed);
  }, [fetchPortfolio, fetchTrades]);

  return {
    portfolio,
    trades,
    loading,
    error,
    refresh: fetchPortfolio,
    refreshTrades: fetchTrades,
  };
}

// Hook for authentication
export function useAuth() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<{ user_id: string; role: string } | null>(null);
  const [loading, setLoading] = useState(true);

  // Define fetchUser first since login depends on it
  const fetchUser = useCallback(async () => {
    const token = localStorage.getItem('auth_token');
    if (!token) {
      setLoading(false);
      return;
    }

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await fetch(`${apiUrl}/api/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setUser(data);
        setIsAuthenticated(true);
      } else {
        // Token invalid or expired
        localStorage.removeItem('auth_token');
        setIsAuthenticated(false);
        setUser(null);
      }
    } catch (err) {
      console.error('Failed to fetch user:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await fetch(`${apiUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Login failed');
      }

      const data = await response.json();
      localStorage.setItem('auth_token', data.access_token);
      
      // Fetch user info
      await fetchUser();
      
      return true;
    } catch (err) {
      console.error('Login failed:', err);
      throw err;
    }
  }, [fetchUser]);

  const logout = useCallback(() => {
    localStorage.removeItem('auth_token');
    setIsAuthenticated(false);
    setUser(null);
  }, []);

  // Check auth on mount
  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  return {
    isAuthenticated,
    user,
    loading,
    login,
    logout,
  };
}

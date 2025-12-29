## ReadyTrader Runbook (Docker-first)

### Common operations

#### Verify health
- Use MCP tool: `get_health()`
- If health fails:
  - confirm required environment variables are set
  - confirm exchange endpoints are reachable (REST + websocket if enabled)
  - confirm rate limits and policy allowlists are not blocking requests

#### View metrics
- Use MCP tool: `get_metrics_snapshot()`

#### Kill switch (live trading)
- Set `TRADING_HALTED=true` and restart the container.

#### Rotate secrets
- Prefer keystore or remote signer in live environments.
- Rotate `CEX_*` credentials by updating env vars and restarting.

#### Debug execution failures
- Look for JSON logs with `event=tool_error`.
- In approve-each mode, use `list_pending_executions()` to inspect pending proposals.
- Re-run failed operations with an `idempotency_key` to avoid duplicates.

#### Websocket market streams
- Start public streams with `start_marketdata_ws(...)` and stop with `stop_marketdata_ws(...)`.
- For Binance private order updates, use `start_cex_private_ws(...)` / `stop_cex_private_ws(...)`, and inspect with
  `list_cex_private_updates(...)`.

### Backup/restore (paper mode)
- Paper ledger is stored in `paper.db` (ignored by git).
- Back up by copying the file while the container is stopped.


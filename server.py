"""
ReadyTrader-Crypto canonical entrypoint.

This is the single source of truth for:
- MCP server name
- tool registration order

Other entrypoints (e.g. `app/main.py`) should import `mcp` from here.
"""

from __future__ import annotations

from fastmcp import FastMCP

from app.tools.execution import register_execution_tools
from app.tools.market_data import register_market_tools
from app.tools.research import register_research_tools
from app.tools.trading import register_trading_tools

# Initialize FastMCP server
mcp = FastMCP("ReadyTrader-Crypto")

# Register Tools
register_market_tools(mcp)
register_trading_tools(mcp)
register_research_tools(mcp)
register_execution_tools(mcp)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()


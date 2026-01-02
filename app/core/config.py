"""
ReadyTrader-Crypto Configuration (Legacy Compatibility)

This module re-exports the unified settings for backward compatibility.
New code should import directly from app.core.settings.
"""

from app.core.settings import Settings, get_execution_approval_mode, set_execution_approval_mode, settings

# Legacy: expose settings object attributes as class attributes
# New code should use settings.ATTRIBUTE directly
__all__ = ["settings", "Settings", "get_execution_approval_mode", "set_execution_approval_mode"]

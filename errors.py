from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import ccxt


@dataclass
class AppError(Exception):
    code: str
    message: str
    data: Dict[str, Any]


def classify_exception(e: Exception) -> AppError:
    """
    Map common CCXT / network issues into stable error codes.
    """
    # CCXT base exceptions
    if isinstance(e, ccxt.BadSymbol):
        return AppError("ccxt_bad_symbol", str(e), {})
    if isinstance(e, ccxt.AuthenticationError):
        return AppError("ccxt_auth_error", str(e), {})
    if isinstance(e, ccxt.PermissionDenied):
        return AppError("ccxt_permission_denied", str(e), {})
    if isinstance(e, ccxt.RateLimitExceeded):
        return AppError("ccxt_rate_limited", str(e), {})
    if isinstance(e, ccxt.NetworkError):
        return AppError("ccxt_network_error", str(e), {})
    if isinstance(e, ccxt.ExchangeNotAvailable):
        return AppError("ccxt_exchange_unavailable", str(e), {})
    if isinstance(e, ccxt.ExchangeError):
        return AppError("ccxt_exchange_error", str(e), {})

    return AppError("unknown_error", str(e), {})


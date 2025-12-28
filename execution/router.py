from __future__ import annotations


def venue_allowed(execution_mode: str, venue: str) -> bool:
    """
    Basic router for Phase 3.

    - dex mode: only DEX actions
    - cex mode: only CEX actions
    - hybrid mode: both
    """
    m = (execution_mode or "").strip().lower()
    v = (venue or "").strip().lower()

    if m == "hybrid":
        return v in {"dex", "cex"}
    if m == "dex":
        return v == "dex"
    if m == "cex":
        return v == "cex"
    # Unknown execution mode: safest is deny
    return False


from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _is_excluded(path: Path) -> bool:
    parts = set(path.parts)
    if "vendor" in parts:
        return True
    if "tests" in parts:
        return True
    if "frontend" in parts:
        return True
    if "docs" in parts:
        return True
    if "__pycache__" in parts:
        return True
    return False


def test_no_stubs_or_todos_in_runtime_code() -> None:
    """
    Enforce a repo-wide production quality rule:
    - no TODO/FIXME/XXX placeholders in runtime code
    - no \"simulated live\" execution paths
    """
    forbidden_substrings = [
        "TODO",
        "FIXME",
        "XXX",
        "simulated live",
        "SIMULATED LIVE",
        "not yet ported",
        "not yet implemented",
    ]

    hits: list[str] = []
    for p in REPO_ROOT.rglob("*.py"):
        if _is_excluded(p):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), start=1):
            for s in forbidden_substrings:
                if s in line:
                    hits.append(f"{p.relative_to(REPO_ROOT)}:{i}:{line.strip()}")

    assert not hits, "Found stub/TODO markers in runtime code:\\n" + "\\n".join(hits)


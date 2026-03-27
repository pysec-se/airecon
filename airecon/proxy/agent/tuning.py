"""Centralized runtime tuning loader for agent heuristics.

Heuristic values live in data/tools_meta.json under "agent_tuning" so
behavior can be tuned without touching Python logic.
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.tuning")


@lru_cache(maxsize=1)
def load_agent_tuning() -> dict[str, Any]:
    """Load agent tuning config from tools_meta.json."""
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        tuning = raw.get("agent_tuning", {})
        if isinstance(tuning, dict):
            return tuning
    except Exception as exc:
        logger.debug("Could not load agent_tuning from tools_meta.json: %s", exc)
    return {}


def get_tuning(path: str, default: Any) -> Any:
    """Get nested tuning value by dotted path with a default fallback."""
    node: Any = load_agent_tuning()
    for part in str(path or "").split("."):
        if not part:
            continue
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


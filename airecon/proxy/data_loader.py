from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.proxy.data_loader")

_DATA_DIR = Path(__file__).parent / "data"


def _load_json(filename: str) -> dict[str, Any]:
    """Load a JSON file from the data directory. Returns empty dict on failure."""
    path = _DATA_DIR / filename
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load %s: %s", filename, exc)
        return {}


# ── Verification patterns ────────────────────────────────────────────────────


def load_verification_patterns() -> dict[str, Any]:
    """Load verification patterns (clean response, dynamic content, honeypot, etc.)."""
    return _load_json("verification_patterns.json")


# ── File extensions ──────────────────────────────────────────────────────────


def load_file_extensions() -> dict[str, Any]:
    """Load file extension categories (static, high_value, document, backend)."""
    return _load_json("file_extensions.json")


# ── Endpoint patterns ────────────────────────────────────────────────────────


def load_endpoint_patterns() -> dict[str, Any]:
    """Load endpoint and subdomain scoring patterns."""
    return _load_json("endpoint_patterns.json")


# ── Tech correlations ────────────────────────────────────────────────────────


def load_tech_correlations() -> dict[str, Any]:
    """Load technology correlation data (vulns, paths, tools, severity)."""
    return _load_json("tech_correlations.json")


# ── Tools metadata ───────────────────────────────────────────────────────────


def load_tools_meta() -> dict[str, Any]:
    """Load tools metadata (categories, tuning, hints, etc.)."""
    return _load_json("tools_meta.json")


# ── Tools definitions ────────────────────────────────────────────────────────


def load_tools() -> list[dict[str, Any]]:
    """Load tool definitions from tools.json."""
    path = _DATA_DIR / "tools.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load tools.json: %s", exc)
        return []


# ── Fuzzer data ──────────────────────────────────────────────────────────────


def load_fuzzer_data() -> dict[str, Any]:
    """Load fuzzer payloads, vulnerable patterns, and chain rules."""
    return _load_json("fuzzer_data.json")


# ── WAF signatures ───────────────────────────────────────────────────────────


def load_waf_signatures() -> dict[str, Any]:
    """Load WAF detection signatures."""
    return _load_json("waf_signatures.json")


# ── WAF bypass strategies ────────────────────────────────────────────────────


def load_waf_bypass_strategies(waf_name: str) -> list[str]:
    """Load WAF bypass strategies for a specific WAF."""
    data = _load_json("waff_bypass.json")
    strategies = data.get("BYPASS_STRATEGIES", {})
    waf_key = waf_name.lower().replace(" ", "_")
    waf_data = strategies.get(waf_key, {})
    if isinstance(waf_data, list):
        return [str(s) for s in waf_data]
    if isinstance(waf_data, dict):
        return [f"{waf_data.get('name', '')}: {waf_data.get('description', '')}"]
    return []


# ── Recon tools ──────────────────────────────────────────────────────────────


def load_recon_tools() -> set[str]:
    """Load all reconnaissance tool names from tools_meta.json."""
    meta = _load_json("tools_meta.json")
    categories = meta.get("categories", {}).get("reconnaissance", {})
    tools: set[str] = set()
    for subcat in categories.values():
        if isinstance(subcat, list):
            tools.update(subcat)
    tools |= {"execute", "browser_action"}
    return tools


# ── Attack chains ────────────────────────────────────────────────────────────


def load_attack_chains() -> list[dict[str, Any]]:
    """Load and normalize attack chains from attack_chains.json."""
    raw = _load_json("attack_chains.json")
    if not raw:
        return []

    if isinstance(raw, dict) and "chains" in raw:
        chains = raw["chains"]
    elif isinstance(raw, list):
        chains = raw
    else:
        return []

    normalized: list[dict[str, Any]] = []
    for i, entry in enumerate(chains):
        if not isinstance(entry, dict):
            continue
        triggers = entry.get("triggers") or entry.get("required_findings") or []
        raw_steps = entry.get("steps", [])
        steps: list[dict[str, Any]] = []
        for step in raw_steps:
            if isinstance(step, dict):
                steps.append(step)
            elif isinstance(step, str):
                steps.append({"description": step, "tool_hint": "execute"})

        normalized.append(
            {
                "id": entry.get("id") or f"chain_{i}",
                "name": entry.get("name", f"Chain {i}"),
                "description": entry.get("description", ""),
                "triggers": [str(t).lower() for t in triggers],
                "required_findings": [str(t).lower() for t in triggers],
                "steps": steps,
                "severity": entry.get("severity", ""),
                "estimated_time": entry.get("estimated_time", ""),
                "detection_risk": entry.get("detection_risk", ""),
                "prerequisites": entry.get("prerequisites", []),
                "post_exploitation": entry.get("post_exploitation", []),
            }
        )
    return normalized


# ── Utility: merge headers ───────────────────────────────────────────────────


def merge_headers(
    base_headers: dict[str, str] | None,
    override_headers: dict[str, str] | None,
) -> dict[str, str] | None:
    """Merge two header dicts. Override takes precedence."""
    if not base_headers and not override_headers:
        return None
    merged: dict[str, str] = {}
    if base_headers:
        merged.update(base_headers)
    if override_headers:
        merged.update(override_headers)
    return merged


# ── Severity ranking (consistent 1-5 scale) ──────────────────────────────────

SEVERITY_TO_INT: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

INT_TO_SEVERITY: dict[int, str] = {v: k for k, v in SEVERITY_TO_INT.items()}


def severity_to_int(severity: str) -> int:
    """Convert severity label to integer (1-5 scale)."""
    return SEVERITY_TO_INT.get(severity.upper(), 1)


def int_to_severity(value: int) -> str:
    """Convert integer to severity label (1-5 scale)."""
    return INT_TO_SEVERITY.get(value, "INFO")


# ── WAF bypass strategies ────────────────────────────────────────────────────

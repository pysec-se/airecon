from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent")


def _load_specialist_prefixes() -> dict[str, str]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        return json.loads(path.read_text(encoding="utf-8")).get("specialist_prompts", {})
    except Exception as exc:
        logger.warning("Could not load specialist_prompts from tools_meta.json: %s", exc)
        return {}


_SPECIALIST_PREFIXES: dict[str, str] = _load_specialist_prefixes()

_RESULT_TRUNCATION_THRESHOLD = 10000
_READ_FILE_CONTENT_TRUNCATION_THRESHOLD = 2000
_MAX_COMMAND_LENGTH = 20_000

_REPORT_FILE_PATTERNS = (
    "final_report", "report", "vuln", "vulnerability", "finding",
    "assessment", "security_report", "pentest_report", "summary_report",
)


def _safe_non_negative_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed >= 0 else 0


def _load_recon_bins(category: str, fallback: frozenset[str]) -> frozenset[str]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        bins = (
            data.get("categories", {})
            .get("reconnaissance", {})
            .get(category, [])
        )
        return frozenset(str(x).strip().lower() for x in bins if str(x).strip())
    except Exception as exc:
        logger.warning(
            "Could not load recon bins (category=%r) from tools_meta.json: %s — "
            "falling back to built-in list. Check that data/tools_meta.json exists.",
            category,
            exc,
        )
        return fallback


_RECON_SUBDOMAIN_BINS: frozenset[str] = _load_recon_bins(
    "subdomain_enum",
    frozenset({"subfinder", "amass", "assetfinder", "findomain", "dnsx"}),
)

_RECON_PORT_SCAN_BINS: frozenset[str] = _load_recon_bins(
    "port_scan",
    frozenset({"nmap", "masscan", "naabu", "rustscan"}),
)

_RECON_LIVE_HOST_BINS: frozenset[str] = _load_recon_bins(
    "live_host_probe",
    frozenset({"httpx", "httprobe", "dnsx"}),
)

_RECON_CONTENT_DISCOVERY_BINS: frozenset[str] = (
    _load_recon_bins("crawling", frozenset({"katana", "waybackurls", "gau", "hakrawler"}))
    | _load_recon_bins("directory_bruteforce", frozenset({"gobuster", "feroxbuster", "ffuf", "dirsearch", "dirb"}))
)


def _load_airecon_tool_names() -> frozenset[str]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools.json"
        data = json.loads(path.read_text(encoding="utf-8"))

        return frozenset(
            str(t["function"]["name"])
            for t in data
            if isinstance(t, dict) and isinstance(t.get("function"), dict) and t["function"].get("name")
        )
    except Exception as exc:
        logger.warning("Could not load tool names from tools.json: %s", exc)
        return frozenset()


_AIRECON_TOOL_NAMES: frozenset[str] = (
    _load_airecon_tool_names() - {"execute"}
)


def _load_tool_flag_conflicts() -> dict[str, tuple[list[str], str]]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        raw = data.get("tool_flag_conflicts", {})
        return {
            tool: (entry["flags"], entry["correct_tool"])
            for tool, entry in raw.items()
            if isinstance(entry.get("flags"), list) and entry.get("correct_tool")
        }
    except Exception as exc:
        logger.warning(
            "Could not load tool_flag_conflicts from tools_meta.json: %s — "
            "flag conflict detection disabled. Check that data/tools_meta.json exists.",
            exc,
        )
        return {}


_TOOL_FLAG_CONFLICTS: dict[str, tuple[list[str], str]] = _load_tool_flag_conflicts()

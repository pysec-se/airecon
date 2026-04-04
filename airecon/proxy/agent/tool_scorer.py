from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.tool_scorer")

# ── Load tool metadata ──────────────────────────────────────────────────────
_TOOLS_META_PATH = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    _TOOLS_META = json.loads(_TOOLS_META_PATH.read_text(encoding="utf-8"))
except Exception as _e:
    logger.warning("tools_meta.json unavailable: %s", _e)
    _TOOLS_META = {}

_CATEGORY_PHASE_MAP: dict[str, list[str]] = {
    "RECON": [
        "subdomain_enum", "port_scan", "web_probing", "fingerprinting",
        "parameter_discovery", "crawling", "live_host_probe",
        "directory_bruteforce", "extraction",
    ],
    "ANALYSIS": [
        "generic_scanners", "cms_scanners", "fuzzing",
        "specific_vulnerabilities", "evasion_and_waf",
        "analysis", "code_analysis", "secrets_scanning",
    ],
    "EXPLOIT": [
        "web", "network_pivoting", "ad_smb", "bruteforce",
        "priv_esc", "advanced_injection",
        "cloud_enum", "cloud_exploitation",
    ],
    "REPORT": [], 
}

_CORE_TOOLS = frozenset({
    "execute", "web_search", "browser_action",
    "create_file", "read_file", "list_files",
})

_PHASE_EXTRAS: dict[str, set[str]] = {
    "RECON": {
        "run_parallel_agents",
        "caido_set_scope", "caido_sitemap", "caido_list_requests",
    },
    "ANALYSIS": {
        "caido_list_requests", "caido_send_request", "caido_sitemap",
    },
    "EXPLOIT": {
        "quick_fuzz", "advanced_fuzz", "deep_fuzz",
        "spawn_agent", "schemathesis_fuzz",
        "caido_send_request", "caido_automate", "caido_list_requests",
        "caido_get_findings",
    },
    "REPORT": set(),
}

_REPORT_TOOLS = frozenset({
    "create_vulnerability_report", "create_file", "read_file", "list_files",
})


def _lookup_category(categories: dict, name: str) -> set[str]:
    """Look up a category by name across all sub-categories in tools_meta.json."""
    tools: set[str] = set()
    for group_name, subcats in categories.items():
        if not isinstance(subcats, dict):
            continue
        for subcat_name, tool_list in subcats.items():
            if subcat_name == name and isinstance(tool_list, list):
                tools.update(t for t in tool_list if isinstance(t, str))
    return tools


def _collect_all_known_tools() -> set[str]:
    """Collect ALL tool names from tools_meta.json categories."""
    all_tools: set[str] = set()
    categories = _TOOLS_META.get("categories", {})
    if isinstance(categories, dict):
        for group in categories.values():
            if isinstance(group, dict):
                for tool_list in group.values():
                    if isinstance(tool_list, list):
                        all_tools.update(t for t in tool_list if isinstance(t, str))
    return all_tools


def _build_phase_appropriate() -> dict[str, set[str]]:
    """Build phase→appropriate-tools dynamically. No hardcoded tool names."""
    phase_tools: dict[str, set[str]] = {
        "RECON": set(_CORE_TOOLS),
        "ANALYSIS": set(_CORE_TOOLS),
        "EXPLOIT": set(_CORE_TOOLS),
        "REPORT": set(_REPORT_TOOLS),
    }

    for phase, extras in _PHASE_EXTRAS.items():
        phase_tools[phase].update(extras)

    categories = _TOOLS_META.get("categories", {})
    if isinstance(categories, dict):
        for phase, cat_names in _CATEGORY_PHASE_MAP.items():
            for cat_name in cat_names:
                phase_tools[phase].update(_lookup_category(categories, cat_name))

    return phase_tools


def _build_phase_blocked() -> dict[str, set[str]]:

    all_phase_tools = _build_phase_appropriate()
    all_known = _collect_all_known_tools()

    report_block = (all_known | _CORE_TOOLS) - _REPORT_TOOLS

    blocked: dict[str, set[str]] = {
        "RECON": set(),
        "ANALYSIS": set(),
        "EXPLOIT": set(),
        "REPORT": report_block,
    }

    phases = ["RECON", "ANALYSIS", "EXPLOIT"]
    for phase in phases:
        for other_phase in phases:
            if other_phase == phase:
                continue
            other_only = all_phase_tools[other_phase] - all_phase_tools[phase] - _CORE_TOOLS
            blocked[phase].update(other_only)

    return blocked


_PHASE_APPROPRIATE_TOOLS: dict[str, set[str]] = _build_phase_appropriate()
_PHASE_BLOCKED_TOOLS: dict[str, set[str]] = _build_phase_blocked()
_KNOWN_TOOL_BINARIES: set[str] = _collect_all_known_tools()


def extract_binary_from_command(command: str) -> str:
    """Extract the primary binary/tool name from a shell command."""
    if not command:
        return ""
    cmd = re.sub(r"^cd\s+\S+\s*&&\s*", "", command).strip()
    if not cmd:
        return ""
    binary = cmd.split()[0].lower() if cmd.split() else ""
    binary = binary.rsplit("/", 1)[-1]
    _shell_builtins = {"cd", "echo", "export", "source", ".", "for", "while", "if",
                       "then", "fi", "done", "do", "case", "esac", "true", "false"}
    if binary in _shell_builtins:
        for token in cmd.split():
            t = token.rsplit("/", 1)[-1].lower()
            if t in _KNOWN_TOOL_BINARIES:
                return t
        return ""
    return binary


def _get_memory_tool_stats() -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    """Get tool success/failure counts from cross-session memory."""
    success_counts: dict[str, int] = {}
    failure_counts: dict[str, int] = {}
    use_counts: dict[str, int] = {}

    try:
        from ..memory import get_memory_manager
        memory = get_memory_manager()
        stats = memory.get_tool_statistics()

        if isinstance(stats, list):
            for s in stats:
                tool = s.get("tool_name", "")
                if tool:
                    success_counts[tool] = s.get("success_count", 0)
                    failure_counts[tool] = s.get("failure_count", 0)
                    use_counts[tool] = success_counts[tool] + failure_counts[tool]
        elif isinstance(stats, dict):
            tool = stats.get("tool_name", "")
            if tool:
                success_counts[tool] = stats.get("success_count", 0)
                failure_counts[tool] = stats.get("failure_count", 0)
                use_counts[tool] = success_counts[tool] + failure_counts[tool]
    except Exception as _e:
        logger.debug("Could not load memory tool stats: %s", _e)

    return success_counts, failure_counts, use_counts


def score_tool(
    tool_name: str,
    *,
    current_phase: str = "RECON",
    tool_use_counts: dict[str, int] | None = None,
    tool_success_counts: dict[str, int] | None = None,
    tool_failure_counts: dict[str, int] | None = None,
    budget_remaining: dict[str, int] | None = None,
    chain_step_hint: str = "",
    session_evidence_count: int = 0,
    consecutive_failures: int = 0,
) -> dict[str, Any]:
    """Score a single tool for relevance."""
    reasons: list[str] = []
    score = 0.5

    phase_upper = current_phase.upper()
    appropriate_tools = _PHASE_APPROPRIATE_TOOLS.get(phase_upper, set())
    blocked_tools = _PHASE_BLOCKED_TOOLS.get(phase_upper, set())

    is_blocked = tool_name.lower() in {t.lower() for t in blocked_tools}
    is_appropriate = tool_name.lower() in {t.lower() for t in appropriate_tools}

    if is_blocked:
        score = 0.0
        reasons.append(f"BLOCKED: '{tool_name}' is not appropriate for {phase_upper} phase")
        return {
            "score": 0.0,
            "phase_appropriate": False,
            "phase_blocked": True,
            "reasons": reasons,
        }

    if is_appropriate:
        score += 0.15
        reasons.append(f"Phase-appropriate for {phase_upper}")

    if tool_success_counts and tool_failure_counts:
        successes = tool_success_counts.get(tool_name, 0)
        failures = tool_failure_counts.get(tool_name, 0)
        total = successes + failures
        if total >= 2:
            success_rate = successes / total
            if success_rate >= 0.8:
                score += 0.15
                reasons.append(f"High historical success rate ({success_rate:.0%})")
            elif success_rate >= 0.6:
                score += 0.05
                reasons.append(f"Moderate historical success rate ({success_rate:.0%})")
            elif success_rate < 0.4:
                score -= 0.15
                reasons.append(f"Low historical success rate ({success_rate:.0%}) — consider alternatives")

    if tool_use_counts:
        use_count = tool_use_counts.get(tool_name, 0)
        if use_count > 10:
            score -= 0.1
            reasons.append(f"Overused in this session ({use_count} times) — diversify")
        elif use_count == 0 and is_appropriate:
            score += 0.05
            reasons.append("Not yet used this session — worth trying")

    if budget_remaining:
        remaining = budget_remaining.get(tool_name, 999)
        if remaining <= 0:
            score -= 0.3
            reasons.append("Tool budget exhausted (0 remaining) — use sparingly")
        elif remaining <= 3:
            score -= 0.1
            reasons.append(f"Tool budget low ({remaining} remaining)")

    if chain_step_hint:
        chain_hint_lower = chain_step_hint.lower()
        tool_lower = tool_name.lower()
        if tool_lower in chain_hint_lower or chain_hint_lower in tool_lower:
            score += 0.25
            reasons.append(f"ALIGNMENT: Matches current exploit chain step hint '{chain_step_hint}'")

    if consecutive_failures >= 3:
        if tool_use_counts and tool_name in tool_use_counts:
            if tool_use_counts.get(tool_name, 0) > 0:
                score -= 0.1
                reasons.append("Consecutive failures — try a different approach")

    score = max(0.0, min(1.0, score))

    return {
        "score": round(score, 3),
        "phase_appropriate": is_appropriate,
        "phase_blocked": is_blocked,
        "reasons": reasons,
    }


def rank_tools_for_phase(
    available_tools: list[dict[str, Any]],
    *,
    current_phase: str = "RECON",
    tool_use_counts: dict[str, int] | None = None,
    tool_success_counts: dict[str, int] | None = None,
    tool_failure_counts: dict[str, int] | None = None,
    budget_remaining: dict[str, int] | None = None,
    chain_step_hint: str = "",
    session_evidence_count: int = 0,
    consecutive_failures: int = 0,
    top_n: int | None = None,
    use_memory: bool = True,
) -> list[dict[str, Any]]:
    """Score and rank all available tools for the current phase.

    Phase-blocked tools are removed entirely.
    Auto-loads cross-session memory if enabled.
    """
    if use_memory and tool_success_counts is None and tool_failure_counts is None:
        mem_success, mem_failure, mem_use = _get_memory_tool_stats()
        if tool_success_counts is None:
            tool_success_counts = mem_success
        if tool_failure_counts is None:
            tool_failure_counts = mem_failure
        if tool_use_counts is None:
            tool_use_counts = mem_use

    scored_tools: list[tuple[float, dict[str, Any]]] = []

    for tool_def in available_tools:
        tool_name = tool_def.get("function", {}).get("name", "") or tool_def.get("name", "")
        if not tool_name:
            continue

        result = score_tool(
            tool_name,
            current_phase=current_phase,
            tool_use_counts=tool_use_counts,
            tool_success_counts=tool_success_counts,
            tool_failure_counts=tool_failure_counts,
            budget_remaining=budget_remaining,
            chain_step_hint=chain_step_hint,
            session_evidence_count=session_evidence_count,
            consecutive_failures=consecutive_failures,
        )

        if result["phase_blocked"]:
            logger.debug("Tool '%s' phase-blocked for %s — removing from tool list",
                         tool_name, current_phase)
            continue

        scored_tools.append((result["score"], tool_def))

    scored_tools.sort(key=lambda x: x[0], reverse=True)

    if top_n and len(scored_tools) > top_n:
        scored_tools = scored_tools[:top_n]

    return [tool_def for _, tool_def in scored_tools]


def build_tool_recommendation_context(
    current_phase: str = "RECON",
    tool_scores: dict[str, dict[str, Any]] | None = None,
    chain_step_hint: str = "",
    consecutive_failures: int = 0,
    blocked_tools: list[str] | None = None,
    wrong_tool_picked: str = "",
) -> str:
    """Build a context string to inject into the conversation."""
    parts: list[str] = []

    phase_upper = current_phase.upper()
    appropriate = _PHASE_APPROPRIATE_TOOLS.get(phase_upper, set())
    if appropriate:
        top_tools = sorted(appropriate)[:15]
        parts.append(
            f'<tool_guidance phase="{phase_upper}">\n'
            f"  Recommended tools for this phase: {', '.join(top_tools)}\n"
            f"  Prioritize tools that advance your current objective.\n"
            f"</tool_guidance>"
        )

    blocked = _PHASE_BLOCKED_TOOLS.get(phase_upper, set())
    if blocked:
        top_blocked = sorted(blocked)[:10]
        parts.append(
            f"<blocked_tools>\n"
            f"  DO NOT use these tools in {phase_upper} phase: {', '.join(top_blocked)}\n"
            f"  Using them will be rejected.\n"
            f"</blocked_tools>"
        )

    if chain_step_hint:
        if wrong_tool_picked:
            parts.append(
                f"<exploit_chain_correction>\n"
                f"  ⚠️ WRONG TOOL SELECTED: You used '{wrong_tool_picked}' but your exploit chain requires '{chain_step_hint}'.\n"
                f"  STOP what you're doing. Use '{chain_step_hint}' NOW to advance the chain.\n"
                f"  The current chain step is waiting for this specific tool.\n"
                f"</exploit_chain_correction>"
            )
        else:
            parts.append(
                f"<exploit_chain_guidance>\n"
                f"  Your exploit chain's current step suggests using: '{chain_step_hint}'\n"
                f"  PRIORITIZE this tool to advance the chain.\n"
                f"</exploit_chain_guidance>"
            )

    if consecutive_failures >= 3:
        parts.append(
            f"<failure_recovery>\n"
            f"  ⚠️ {consecutive_failures} consecutive tool failures detected!\n"
            f"  STOP using the same approach. Switch to a completely different tool or strategy.\n"
            f"  Check tools_meta.json for alternative suggestions.\n"
            f"</failure_recovery>"
        )

    if not parts:
        return ""

    return "\n\n".join(["<system_tool_intelligence>"] + parts + ["</system_tool_intelligence>"])

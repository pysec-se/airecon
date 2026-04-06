from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.tool_scorer")

# ── Load tool metadata ──────────────────────────────────────────────────────
_TOOLS_META_PATH = Path(__file__).parent.parent / "data" / "tools_meta.json"
_TOOLS_JSON_PATH = Path(__file__).parent.parent / "data" / "tools.json"
try:
    _TOOLS_META = json.loads(_TOOLS_META_PATH.read_text(encoding="utf-8"))
except Exception as _e:
    logger.warning("tools_meta.json unavailable: %s", _e)
    _TOOLS_META = {}


# ── Derive core tools from tools.json (agent-level tools always available) ──
def _derive_core_tools() -> frozenset[str]:
    """Core tools = tools that are NOT categorized in tools_meta.json subcategories.
    These are agent-level tools (execute, browser_action, create_file, etc.)
    loaded dynamically from tools.json."""
    core: set[str] = set()
    try:
        tools_path = _TOOLS_JSON_PATH
        if tools_path.exists():
            tools_list = json.loads(tools_path.read_text(encoding="utf-8"))
            for tool_def in tools_list:
                name = tool_def.get("function", {}).get("name", "")
                if name:
                    core.add(name)
    except Exception as exc:
        logger.debug("Operation failed: %s", exc)
    # Remove tools that belong to specific categories in tools_meta.json
    categories = _TOOLS_META.get("categories", {})
    categorized: set[str] = set()
    for group in categories.values():
        if isinstance(group, dict):
            for tool_list in group.values():
                if isinstance(tool_list, list):
                    categorized.update(tool_list)
    # Core = tools.json tools MINUS categorized tools from tools_meta.json
    core_tools = core - categorized
    # Always include these agent-level tools
    core_tools |= {
        "execute",
        "browser_action",
        "web_search",
        "create_file",
        "read_file",
        "list_files",
    }
    return frozenset(core_tools)


_CORE_TOOLS = _derive_core_tools()

_CATEGORY_PHASE_MAP: dict[str, list[str]] = _TOOLS_META.get("phase_category_map", {})

_PHASE_EXTRAS: dict[str, set[str]] = {
    phase: set(tools) for phase, tools in _TOOLS_META.get("phase_extras", {}).items()
}

_REPORT_TOOLS = frozenset(_TOOLS_META.get("report_tools", []))


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
            other_only = (
                all_phase_tools[other_phase] - all_phase_tools[phase] - _CORE_TOOLS
            )
            blocked[phase].update(other_only)

    return blocked


_PHASE_APPROPRIATE_TOOLS: dict[str, set[str]] = _build_phase_appropriate()
_PHASE_BLOCKED_TOOLS: dict[str, set[str]] = _build_phase_blocked()
_KNOWN_TOOL_BINARIES: set[str] = _collect_all_known_tools()


# Shell binary descriptions sourced from tools_meta.json["tool_descriptions"]
# No hardcoded descriptions in Python code — all maintained in JSON.

# Map phases to relevant shell binary subcategory names from tools_meta.json
_PHASE_SHELL_CATEGORIES = {
    "RECON": {
        "subdomain_enum", "port_scan", "web_probing", "fingerprinting",
        "crawling", "live_host_probe", "directory_bruteforce",
        "parameter_discovery", "extraction",
    },
    "ANALYSIS": {
        "generic_scanners", "cms_scanners", "fuzzing",
        "specific_vulnerabilities", "evasion_and_waf",
        "analysis", "code_analysis",
    },
    "EXPLOIT": {
        "specific_vulnerabilities", "advanced_injection", "evasion_and_waf",
        "network_pivoting", "networking", "bruteforce",
        "priv_esc", "cloud_exploitation",
    },
    "REPORT": set(),
}


def _collect_shell_binary_descriptions() -> dict[str, str]:
    """Return mapping of shell binary name → description from tools_meta.json."""
    descriptions = _TOOLS_META.get("tool_descriptions", {})
    if not isinstance(descriptions, dict):
        descriptions = {}
    return descriptions


def _match_shells_for_phase(phase: str) -> set[str]:
    """Return shell binaries relevant for the given phase."""
    cats = _PHASE_SHELL_CATEGORIES.get(phase, set())
    if not cats:
        return set()

    result: set[str] = set()
    categories = _TOOLS_META.get("categories", {})
    for cat_name in cats:
        for group in categories.values():
            if isinstance(group, dict) and cat_name in group:
                tlist = group[cat_name]
                if isinstance(tlist, list):
                    result.update(t for t in tlist if isinstance(t, str))
    return result


def extract_binary_from_command(command: str) -> str:
    """Extract the primary binary/tool name from a shell command."""
    if not command:
        return ""
    cmd = re.sub(r"^cd\s+\S+\s*&&\s*", "", command).strip()
    if not cmd:
        return ""
    binary = cmd.split()[0].lower() if cmd.split() else ""
    binary = binary.rsplit("/", 1)[-1]
    _shell_builtins = {
        "cd",
        "echo",
        "export",
        "source",
        ".",
        "for",
        "while",
        "if",
        "then",
        "fi",
        "done",
        "do",
        "case",
        "esac",
        "true",
        "false",
    }
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
        reasons.append(
            f"BLOCKED: '{tool_name}' is not appropriate for {phase_upper} phase"
        )
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
                reasons.append(
                    f"Low historical success rate ({success_rate:.0%}) — consider alternatives"
                )

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
            reasons.append(
                f"ALIGNMENT: Matches current exploit chain step hint '{chain_step_hint}'"
            )

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
        tool_name = tool_def.get("function", {}).get("name", "") or tool_def.get(
            "name", ""
        )
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
            logger.debug(
                "Tool '%s' phase-blocked for %s — removing from tool list",
                tool_name,
                current_phase,
            )
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
    tool_registry: list[dict[str, Any]] | None = None,
) -> str:
    """Build a context string to inject into the conversation.

    Now includes tool descriptions so the agent is NOT blind.
    """
    parts: list[str] = []

    phase_upper = current_phase.upper()
    appropriate = _PHASE_APPROPRIATE_TOOLS.get(phase_upper, set())
    if appropriate:
        top_tools = sorted(appropriate)[:15]

        # Build a named→description lookup from the tool registry
        desc_map: dict[str, str] = {}
        if tool_registry:
            for tdef in tool_registry:
                fn = tdef.get("function", {}) if isinstance(tdef, dict) else {}
                tname = fn.get("name", "")
                tdesc = fn.get("description", "")
                if tname and tdesc:
                    desc_map[tname.lower()] = tdesc

        # Also pull shell binary descriptions from tools_meta.json
        categories = _TOOLS_META.get("categories", {})
        for cat in categories.values():
            if isinstance(cat, dict):
                for subcat, tlist in cat.items():
                    if isinstance(tlist, list):
                        # subcategory name acts as a keyword for the binary
                        pass

        tool_lines: list[str] = []
        for tname in top_tools:
            tl = tname.lower()
            desc = desc_map.get(tl, "")
            if desc:
                # Truncate long descriptions
                if len(desc) > 200:
                    desc = desc[:197] + "..."
                tool_lines.append(f"    - {tname}: {desc}")
            else:
                tool_lines.append(f"    - {tname}")

        # Add known shell binaries accessible via execute()
        shell_binaries = _collect_shell_binary_descriptions()
        relevant_shells = _match_shells_for_phase(phase_upper)
        if relevant_shells:
            shell_lines: list[str] = []
            for shell_name in sorted(relevant_shells)[:25]:
                desc = shell_binaries.get(shell_name, "")
                if desc:
                    shell_lines.append(f"    - {shell_name}: {desc}")
                    desc_len = len(shell_name) + len(desc)
                    if desc_len > 150:
                        break
                else:
                    shell_lines.append(f"    - {shell_name}")
                if len(shell_lines) >= 25:
                    break
            tool_lines.append("")
            tool_lines.append("  You can ALSO run these via execute(command='...'):")
            tool_lines.extend(shell_lines)

        parts.append(
            '<tool_guidance phase="' + phase_upper + '">\n'
            '  Recommended tools for this phase (with descriptions):\n'
            + "\n".join(tool_lines)
            + "\n  Prioritize tools that advance your current objective.\n"
            "</tool_guidance>"
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

    # Skills catalog index — tell agent about available knowledge
    _skills = _TOOLS_META.get("skills_catalog", {})
    if isinstance(_skills, dict):
        phase_skills: dict[str, set[str]] = {
            "RECON": {"subdomain_enum", "full_recon", "dorking", "asn_whois_osint"},
            "ANALYSIS": {"javascript_analysis", "waf_detection", "cors", "idor"},
            "EXPLOIT": {
                "xss", "sql_injection", "ssrf", "lfi", "ssti", "command_injection",
                "xxe", "deserialization", "auth_workflow", "business_logic",
            },
            "REPORT": {"information_disclosure", "web_cache_poisoning"},
        }
        relevant_skill_names = phase_skills.get(phase_upper, set())
        # Auto-derive relevant tool↔skill cross-links from catalog itself
        _skill_tool_names: set[str] = {
            sname.lower()
            for sub in _skills.values()
            if isinstance(sub, dict)
            for sname in sub.keys()
        } & _KNOWN_TOOL_BINARIES

        skill_entries: list[str] = []
        for cat, skills in _skills.items():
            if isinstance(skills, dict):
                for sname, sdesc in skills.items():
                    if sname in relevant_skill_names:
                        skill_entries.append(f"    - skills/{cat}/{sname}.md: {sdesc[:180]}")
                    # Match if skill name is also a known tool/binary
                    if sname.lower() in _skill_tool_names and sname not in relevant_skill_names:
                        skill_entries.append(f"    - skills/{cat}/{sname}.md: {sdesc[:180]}")
        if skill_entries:
            # Deduplicate
            seen = set()
            unique_skills = []
            for line in skill_entries:
                if line not in seen:
                    seen.add(line)
                    unique_skills.append(line)
            parts.append(
                '<skills_catalog>\n'
                '  Available knowledge modules. Load with read_file(path="skills/<cat>/<name>.md"):\n'
                + "\n".join(unique_skills)
                + "\n  Use these modules to guide your approach and avoid common pitfalls.\n"
                "</skills_catalog>"
            )

    if not parts:
        return ""

    return "\n\n".join(
        ["<system_tool_intelligence>"] + parts + ["</system_tool_intelligence>"]
    )

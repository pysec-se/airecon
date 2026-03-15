"""System prompt for the AIRecon security agent."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .config import get_config

with open(Path(__file__).parent / "prompts" / "system.txt", "r") as f:
    SYSTEM_PROMPT = f.read()

_CTF_PROMPT_PATH = Path(__file__).parent / "prompts" / "system_ctf.txt"
with open(_CTF_PROMPT_PATH, "r") as f:
    CTF_SYSTEM_PROMPT = f.read()

_BUGBOUNTY_PROMPT_PATH = Path(__file__).parent / "prompts" / "bugbounty.txt"
with open(_BUGBOUNTY_PROMPT_PATH, "r") as f:
    BUGBOUNTY_SYSTEM_PROMPT = f.read()

_PENTEST_PROMPT_PATH = Path(__file__).parent / \
    "prompts" / "penetration_test.txt"
with open(_PENTEST_PROMPT_PATH, "r") as f:
    PENTEST_SYSTEM_PROMPT = f.read()


# ------------------------------------------------------------------
# CTF target detection
# ------------------------------------------------------------------
_CTF_INDICATORS_TARGET = (
    "localhost",
    "127.0.0.1",
    "::1",
)
_PRIVATE_IP_RE = re.compile(
    r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+):\d+\b"
)

# Whole-word regex for CTF message detection.
# Using \b boundaries prevents false positives from common security terms:
#   "flag"      → would match "feature flags", "--flag param", "red flags"
#   "challenge" → would match "challenging", "challenged"
#   "benchmark" → would match "benchmark" only (safe as whole word)
# "flag" is intentionally dropped — "flag{" (CTF flag format) is kept instead.
# Only explicit, unambiguous CTF-specific terms are matched.
_CTF_MSG_RE = re.compile(
    r"(?:"
    r"\bctf\b"
    r"|flag\{"            # CTF flag format: flag{...} — no false positives
    r"|\bcapture the flag\b"
    r"|\bxbow\b"
    r"|\bhacksim\b"
    r"|\bhtb\b"           # HackTheBox shorthand
    r"|\bpicoctf\b"
    r"|\broot\.txt\b"     # common CTF objective
    r"|\buser\.txt\b"     # common CTF objective (HackTheBox)
    r")",
    re.IGNORECASE,
)


def _is_ctf_target(target: str | None = None,
                   user_message: str | None = None) -> bool:
    """Return True when the engagement looks like a CTF/XBOW/benchmark challenge.

    Heuristics (any one match = CTF mode):
    - Target string contains localhost / 127.0.0.1 / ::1
    - Target matches private-IP:PORT pattern (single exposed service)
    - User message contains unambiguous CTF-specific keywords (whole-word match)

    NOTE: "challenge", "benchmark", and bare "flag" are intentionally excluded
    from message detection to prevent false positives during normal recon
    (e.g. "challenging target", "run a benchmark", "feature flags").
    """
    if target:
        t_lower = target.lower()
        if any(ind in t_lower for ind in _CTF_INDICATORS_TARGET):
            return True
        # Private IP with explicit port ⇒ single-service CTF style
        if _PRIVATE_IP_RE.search(target):
            return True
    if user_message and _CTF_MSG_RE.search(user_message):
        return True
    return False


# ------------------------------------------------------------------
# Bug Bounty detection
# ------------------------------------------------------------------
_BUGBOUNTY_INDICATORS_MSG = (
    "bug bounty",
    "bugbounty",
    "bounty",
    "hackerone",
    "bugcrowd",
    "intigriti",
    "public domain",
    "external assessment",
)
_PUBLIC_DOMAIN_RE = re.compile(
    r"\b([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(com|net|org|io|co|app|dev|ai|xyz|tech|gov|edu)\b",
    re.IGNORECASE,
)


def _is_bugbounty_target(target: str | None = None,
                         user_message: str | None = None) -> bool:
    """Return True when the engagement looks like a bug bounty / external assessment."""
    if user_message:
        m_lower = user_message.lower()
        if any(ind in m_lower for ind in _BUGBOUNTY_INDICATORS_MSG):
            return True
    if target:
        t_lower = target.lower()
        # Has subdomains or is a public TLD domain without port-only style
        if _PUBLIC_DOMAIN_RE.search(t_lower) and ":" not in t_lower:
            return True
        if any(ind in t_lower for ind in _BUGBOUNTY_INDICATORS_MSG):
            return True
    return False


# ------------------------------------------------------------------
# Pentest detection (local network / cloud)
# ------------------------------------------------------------------
_PENTEST_INDICATORS_MSG = (
    "pentest",
    "penetration test",
    "internal",
    "local pentest",
    "network pentest",
    "cloud pentest",
    "aws",
    "gcp",
    "azure",
    "cloud",
    "s3 bucket",
    "ec2",
    "lambda",
    "iam",
    "smb",
    "lateral movement",
)
_PENTEST_TARGET_RE = re.compile(
    r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"
)


def _is_pentest_target(target: str | None = None,
                       user_message: str | None = None) -> bool:
    """Return True when the engagement is a local network or cloud pentest."""
    if target:
        t_lower = target.lower()
        # Private IP without explicit port = internal network (not single CTF
        # service)
        if _PENTEST_TARGET_RE.search(
                t_lower) and not _PRIVATE_IP_RE.search(t_lower):
            return True
        if any(ind in t_lower for ind in ("aws", "gcp", "azure", "cloud")):
            return True
    if user_message:
        m_lower = user_message.lower()
        if any(ind in m_lower for ind in _PENTEST_INDICATORS_MSG):
            return True
    return False


# ------------------------------------------------------------------
# Skills loaders
# ------------------------------------------------------------------
# Heavy skills embedded in the full prompt context.
# NOT used in CTF mode to save ~85-100K tokens.
# Keys are relative paths from the skills/ directory (subdir/filename.md)
# so same-named files in different subdirectories don't collide.
_FULL_EMBED_SKILLS = {
    "tools/install.md",
    "tools/scripting.md",
    "tools/tool_catalog.md",
    "reconnaissance/full_recon.md",
    "tools/browser_automation.md",
    "tools/nuclei.md",
    "tools/sqlmap.md",
    "tools/dalfox.md",
    "tools/nmap.md",
    "tools/semgrep.md",
}

# Minimal set embedded for CTF mode (only what's needed for local exploitation)
_CTF_EMBED_SKILLS = {
    "tools/install.md",
}


def _load_local_skills(ctf_mode: bool = False) -> str:
    """Load local skills from airecon/proxy/skills/*.md and append to prompt.

    In ctf_mode, only the minimal install.md is embedded to avoid context
    explosion. All other skills remain available via read_file.
    Skills are listed as read_file references. The SOP and tool catalog will
    be auto-loaded via auto_load_skills_for_message() when triggered by keywords.
    """
    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return ""

    embed_set = _CTF_EMBED_SKILLS if ctf_mode else _FULL_EMBED_SKILLS

    embedded_parts: list[str] = []
    reference_parts: list[str] = []

    for path in sorted(skills_dir.rglob("*.md")):
        rel = path.relative_to(skills_dir).as_posix()
        if rel in embed_set:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                embedded_parts.append(
                    f'\n<embedded_skill name="{path.name}">\n{content}\n</embedded_skill>\n'
                )
            except Exception:
                reference_parts.append(f"- {path.absolute().as_posix()}")
        else:
            reference_parts.append(f"- {path.absolute().as_posix()}")

    result = ""

    if embedded_parts:
        result += (
            "\n\n<core_skills>\n"
            "The following skill documents are pre-loaded for you. "
            "You do NOT need to read_file these — they are already available:\n"
            + "".join(embedded_parts)
            + "</core_skills>\n"
        )

    if reference_parts:
        result += (
            "\n\n<available_skills>\n"
            "Additional skill documents available via read_file. "
            "Load the relevant one when you need specialized guidance:\n"
            + "\n".join(reference_parts)
            + "\n</available_skills>\n"
        )

    return result


def _load_skill_keywords() -> dict[str, str]:
    """Load skill keywords from data/skills.json.

    Returns a mapping of keyword → skill file path.
    Falls back to empty dict if file not found.
    """
    try:
        skills_json = Path(__file__).parent / "data" / "skills.json"
        if skills_json.exists():
            with open(skills_json, "r") as f:
                data = json.load(f)
                return data.get("skill_keywords", {})
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to load skill keywords from JSON: {e}")
    return {}


def _keyword_matches_message(keyword: str, msg_lower: str) -> bool:
    """Return True when a skill keyword is present without broad substring noise.

    Uses word boundaries for alphanumeric edge keywords (e.g. `express`) to
    avoid false positives like `expression`. Falls back to literal matching for
    keywords with symbolic edges.
    """
    k = keyword.lower().strip()
    if not k:
        return False

    prefix = r"\b" if k[0].isalnum() else ""
    suffix = r"\b" if k[-1].isalnum() else ""
    pattern = prefix + re.escape(k) + suffix
    return re.search(pattern, msg_lower) is not None


# Keyword → skill file mapping for auto-loading (loaded from data/skills.json)
_SKILL_KEYWORDS: dict[str, str] = _load_skill_keywords()

# Phase → preferred skill subdirectories for phase-aware score boosting.
# Skills in a preferred directory receive +2 bonus on their keyword score,
# ensuring phase-appropriate skills rank higher. Only skills with at least
# 1 keyword hit are boosted (zero-hit skills are never injected).
_PHASE_SKILL_DIRECTORIES: dict[str, set[str]] = {
    "RECON":    {"reconnaissance", "tools", "protocols"},
    "ANALYSIS": {"vulnerabilities", "frameworks", "technologies", "protocols"},
    "EXPLOIT":  {"payloads", "vulnerabilities", "postexploit", "frameworks", "tools", "ctf"},
    "REPORT":   set(),
    "COMPLETE": set(),
}


def auto_load_skills_for_message(
    user_message: str, phase: str = ""
) -> tuple[str, list[str]]:
    """Auto-detect relevant skills from user message and return their content.

    Skills are ranked by keyword match count so the most relevant ones are
    always loaded first. Ties are broken alphabetically for stable ordering.
    Limit is 4 to avoid context explosion — always the top-4 most relevant.

    When `phase` is provided, skills in the preferred directories for that
    phase receive a +2 score bonus to promote phase-appropriate content.

    Returns a tuple of (skill_context_string, list_of_loaded_skill_names).
    """
    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return "", []

    msg_lower = user_message.lower()

    # Count how many keywords from the message map to each skill path.
    # More keyword hits = more relevant to this specific query.
    skill_scores: dict[str, int] = {}
    for keyword, skill_path in _SKILL_KEYWORDS.items():
        if _keyword_matches_message(keyword, msg_lower):
            skill_scores[skill_path] = skill_scores.get(skill_path, 0) + 1

    if not skill_scores:
        return "", []

    # Phase-aware boost: preferred-directory skills get +2 bonus.
    # Only applied if there are already keyword hits (no zero-score injection).
    if phase:
        preferred = _PHASE_SKILL_DIRECTORIES.get(phase.upper(), set())
        if preferred:
            for skill_path in list(skill_scores.keys()):
                skill_dir = skill_path.split("/")[0]
                if skill_dir in preferred:
                    skill_scores[skill_path] += 2

    # Sort by score descending, then alphabetically for stable tie-breaking.
    # This ensures the most relevant skills are always loaded — not random.
    sorted_skills = sorted(
        skill_scores.keys(),
        key=lambda s: (-skill_scores[s], s),
    )

    parts: list[str] = []
    loaded_names: list[str] = []
    for skill_rel in sorted_skills[:4]:
        skill_file = skills_dir / skill_rel
        if skill_file.exists():
            try:
                content = skill_file.read_text(
                    encoding="utf-8", errors="replace")
                # Tool reference docs and reconnaissance skills get a higher
                # budget
                limit = 20000 if (skill_rel.startswith(
                    "tools/") or skill_rel.startswith("reconnaissance/")) else 4000
                if len(content) > limit:
                    content = (
                        content[:limit]
                        + f"\n... (truncated at {limit} chars, use read_file for full content: {skill_file.absolute().as_posix()})"
                    )
                parts.append(f"[AUTO-LOADED SKILL: {skill_rel}]\n{content}")
                loaded_names.append(skill_file.stem)
            except Exception:  # nosec B110 - skill loading is best-effort
                pass

    if not parts:
        return "", []

    return (
        "[SYSTEM: RELEVANT SKILLS AUTO-LOADED based on your request]\n"
        + "\n---\n".join(parts),
        loaded_names
    )


def auto_load_skills_for_technologies(
    technologies: dict[str, str],
    already_loaded: set[str] | None = None,
) -> tuple[str, list[str]]:
    """Load skills for newly detected technologies in the session.

    Called after tool execution when `session.technologies` grows.
    Unlike `auto_load_skills_for_message` (keyword-based on text),
    this fires directly on technology names from fingerprinting tools
    (httpx -tech-detect, whatweb, nmap scripts, etc.).

    Deduplicates against `already_loaded` set (skill rel-paths already
    injected this session) to prevent re-injecting the same skill.

    Returns (skill_context_string, list_of_loaded_skill_names).
    """
    if not technologies:
        return "", []

    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return "", []

    if already_loaded is None:
        already_loaded = set()

    # Build a synthetic message from all technology names so we can reuse
    # the existing keyword matcher.  Join with spaces to allow word-boundary
    # matching on multi-word tech names like "spring boot".
    tech_message = " ".join(technologies.keys()).lower()

    skill_scores: dict[str, int] = {}
    for keyword, skill_path in _SKILL_KEYWORDS.items():
        if _keyword_matches_message(keyword, tech_message):
            skill_scores[skill_path] = skill_scores.get(skill_path, 0) + 1

    if not skill_scores:
        return "", []

    sorted_skills = sorted(
        skill_scores.keys(),
        key=lambda s: (-skill_scores[s], s),
    )

    parts: list[str] = []
    loaded_names: list[str] = []
    for skill_rel in sorted_skills[:3]:
        # Skip skills already injected this session (dedup by rel-path)
        if skill_rel in already_loaded:
            continue
        skill_file = skills_dir / skill_rel
        if skill_file.exists():
            try:
                content = skill_file.read_text(encoding="utf-8", errors="replace")
                limit = 20000 if skill_rel.startswith("technologies/") or skill_rel.startswith("frameworks/") else 4000
                if len(content) > limit:
                    content = content[:limit] + f"\n... (truncated, use read_file for full: {skill_file.absolute().as_posix()})"
                parts.append(f"[AUTO-LOADED TECH SKILL: {skill_rel}]\n{content}")
                loaded_names.append(skill_file.stem)
                already_loaded.add(skill_rel)
            except Exception:  # nosec B110
                pass

    if not parts:
        return "", []

    tech_names = ", ".join(list(technologies.keys())[:8])
    return (
        f"[SYSTEM: TECH-SPECIFIC SKILLS LOADED — detected: {tech_names}]\n"
        + "\n---\n".join(parts),
        loaded_names,
    )


def get_system_prompt(
    target: str | None = None,
    user_message: str | None = None,
) -> str:
    """Return the system prompt appropriate for the detected engagement type.

    Engagement detection priority (first match wins):
      1. CTF/XBOW/benchmark  → system_ctf.txt (compact, minimal skills)
      2. Bug Bounty           → bugbounty.txt + system.txt (full skills)
      3. Pentest (local/cloud)→ penetration_test.txt + system.txt (full skills)
      4. Default              → system.txt (full skills)
    """
    # Priority 1: CTF — lightest prompt, prevents context overload on local
    # models
    if _is_ctf_target(target, user_message):
        return CTF_SYSTEM_PROMPT + _load_local_skills(ctf_mode=True)

    cfg = get_config()
    base_prompt = SYSTEM_PROMPT

    # Destructive mode patch (applies to non-CTF engagements only)
    if cfg.allow_destructive_testing:
        base_prompt = base_prompt.replace(
            "You have FULL AUTHORIZATION for non-destructive penetration testing",
            "You have FULL AUTHORIZATION for UNRESTRICTED DESTRUCTIVE penetration testing",
        )
        safety_override = """
<safety_override>
WARNING: DESTRUCTIVE MODE ENABLED
- You are authorized to perform destructive actions in this session.
- Use maximum threads and deep recursion. Ignore polite rate limits.
- Zero false positives remain mandatory: never report without a working PoC.
  A crash is NOT a vulnerability unless you understand WHY and can reproduce it.
  Verification is MANDATORY. Hypothetical vulnerabilities are failures.
</safety_override>
"""
        base_prompt = base_prompt.replace(
            "<execution_guidelines>", safety_override + "\n<execution_guidelines>"
        )

    skills_block = _load_local_skills(ctf_mode=False)

    # Priority 2: Bug Bounty — prepend bugbounty.txt before base system prompt
    if _is_bugbounty_target(target, user_message):
        return BUGBOUNTY_SYSTEM_PROMPT + "\n\n" + base_prompt + skills_block

    # Priority 3: Pentest (local network / cloud) — prepend
    # penetration_test.txt
    if _is_pentest_target(target, user_message):
        return PENTEST_SYSTEM_PROMPT + "\n\n" + base_prompt + skills_block

    # Priority 4: Default — base system.txt only (e.g. unknown target type)
    return base_prompt + skills_block

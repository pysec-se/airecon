from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from .config import get_config

logger = logging.getLogger("airecon.system")

with open(Path(__file__).parent / "prompts" / "system.txt", "r") as f:
    SYSTEM_PROMPT = f.read()

_CTF_PROMPT_PATH = Path(__file__).parent / "prompts" / "system_ctf.txt"
with open(_CTF_PROMPT_PATH, "r") as f:
    CTF_SYSTEM_PROMPT = f.read()

_BUGBOUNTY_PROMPT_PATH = Path(__file__).parent / "prompts" / "bugbounty.txt"
with open(_BUGBOUNTY_PROMPT_PATH, "r") as f:
    BUGBOUNTY_SYSTEM_PROMPT = f.read()

_PENTEST_PROMPT_PATH = Path(__file__).parent / "prompts" / "penetration_test.txt"
with open(_PENTEST_PROMPT_PATH, "r") as f:
    PENTEST_SYSTEM_PROMPT = f.read()

_CTF_INDICATORS_TARGET = (
    "localhost",
    "127.0.0.1",
    "::1",
)
_PRIVATE_IP_RE = re.compile(
    r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+):\d+\b"
)

_CTF_MSG_RE = re.compile(
    r"(?:"
    r"\bctf\b"
    r"|flag\{"
    r"|\bcapture the flag\b"
    r"|\bxbow\b"
    r"|\bhacksim\b"
    r"|\bhtb\b"
    r"|\bpicoctf\b"
    r"|\broot\.txt\b"
    r"|\buser\.txt\b"
    r")",
    re.IGNORECASE,
)


def _is_ctf_target(target: str | None = None, user_message: str | None = None) -> bool:
    if target:
        t_lower = target.lower()
        if any(ind in t_lower for ind in _CTF_INDICATORS_TARGET):
            return True

        if _PRIVATE_IP_RE.search(target):
            return True
    if user_message and _CTF_MSG_RE.search(user_message):
        return True
    return False


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
_BUGBOUNTY_TARGET_HINTS = (
    "hackerone",
    "bugcrowd",
    "intigriti",
    "/security",
    "/security.txt",
    "/responsible-disclosure",
    "/vulnerability-disclosure",
    "/bug-bounty",
    "/bounty",
)
_PUBLIC_DOMAIN_RE = re.compile(
    r"\b([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(com|net|org|io|co|app|dev|ai|xyz|tech|gov|edu)\b",
    re.IGNORECASE,
)


def _is_bugbounty_target(
    target: str | None = None, user_message: str | None = None
) -> bool:
    msg_has_indicator = False
    target_has_indicator = False
    target_is_public_domain = False

    if user_message:
        m_lower = user_message.lower()
        msg_has_indicator = any(ind in m_lower for ind in _BUGBOUNTY_INDICATORS_MSG)

    if target:
        t_lower = target.lower()
        target_is_public_domain = bool(
            _PUBLIC_DOMAIN_RE.search(t_lower) and ":" not in t_lower
        )
        target_has_indicator = any(ind in t_lower for ind in _BUGBOUNTY_INDICATORS_MSG)
        if not target_has_indicator:
            target_has_indicator = any(
                hint in t_lower for hint in _BUGBOUNTY_TARGET_HINTS
            )

    if msg_has_indicator:
        return True

    if target_is_public_domain and target_has_indicator:
        return True

    if target_has_indicator:
        return True

    return False


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


def _is_pentest_target(
    target: str | None = None, user_message: str | None = None
) -> bool:
    if target:
        t_lower = target.lower()

        if _PENTEST_TARGET_RE.search(t_lower) and not _PRIVATE_IP_RE.search(t_lower):
            return True
        if any(ind in t_lower for ind in ("aws", "gcp", "azure", "cloud")):
            return True
    if user_message:
        m_lower = user_message.lower()
        if any(ind in m_lower for ind in _PENTEST_INDICATORS_MSG):
            return True
    return False


_FULL_EMBED_SKILLS = {
    "tools/install.md",
}

_CTF_EMBED_SKILLS = {
    "tools/install.md",
}


def _load_local_skills(ctf_mode: bool = False) -> str:
    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return ""

    embed_set = _CTF_EMBED_SKILLS if ctf_mode else _FULL_EMBED_SKILLS

    embedded_parts: list[str] = []
    category_counts: dict[str, int] = {}

    for path in sorted(skills_dir.rglob("*.md")):
        rel = path.relative_to(skills_dir).as_posix()
        if rel in embed_set:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                embedded_parts.append(
                    f'\n<embedded_skill name="{path.name}">\n{content}\n</embedded_skill>\n'
                )
            except Exception:
                top = rel.split("/", 1)[0]
                category_counts[top] = category_counts.get(top, 0) + 1
        else:
            top = rel.split("/", 1)[0]
            category_counts[top] = category_counts.get(top, 0) + 1

    result = ""

    if embedded_parts:
        result += (
            "\n\n<core_skills>\n"
            "The following skill documents are pre-loaded for you. "
            "You do NOT need to read_file these — they are already available:\n"
            + "".join(embedded_parts)
            + "</core_skills>\n"
        )

    if category_counts:
        total = sum(category_counts.values())
        cat_list = ", ".join(
            f"{k}({category_counts[k]})" for k in sorted(category_counts)
        )
        base_path = skills_dir.as_posix()
        result += (
            "\n\n<available_skills>\n"
            "Additional skills are available via read_file (not pre-loaded).\n"
            f"Skills base path: {base_path}\n"
            f"Categories ({total} total): {cat_list}\n"
            "Auto-load will inject relevant skills based on keywords in the request.\n"
            "If you need a specific one, call read_file with the full path.\n"
            f"Example: {base_path}/tools/<skill_name>.md\n"
            "</available_skills>\n"
        )

    return result


def _load_skill_keywords() -> dict[str, str]:
    try:
        skills_json = Path(__file__).parent / "data" / "skills.json"
        if skills_json.exists():
            with open(skills_json, "r") as f:
                data = json.load(f)
                return data.get("skill_keywords", {})
    except Exception as e:
        logger.warning("Failed to load skill keywords from JSON: %s", e)
    return {}


def _keyword_matches_message(keyword: str, msg_lower: str) -> bool:
    k = keyword.lower().strip()
    if not k:
        return False

    prefix = r"\b" if k[0].isalnum() else ""
    suffix = r"\b" if k[-1].isalnum() else ""
    pattern = prefix + re.escape(k) + suffix
    return re.search(pattern, msg_lower) is not None


_SKILL_KEYWORDS: dict[str, str] = _load_skill_keywords()

_PHASE_SKILL_DIRECTORIES: dict[str, set[str]] = {
    "RECON": {"reconnaissance", "tools", "protocols"},
    "ANALYSIS": {"vulnerabilities", "frameworks", "technologies", "protocols"},
    "EXPLOIT": {
        "payloads",
        "vulnerabilities",
        "postexploit",
        "frameworks",
        "tools",
        "ctf",
    },
    "REPORT": set(),
    "COMPLETE": set(),
}

_PHASE_ENTRY_SKILLS: dict[str, list[str]] = {
    "RECON": [
        "reconnaissance/dorking.md",
        "tools/tool_catalog.md",
    ],
    "ANALYSIS": [
        "tools/semgrep.md",
        "vulnerabilities/api_testing.md",
    ],
    "EXPLOIT": [
        "tools/advanced_fuzzing.md",
        "vulnerabilities/exploitation.md",
    ],
    "REPORT": [],
}


def auto_load_skills_for_message(
    user_message: str,
    phase: str = "",
    session_loaded_skills: set[str] | None = None,
    memory_manager=None,
    current_target: str = "",
) -> tuple[str, list[str]]:
    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return "", []

    msg_lower = user_message.lower()

    skill_scores: dict[str, int] = {}
    for keyword, skill_path in _SKILL_KEYWORDS.items():
        if _keyword_matches_message(keyword, msg_lower):
            skill_scores[skill_path] = skill_scores.get(skill_path, 0) + 1

    if phase:
        preferred = _PHASE_SKILL_DIRECTORIES.get(phase.upper(), set())
        if preferred:
            for skill_path in list(skill_scores.keys()):
                skill_dir = skill_path.split("/")[0]
                if skill_dir in preferred:
                    skill_scores[skill_path] += 2

    sorted_skills = sorted(
        skill_scores.keys(),
        key=lambda s: (-skill_scores[s], s),
    )

    recommended_skills = []
    if memory_manager and current_target:
        try:
            skill_recs = memory_manager.get_skill_recommendations(current_target, phase)
            for rec in skill_recs:
                skill_path = (
                    f"ctf/{rec['skill_name']}.py"
                    if phase == "EXPLOIT"
                    else f"reconnaissance/{rec['skill_name']}.py"
                )
                skill_file = skills_dir / skill_path
                if skill_file.exists() and skill_path not in skill_scores:
                    skill_scores[skill_path] = int(rec["success_rate"] * 5)
                    recommended_skills.append(skill_path)
            sorted_skills = sorted(
                skill_scores.keys(),
                key=lambda s: (-skill_scores[s], s),
            )
        except Exception as e:
            logger.debug("Skill recommendation lookup failed: %s", e)

    guaranteed = _PHASE_ENTRY_SKILLS.get(phase.upper(), []) if phase else []
    max_keyword_skills = 2

    parts: list[str] = []
    loaded_skills: list[str] = []
    loaded_paths: set[str] = set()

    def _load_skill(skill_rel: str, *, guaranteed_skill: bool = False) -> bool:
        if skill_rel in loaded_paths:
            return False

        if session_loaded_skills:
            _legacy_stem = Path(skill_rel).stem
            if (
                skill_rel in session_loaded_skills
                or _legacy_stem in session_loaded_skills
            ):
                logger.debug("Skill already loaded this session: %s", skill_rel)
                return False
        skill_file = skills_dir / skill_rel
        if not skill_file.exists():
            if guaranteed_skill:
                logger.warning(
                    "Phase-guaranteed skill path is invalid and was skipped: %s",
                    skill_rel,
                )
            return False
        try:
            content = skill_file.read_text(encoding="utf-8", errors="replace")

            limit = (
                5000
                if (
                    skill_rel.startswith("tools/")
                    or skill_rel.startswith("reconnaissance/")
                )
                else 1500
            )
            if len(content) > limit:
                content = (
                    content[:limit]
                    + f"\n... (truncated at {limit} chars, use read_file for"
                    f" full content: {skill_file.absolute().as_posix()})"
                )
            parts.append(f"[AUTO-LOADED SKILL: {skill_rel}]\n{content}")
            loaded_skills.append(skill_rel)
            loaded_paths.add(skill_rel)
            return True
        except Exception:
            return False

    for skill_rel in guaranteed:
        _load_skill(skill_rel, guaranteed_skill=True)

    keyword_count = 0
    for skill_rel in sorted_skills:
        if keyword_count >= max_keyword_skills:
            break
        if _load_skill(skill_rel):
            keyword_count += 1

    if not parts:
        return "", []

    total_chars = sum(len(p) for p in parts)
    logger.debug(
        "skill_injection_stats: phase=%s guaranteed=%d max_keywords=%d loaded=%d total_chars=%d",
        phase,
        len(guaranteed),
        max_keyword_skills,
        len(loaded_skills),
        total_chars,
    )

    return (
        "[SYSTEM: RELEVANT SKILLS AUTO-LOADED based on your request]\n"
        + "\n---\n".join(parts),
        loaded_skills,
    )


def auto_load_skills_for_technologies(
    technologies: dict[str, str],
    already_loaded: set[str] | None = None,
) -> tuple[str, list[str]]:
    if not technologies:
        return "", []

    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return "", []

    if already_loaded is None:
        already_loaded = set()

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

    def _tech_skill_budget(ctx_tokens: int) -> tuple[int, int, int]:
        ctx = max(4096, int(ctx_tokens or 0))
        if ctx >= 131072:
            return 22000, 7000, 66000
        if ctx >= 65536:
            return 18000, 6000, 54000
        if ctx >= 32768:
            return 14000, 4500, 42000
        if ctx >= 16384:
            return 11000, 3500, 30000
        return 9000, 3000, 22000

    try:
        cfg = get_config()
        tech_limit, generic_limit, total_limit = _tech_skill_budget(
            int(getattr(cfg, "ollama_num_ctx", 32768) or 32768)
        )
    except Exception:
        tech_limit, generic_limit, total_limit = _tech_skill_budget(32768)

    parts: list[str] = []
    loaded_names: list[str] = []
    used_chars = 0
    for skill_rel in sorted_skills[:3]:
        if skill_rel in already_loaded:
            continue
        skill_file = skills_dir / skill_rel
        if skill_file.exists():
            try:
                content = skill_file.read_text(encoding="utf-8", errors="replace")
                limit = (
                    tech_limit
                    if (
                        skill_rel.startswith("technologies/")
                        or skill_rel.startswith("frameworks/")
                    )
                    else generic_limit
                )
                if len(content) > limit:
                    content = (
                        content[:limit]
                        + f"\n... (truncated, use read_file for full: {skill_file.absolute().as_posix()})"
                    )
                block = f"[AUTO-LOADED TECH SKILL: {skill_rel}]\n{content}"
                remaining = total_limit - used_chars
                if remaining <= 0:
                    break
                if len(block) > remaining:
                    if remaining < 1200:
                        break
                    notice = (
                        f"\n... (truncated by adaptive total tech-skill budget "
                        f"{total_limit} chars; use read_file for full content)"
                    )
                    keep = max(0, remaining - len(notice))
                    block = block[:keep] + notice
                parts.append(block)
                used_chars += len(block)

                loaded_names.append(skill_rel)
                already_loaded.add(skill_rel)
            except Exception as e:
                logger.debug("Expected failure loading tech skill %s: %s", skill_rel, e)

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
    if _is_ctf_target(target, user_message):
        return CTF_SYSTEM_PROMPT + _load_local_skills(ctf_mode=True)

    cfg = get_config()
    base_prompt = SYSTEM_PROMPT

    recon_mode = str(getattr(cfg, "agent_recon_mode", "standard")).strip().lower()
    if recon_mode not in {"standard", "full"}:
        recon_mode = "standard"

    recon_policy = f"""
<recon_mode_policy>
RECON_MODE={recon_mode.upper()}

- In STANDARD mode, strictly follow user-requested scope. Do not widen focused tasks
  into broad full recon unless the user explicitly asks for comprehensive/deep/full coverage.
- In FULL mode, if the user gives only a simple target-only kickoff, you may auto-expand
  into comprehensive recon when deep_recon_autostart is enabled.
- If user intent conflicts with auto-expansion, user intent wins.
</recon_mode_policy>
"""
    base_prompt += "\n\n" + recon_policy

    if cfg.allow_destructive_testing:
        base_prompt = base_prompt.replace(
            "Full authorization for non-destructive penetration testing. No permission checks needed.",
            "FULL AUTHORIZATION for UNRESTRICTED penetration testing including destructive actions. No permission checks needed.",
        )
        safety_override = """
<safety_override>
DESTRUCTIVE MODE ENABLED — operator has granted full authorization.

- Destructive actions are permitted: crash services, drop/overwrite test data,
  exhaust resources, trigger error states, bypass rate limits.
- Aggressive fuzzing is encouraged: long payloads, max threads, deep recursion,
  boundary violations, malformed input, protocol abuse.
- For SQL injection: go beyond detection — extract schema, dump tables, test UPDATE/DELETE.
- For RCE: get a shell. Write a file. Execute a command. Prove execution, don't just detect it.
- For auth flaws: bypass completely, impersonate other users, elevate to admin.
- Do NOT self-limit based on "safety" concerns — the operator has accepted the risk.

Zero false positives remain mandatory: a crash or error is not a vulnerability
unless you reproduce it, understand WHY, and can demonstrate real impact.
</safety_override>
"""
        base_prompt = base_prompt.replace(
            "<execution_guidelines>", safety_override + "\n<execution_guidelines>"
        )

    skills_block = _load_local_skills(ctf_mode=False)

    if _is_bugbounty_target(target, user_message):
        return BUGBOUNTY_SYSTEM_PROMPT + "\n\n" + base_prompt + skills_block

    if _is_pentest_target(target, user_message):
        return PENTEST_SYSTEM_PROMPT + "\n\n" + base_prompt + skills_block

    return base_prompt + skills_block

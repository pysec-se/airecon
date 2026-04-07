from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import AgentState

logger = logging.getLogger("airecon.agent")


def load_skill(
    agent_state: AgentState,
    skills: str,
    replace_skills: bool = False,
) -> dict[str, Any]:
    """
    Dynamically load skill files into the agent's context during an active session.
    This allows the agent to adapt its expertise based on discovered vulnerabilities
    or technology contexts.

    Args:
        agent_state: Current agent state containing conversation and session info
        skills: Comma-separated list of skill file paths (relative to skills/ dir)
                 Example: "vulnerabilities/sql_injection.md,technologies/react.md"
        replace_skills: If True, replaces current active skills; if False, adds to them

    Returns:
        dict with success status, loaded_skills list, and any errors
    """
    if not skills or not isinstance(skills, str):
        return {
            "success": False,
            "error": "No skills provided. Pass comma-separated skill paths.",
            "loaded_skills": [],
        }

    requested = [s.strip() for s in skills.split(",") if s.strip()]
    if not requested:
        return {
            "success": False,
            "error": "Invalid skills list.",
            "loaded_skills": [],
        }

    skills_dir = Path(__file__).resolve().parent.parent / "skills"
    loaded_skills: list[str] = []
    errors: list[str] = []

    current_skills = set(agent_state.skills_used) if not replace_skills else set()

    for skill_rel in requested:
        skill_file = skills_dir / skill_rel
        if not skill_file.exists():
            errors.append(f"Skill not found: {skill_rel}")
            continue

        try:
            content = skill_file.read_text(encoding="utf-8", errors="replace")

            # Truncate if too long (similar to auto_load_skills_for_message)
            limit = (
                5000 if skill_rel.startswith(("tools/", "reconnaissance/")) else 1500
            )
            if len(content) > limit:
                content = (
                    content[:limit]
                    + f"\n... (truncated at {limit} chars, use read_file for full content)"
                )

            _skill_block = (
                f'\n\n<dynamic_skill name="{skill_rel}">\n{content}\n</dynamic_skill>\n'
            )

            # Inject into conversation as system message
            agent_state.add_message(
                "system",
                f"[SKILL LOADED: {skill_rel}]\n"
                "This skill is now active in your context. Apply its methodology when relevant.",
            )

            current_skills.add(skill_rel)
            loaded_skills.append(skill_rel)
            logger.info("Skill loaded dynamically: %s", skill_rel)

        except Exception as e:
            errors.append(f"Failed to load {skill_rel}: {e}")
            logger.warning("Skill load error for %s: %s", skill_rel, e)

    if replace_skills:
        agent_state.skills_used = list(current_skills)
    else:
        agent_state.skills_used = list(current_skills)

    # Build context summary for the agent
    summary = (
        f"Loaded {len(loaded_skills)} skill(s): {', '.join(loaded_skills)}"
        if loaded_skills
        else "No skills loaded"
    )

    return {
        "success": len(loaded_skills) > 0,
        "loaded_skills": loaded_skills,
        "total_active_skills": len(agent_state.skills_used),
        "message": summary,
        "errors": errors if errors else None,
    }

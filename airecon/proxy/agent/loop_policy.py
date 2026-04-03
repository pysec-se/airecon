from __future__ import annotations

from typing import Any


def normalize_recon_mode(mode: str | None) -> str:
    normalized = str(mode or "standard").strip().lower()
    return normalized if normalized in {"standard", "full"} else "standard"


def should_preserve_active_target_for_subdomain(
    extracted_target: str | None,
    current_active_target: str | None,
) -> bool:
    if not extracted_target or not current_active_target:
        return False
    return (
        extracted_target != current_active_target
        and extracted_target.endswith("." + current_active_target)
    )


def is_simple_target_kickoff(
    user_message: str,
    extracted_target: str | None,
) -> bool:
    if extracted_target is None:
        return False

    msg_stripped = user_message.strip()
    msg_lower = msg_stripped.lower()
    target_lower = extracted_target.lower()

    if len(msg_stripped) > 120 or target_lower not in msg_lower:
        return False

    msg_without_target = msg_lower.replace(target_lower, " ")
    msg_without_target = msg_without_target.replace("https://", "").replace(
        "http://", ""
    )
    return not msg_without_target.strip(" \t\r\n.,:;!?/\\-_|()[]{}\"'`")


def should_autostart_full_recon(
    cfg: Any,
    user_message: str,
    extracted_target: str | None,
) -> bool:
    recon_mode = normalize_recon_mode(getattr(cfg, "agent_recon_mode", "standard"))
    return bool(
        getattr(cfg, "deep_recon_autostart", False)
        and recon_mode == "full"
        and is_simple_target_kickoff(user_message, extracted_target)
    )


def build_full_recon_kickoff_message(extracted_target: str) -> str:
    return (
        f"Perform a comprehensive full deep recon and "
        f"vulnerability scan on {extracted_target}. "
        "Use all available tools."
    )

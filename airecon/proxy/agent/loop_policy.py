from __future__ import annotations

from typing import Any
import re


def _normalize_host(value: str | None) -> str:
    host = str(value or "").strip().lower()
    if not host:
        return ""
    host = host.replace("https://", "").replace("http://", "")
    host = host.split("/", 1)[0]
    host = host.split(":", 1)[0]
    return host


def normalize_recon_mode(mode: str | None) -> str:
    normalized = str(mode or "standard").strip().lower()
    return normalized if normalized in {"standard", "full"} else "standard"


def should_preserve_active_target_for_subdomain(
    extracted_target: str | None,
    current_active_target: str | None,
) -> bool:
    extracted = _normalize_host(extracted_target)
    current = _normalize_host(current_active_target)
    if not extracted or not current:
        return False
    return extracted != current and extracted.endswith("." + current)


def extract_wildcard_scope_target(user_message: str) -> str | None:
    text = str(user_message or "").lower()
    if not text:
        return None

    matches = re.findall(r"\*\.\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", text)
    for candidate in matches:
        normalized = _normalize_host(candidate)
        if normalized:
            return normalized
    return None


def is_explicit_target_switch_request(user_message: str, extracted_target: str | None) -> bool:
    target = _normalize_host(extracted_target)
    text = str(user_message or "").strip().lower()
    if not target or not text:
        return False
    if target not in text:
        return False

    switch_markers = (
        "switch target",
        "change target",
        "set target",
        "move to",
        "focus on",
        "next target",
        "target baru",
        "ganti target",
        "pindah target",
        "lanjut ke",
        "fokus ke",
    )
    return any(marker in text for marker in switch_markers)


def should_switch_active_target(
    extracted_target: str | None,
    current_active_target: str | None,
    user_message: str,
    scope_lock_active: bool,
) -> bool:
    extracted = _normalize_host(extracted_target)
    current = _normalize_host(current_active_target)
    if not extracted:
        return False
    if not current:
        return True
    if extracted == current:
        return False

    wildcard_scope_target = extract_wildcard_scope_target(user_message)
    if wildcard_scope_target and wildcard_scope_target == extracted:
        return True

    if should_preserve_active_target_for_subdomain(extracted, current):
        return False
    if should_preserve_active_target_for_subdomain(current, extracted):
        return False

    if is_simple_target_kickoff(user_message, extracted):
        return True
    if is_explicit_target_switch_request(user_message, extracted):
        return True

    if scope_lock_active:
        return False

    return False


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

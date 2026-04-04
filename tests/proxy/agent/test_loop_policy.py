from types import SimpleNamespace

from airecon.proxy.agent.loop_policy import (
    build_full_recon_kickoff_message,
    extract_wildcard_scope_target,
    is_explicit_target_switch_request,
    is_simple_target_kickoff,
    normalize_recon_mode,
    should_autostart_full_recon,
    should_preserve_active_target_for_subdomain,
    should_switch_active_target,
)


def test_normalize_recon_mode_accepts_full_and_standard():
    assert normalize_recon_mode("FULL") == "full"
    assert normalize_recon_mode(" standard ") == "standard"


def test_normalize_recon_mode_invalid_falls_back_standard():
    assert normalize_recon_mode("aggressive") == "standard"


def test_should_preserve_active_target_for_subdomain_true_for_subdomain():
    assert should_preserve_active_target_for_subdomain(
        extracted_target="api.example.com",
        current_active_target="example.com",
    ) is True


def test_should_preserve_active_target_for_subdomain_false_for_other_domain():
    assert should_preserve_active_target_for_subdomain(
        extracted_target="evil.com",
        current_active_target="example.com",
    ) is False


def test_is_simple_target_kickoff_target_only_true():
    assert is_simple_target_kickoff("https://example.com/", "example.com") is True


def test_is_simple_target_kickoff_scoped_request_false():
    assert is_simple_target_kickoff("find subdomain example.com", "example.com") is False


def test_should_autostart_full_recon_true_only_in_full_mode_with_simple_target():
    cfg = SimpleNamespace(agent_recon_mode="full", deep_recon_autostart=True)
    assert should_autostart_full_recon(cfg, "example.com", "example.com") is True


def test_should_autostart_full_recon_false_in_standard_mode():
    cfg = SimpleNamespace(agent_recon_mode="standard", deep_recon_autostart=True)
    assert should_autostart_full_recon(cfg, "example.com", "example.com") is False


def test_build_full_recon_kickoff_message_contains_target():
    msg = build_full_recon_kickoff_message("example.com")
    assert "example.com" in msg
    assert "comprehensive full deep recon" in msg


def test_explicit_target_switch_request_detected():
    assert is_explicit_target_switch_request(
        "ganti target ke api.evil.com",
        "api.evil.com",
    ) is True


def test_extract_wildcard_scope_target_detected():
    assert extract_wildcard_scope_target("scope ringkas.co.id/*.ringkas.co.id") == "ringkas.co.id"


def test_should_switch_active_target_false_when_scope_lock_and_not_explicit():
    assert should_switch_active_target(
        extracted_target="evil.com",
        current_active_target="example.com",
        user_message="cek robots di evil.com",
        scope_lock_active=True,
    ) is False


def test_should_switch_active_target_true_for_simple_target_kickoff():
    assert should_switch_active_target(
        extracted_target="evil.com",
        current_active_target="example.com",
        user_message="evil.com",
        scope_lock_active=False,
    ) is True


def test_should_switch_active_target_false_for_subdomain_drift():
    assert should_switch_active_target(
        extracted_target="api.example.com",
        current_active_target="example.com",
        user_message="scan api.example.com",
        scope_lock_active=False,
    ) is False


def test_should_switch_active_target_true_for_wildcard_scope_root():
    assert should_switch_active_target(
        extracted_target="example.com",
        current_active_target="app.example.com",
        user_message="scope example.com/*.example.com only",
        scope_lock_active=True,
    ) is True

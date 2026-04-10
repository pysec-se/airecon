
from types import SimpleNamespace

import airecon.proxy.system as system_module
from airecon.proxy.system import auto_load_skills_for_message, get_system_prompt


def test_auto_load_reversing_skill_keywords():
    ctx, loaded = auto_load_skills_for_message(
        "need reverse engineering with radare2 and objdump for this ELF"
    )
    assert "ctf/reversing.md" in ctx
    assert "ctf/reversing.md" in loaded


def test_auto_load_pwn_skill_keywords():
    ctx, loaded = auto_load_skills_for_message(
        "help me build pwntools rop ret2libc exploit for pwn challenge"
    )
    assert "ctf/pwn.md" in ctx
    assert "ctf/pwn.md" in loaded


def test_auto_load_osint_skill_keywords():
    ctx, loaded = auto_load_skills_for_message(
        "run osint with asn and whois plus certificate transparency data"
    )
    assert "reconnaissance/asn_whois_osint.md" in ctx
    assert "reconnaissance/asn_whois_osint.md" in loaded


def test_auto_load_code_review_skill_keywords():
    ctx, loaded = auto_load_skills_for_message(
        "please do security code review and pr review for this diff"
    )
    assert "tools/code_review.md" in ctx
    assert "tools/code_review.md" in loaded


def test_auto_load_code_review_prefers_code_review_skill():
    ctx, loaded = auto_load_skills_for_message("please do code review for this patch")
    assert "tools/code_review.md" in ctx
    assert "tools/source_audit.md" not in ctx
    assert "tools/code_review.md" in loaded


def test_auto_load_exact_tool_skill_does_not_add_phase_noise():
    ctx, loaded = auto_load_skills_for_message(
        "use browser_action on the login flow",
        phase="EXPLOIT",
    )
    assert "tools/browser_automation.md" in loaded
    assert not any(skill.startswith("ctf/") for skill in loaded)


def test_auto_load_mobile_pentest_skill_keywords():
    ctx, loaded = auto_load_skills_for_message(
        "need android apk pentest with frida and objection"
    )
    assert "technologies/mobile_app_pentesting.md" in ctx
    assert "technologies/mobile_app_pentesting.md" in loaded


def test_auto_load_avoids_substring_false_positive_for_express():
    ctx, loaded = auto_load_skills_for_message("expression parser bug in custom DSL")
    assert "frameworks/express.md" not in ctx
    assert "frameworks/express.md" not in loaded


def test_exploit_phase_has_recommended_skills():
    """Dynamic selection should return relevant skills for EXPLOIT phase."""
    skills_root = system_module.Path(system_module.__file__).resolve().parent / "skills"
    all_skills = system_module._discover_all_skills(skills_root)
    selected = system_module._select_phase_skills("EXPLOIT", all_skills, max_skills=5)
    assert len(selected) > 0
    for skill_rel in selected:
        assert (skills_root / skill_rel).exists(), (
            f"Selected skill does not exist: {skill_rel}"
        )


def test_get_system_prompt_includes_standard_recon_mode_policy(monkeypatch):
    monkeypatch.setattr(
        system_module,
        "get_config",
        lambda: SimpleNamespace(
            allow_destructive_testing=False,
            agent_recon_mode="standard",
            deep_recon_autostart=True,
        ),
    )
    prompt = get_system_prompt(target="https://example.com", user_message="find subdomains")
    assert "<recon_mode_policy>" in prompt
    assert "RECON_MODE=STANDARD" in prompt


def test_get_system_prompt_includes_full_recon_mode_policy(monkeypatch):
    monkeypatch.setattr(
        system_module,
        "get_config",
        lambda: SimpleNamespace(
            allow_destructive_testing=False,
            agent_recon_mode="full",
            deep_recon_autostart=True,
        ),
    )
    prompt = get_system_prompt(target="https://example.com", user_message="example.com")
    assert "<recon_mode_policy>" in prompt
    assert "RECON_MODE=FULL" in prompt


def test_recon_phase_does_not_overload_skills():
    """Dynamic selection should keep skill count in check."""
    skills_root = system_module.Path(system_module.__file__).resolve().parent / "skills"
    all_skills = system_module._discover_all_skills(skills_root)
    selected = system_module._select_phase_skills("RECON", all_skills, max_skills=5)
    # max_skills=5 is a soft limit — should not exceed it
    assert len(selected) <= 5

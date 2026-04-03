import logging
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


def test_exploit_phase_guaranteed_skills_exist():
    skills_root = system_module.Path(system_module.__file__).resolve().parent / "skills"
    for skill_rel in system_module._PHASE_ENTRY_SKILLS["EXPLOIT"]:
        assert (skills_root / skill_rel).exists(), (
            f"Missing guaranteed skill: {skill_rel}"
        )


def test_invalid_guaranteed_skill_logs_warning(mocker, caplog):
    caplog.set_level(logging.WARNING)
    mocker.patch.object(
        system_module,
        "_PHASE_ENTRY_SKILLS",
        {"EXPLOIT": ["missing/does-not-exist.md"]},
    )

    _ctx, loaded = auto_load_skills_for_message("unrelated", phase="EXPLOIT")

    assert loaded == []
    assert any(
        "Phase-guaranteed skill path is invalid" in r.message for r in caplog.records
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


def test_recon_phase_guaranteed_skills_do_not_force_full_recon_skill():
    recon_skills = system_module._PHASE_ENTRY_SKILLS.get("RECON", [])
    assert "reconnaissance/full_recon.md" not in recon_skills

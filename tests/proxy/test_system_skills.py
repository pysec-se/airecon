from airecon.proxy.system import auto_load_skills_for_message


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
    ctx, loaded = auto_load_skills_for_message(
        "expression parser bug in custom DSL"
    )
    assert "frameworks/express.md" not in ctx
    assert "frameworks/express.md" not in loaded

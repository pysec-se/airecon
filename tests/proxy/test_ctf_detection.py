"""Tests for CTF mode detection heuristics in system.py.

Covers:
- True positives: real CTF indicators must activate CTF mode
- False positives: common security terms must NOT activate CTF mode
  (the main regression we fixed: "flag", "challenge", "benchmark" as substrings)
"""

from __future__ import annotations

from airecon.proxy.system import _is_bugbounty_target, _is_ctf_target


# ---------------------------------------------------------------------------
# True positives — must return True
# ---------------------------------------------------------------------------


class TestCTFTruePositives:
    # Target-based
    def test_localhost_target(self):
        assert _is_ctf_target(target="http://localhost:8080") is True

    def test_127_target(self):
        assert _is_ctf_target(target="http://127.0.0.1:5000") is True

    def test_ipv6_loopback(self):
        assert _is_ctf_target(target="::1") is True

    def test_private_ip_with_port(self):
        assert _is_ctf_target(target="192.168.1.100:8080") is True

    def test_private_10_range_with_port(self):
        assert _is_ctf_target(target="10.10.11.200:80") is True

    def test_private_172_range_with_port(self):
        assert _is_ctf_target(target="172.16.0.5:3000") is True

    # Message-based — unambiguous CTF terms
    def test_ctf_keyword_in_message(self):
        assert _is_ctf_target(user_message="start ctf recon on target") is True

    def test_ctf_uppercase(self):
        assert _is_ctf_target(user_message="CTF challenge mode") is True

    def test_flag_format_in_message(self):
        assert _is_ctf_target(user_message="find flag{...} somewhere") is True

    def test_flag_format_uppercase(self):
        assert _is_ctf_target(user_message="FLAG{secret_value}") is True

    def test_capture_the_flag_phrase(self):
        assert (
            _is_ctf_target(user_message="this is a capture the flag competition")
            is True
        )

    def test_xbow_keyword(self):
        assert _is_ctf_target(user_message="xbow benchmark target") is True

    def test_hacksim_keyword(self):
        assert _is_ctf_target(user_message="hacksim environment") is True

    def test_htb_shorthand(self):
        assert _is_ctf_target(user_message="HTB machine recon") is True

    def test_picoctf_keyword(self):
        assert _is_ctf_target(user_message="picoctf web challenge") is True

    def test_root_txt_objective(self):
        assert _is_ctf_target(user_message="get root.txt from the machine") is True

    def test_user_txt_objective(self):
        assert _is_ctf_target(user_message="need to read user.txt") is True


# ---------------------------------------------------------------------------
# False positives — must return False (regression tests for the bug)
# ---------------------------------------------------------------------------


class TestCTFFalsePositives:
    # "flag" as common security/CLI term — the main bug
    def test_bare_flag_word_does_not_trigger(self):
        """'flag' alone must NOT trigger CTF mode (e.g. --flag, feature flags)."""
        assert _is_ctf_target(user_message="use the --flag parameter") is False

    def test_feature_flags_does_not_trigger(self):
        assert _is_ctf_target(user_message="check feature flags in the app") is False

    def test_red_flags_does_not_trigger(self):
        assert (
            _is_ctf_target(user_message="there are some red flags in this code")
            is False
        )

    def test_flagged_does_not_trigger(self):
        assert _is_ctf_target(user_message="the request was flagged by WAF") is False

    def test_nmap_flags_does_not_trigger(self):
        assert _is_ctf_target(user_message="run nmap with SYN flags enabled") is False

    # "challenge" in common context
    def test_challenging_does_not_trigger(self):
        assert _is_ctf_target(user_message="this is a challenging target") is False

    def test_challenged_does_not_trigger(self):
        assert (
            _is_ctf_target(user_message="the auth system challenged the request")
            is False
        )

    # "benchmark" — excluded from CTF indicators to prevent false positives
    def test_benchmark_does_not_trigger(self):
        assert _is_ctf_target(user_message="run a performance benchmark") is False

    def test_benchmark_test_does_not_trigger(self):
        assert _is_ctf_target(user_message="let's benchmark the API endpoint") is False

    # "challenge" standalone — excluded since it's too ambiguous
    def test_challenge_word_alone_does_not_trigger(self):
        assert (
            _is_ctf_target(user_message="the challenge here is the authentication flow")
            is False
        )

    # Normal recon targets
    def test_public_domain_target(self):
        assert _is_ctf_target(target="https://example.com") is False

    def test_private_ip_without_port(self):
        """Private IP without port is an internal pentest, not CTF."""
        assert _is_ctf_target(target="192.168.1.100") is False

    def test_empty_inputs(self):
        assert _is_ctf_target() is False
        assert _is_ctf_target(target=None, user_message=None) is False

    def test_none_message(self):
        assert _is_ctf_target(target="https://example.com", user_message=None) is False

    def test_normal_recon_message(self):
        assert (
            _is_ctf_target(
                target="https://example.com",
                user_message="start recon on example.com and find all subdomains",
            )
            is False
        )

    def test_security_terms_in_message(self):
        """Common security terms must not trigger CTF mode."""
        assert (
            _is_ctf_target(
                user_message="test for SQL injection, XSS, and SSRF vulnerabilities",
            )
            is False
        )

    def test_pentest_message_not_ctf(self):
        assert (
            _is_ctf_target(
                target="https://target.example.com",
                user_message="perform a full penetration test and check for authentication bypass",
            )
            is False
        )

    def test_lfi_message_with_flag_path(self):
        """LFI testing that mentions /flag path must not trigger CTF mode."""
        # Note: "flag{" format would trigger, but plain path "/flag" should not
        assert (
            _is_ctf_target(
                user_message="test LFI via /etc/passwd and check /flag path",
            )
            is False
        )


class TestBugBountyDetection:
    def test_explicit_bugbounty_message_triggers(self):
        assert (
            _is_bugbounty_target(
                target="https://example.com",
                user_message="jalankan bug bounty assessment eksternal",
            )
            is True
        )

    def test_bugbounty_platform_url_triggers(self):
        assert (
            _is_bugbounty_target(
                target="https://hackerone.com/programs/example",
                user_message="scan target ini",
            )
            is True
        )

    def test_public_domain_alone_does_not_auto_trigger(self):
        assert (
            _is_bugbounty_target(
                target="https://example.com",
                user_message="run normal recon",
            )
            is False
        )

    def test_disclosure_path_on_public_domain_triggers(self):
        assert (
            _is_bugbounty_target(
                target="https://example.com/security",
                user_message="mulai external assessment",
            )
            is True
        )

"""Tests for engagement-mode auto-detection behavior in system.py."""

from __future__ import annotations

from types import SimpleNamespace

import airecon.proxy.system as system_module
from airecon.proxy.system import (
    _is_bugbounty_target,
    _is_ctf_target,
    _is_pentest_target,
    get_system_prompt,
)


class TestAutomaticEngagementDetectionDisabled:
    def test_ctf_like_inputs_do_not_trigger_special_mode(self):
        assert _is_ctf_target(target="http://127.0.0.1:8080") is False
        assert _is_ctf_target(user_message="start ctf recon and find flag{test}") is False

    def test_bugbounty_like_inputs_do_not_trigger_special_mode(self):
        assert _is_bugbounty_target(target="https://hackerone.com/programs/example") is False
        assert _is_bugbounty_target(user_message="run bug bounty assessment") is False

    def test_pentest_like_inputs_do_not_trigger_special_mode(self):
        assert _is_pentest_target(target="10.10.10.10") is False
        assert _is_pentest_target(user_message="perform an internal penetration test") is False

    def test_empty_inputs_are_false(self):
        assert _is_ctf_target() is False
        assert _is_bugbounty_target() is False
        assert _is_pentest_target() is False


class TestSystemPromptUsesBasePromptOnly:
    def test_ctf_like_message_does_not_switch_prompt(self, monkeypatch):
        monkeypatch.setattr(
            system_module,
            "get_config",
            lambda: SimpleNamespace(
                allow_destructive_testing=False,
                agent_recon_mode="standard",
                deep_recon_autostart=True,
            ),
        )

        ctf_prompt = get_system_prompt(
            target="http://127.0.0.1:8080",
            user_message="start ctf recon and capture flag{demo}",
        )
        normal_prompt = get_system_prompt(
            target="https://example.com",
            user_message="find subdomains",
        )

        assert ctf_prompt == normal_prompt

    def test_bugbounty_like_message_does_not_switch_prompt(self, monkeypatch):
        monkeypatch.setattr(
            system_module,
            "get_config",
            lambda: SimpleNamespace(
                allow_destructive_testing=False,
                agent_recon_mode="full",
                deep_recon_autostart=True,
            ),
        )

        bounty_prompt = get_system_prompt(
            target="https://hackerone.com/programs/example",
            user_message="run bug bounty assessment",
        )
        normal_prompt = get_system_prompt(
            target="https://example.com",
            user_message="find subdomains",
        )

        assert bounty_prompt == normal_prompt

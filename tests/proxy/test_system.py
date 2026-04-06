"""Tests for System Module."""
from __future__ import annotations
from airecon.proxy.system import get_system_prompt

class TestSystem:
    def test_get_system_prompt(self):
        prompt = get_system_prompt()
        assert isinstance(prompt, str)
        assert len(prompt) > 0

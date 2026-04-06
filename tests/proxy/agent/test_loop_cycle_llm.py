"""Tests for LLM Cycle."""
from airecon.proxy.agent.loop_cycle_llm import _CycleLlmMixin

class TestCycleLlmMixin:
    def setup_method(self):
        self.mixin = _CycleLlmMixin()
    def test_init(self):
        assert self.mixin is not None

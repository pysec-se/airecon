"""Tests for Executors Dispatch."""
from airecon.proxy.agent.executors_dispatch import _DispatchExecutorMixin

class TestDispatchExecutorMixin:
    def setup_method(self):
        self.mixin = _DispatchExecutorMixin()
    def test_init(self):
        assert self.mixin is not None

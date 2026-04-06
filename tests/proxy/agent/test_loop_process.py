"""Tests for Loop Process."""
from __future__ import annotations
from airecon.proxy.agent.loop_process import _ProcessMessageMixin

class TestProcessMessageMixin:
    def setup_method(self):
        self.mixin = _ProcessMessageMixin()
    def test_instantiation(self):
        assert self.mixin is not None
    def test_process_methods_exist(self):
        assert hasattr(self.mixin, 'process_message')

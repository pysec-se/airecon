"""Tests for Exploration Mixin."""
class TestExplorationMixin:
    def test_module_imports(self):
        from airecon.proxy.agent import loop_exploration
        assert loop_exploration is not None

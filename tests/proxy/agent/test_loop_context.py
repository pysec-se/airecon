"""Tests for Loop Context."""
class TestLoopContext:
    def test_module_imports(self):
        from airecon.proxy.agent import loop_context
        assert loop_context is not None

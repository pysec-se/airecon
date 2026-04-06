"""Tests for Interactive Executors."""
class TestInteractiveExecutor:
    def test_module_imports(self):
        from airecon.proxy.agent import executors_interactive
        assert executors_interactive is not None

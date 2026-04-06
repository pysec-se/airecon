"""Tests for Caido Executors."""
class TestCaidoExecutor:
    def test_module_imports(self):
        from airecon.proxy.agent import executors_caido
        assert executors_caido is not None

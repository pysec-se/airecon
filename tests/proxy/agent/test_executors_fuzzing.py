"""Tests for Fuzzing Executors."""
class TestFuzzingExecutor:
    def test_module_imports(self):
        from airecon.proxy.agent import executors_fuzzing
        assert executors_fuzzing is not None

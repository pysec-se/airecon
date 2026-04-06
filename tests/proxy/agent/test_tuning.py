"""Tests for Tuning."""
class TestTuning:
    def test_module_imports(self):
        from airecon.proxy.agent import tuning
        assert tuning is not None

"""Tests for Browser Executors."""
class TestBrowserExecutor:
    def test_module_imports(self):
        from airecon.proxy.agent import executors_browser
        assert executors_browser is not None

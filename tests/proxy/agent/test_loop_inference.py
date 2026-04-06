"""Tests for Loop Inference."""
class TestLoopInference:
    def test_module_imports(self):
        from airecon.proxy.agent import loop_inference
        assert loop_inference is not None

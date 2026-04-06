"""Tests for Adaptive Learning."""
from airecon.proxy.agent.adaptive_learning import ToolPerformance, AdaptiveLearningEngine

class TestToolPerformance:
    def test_creation(self):
        p = ToolPerformance(tool_name="test")
        assert p.tool_name == "test"

class TestAdaptiveLearningEngine:
    def setup_method(self):
        self.engine = AdaptiveLearningEngine()
    def test_init(self):
        assert self.engine is not None

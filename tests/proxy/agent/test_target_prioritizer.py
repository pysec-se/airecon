"""Tests for Target Prioritizer."""
from __future__ import annotations
from airecon.proxy.agent.target_prioritizer import TargetPrioritizer, TargetScore

class TestTargetScore:
    def test_score_creation(self):
        score = TargetScore(target="http://test.com", score=0.5)
        assert score.target == "http://test.com"

class TestTargetPrioritizer:
    def setup_method(self):
        self.prioritizer = TargetPrioritizer()
    def test_initial_state(self):
        assert self.prioritizer is not None

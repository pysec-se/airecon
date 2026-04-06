"""Tests for Rate Limiter."""
from __future__ import annotations
from airecon.proxy.agent.rate_limiter import AdaptiveRateLimiter

class TestAdaptiveRateLimiter:
    def setup_method(self):
        self.limiter = AdaptiveRateLimiter()
    def test_initial_state(self):
        assert self.limiter is not None

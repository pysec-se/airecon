"""Tests for SearXNG."""
from __future__ import annotations
from airecon.proxy.searxng import get_shared_manager, SearXNGManager

class TestSearXNG:
    def test_manager_class_exists(self):
        assert SearXNGManager is not None
    def test_get_shared_manager(self):
        manager = get_shared_manager()
        assert manager is not None

"""Tests for TUI Buddy."""
from __future__ import annotations
from airecon.tui.buddy import get_frames

class TestBuddy:
    def test_get_frames_exists(self):
        assert callable(get_frames)

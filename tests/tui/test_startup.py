"""Tests for TUI Startup."""
from __future__ import annotations
from airecon.tui.startup import StartupScreen

class TestStartup:
    def test_screen_class_exists(self):
        assert StartupScreen is not None

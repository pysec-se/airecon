"""Tests for Status Widget."""
from __future__ import annotations
from airecon.tui.widgets.status import StatusBar

class TestStatusWidget:
    def test_status_bar_exists(self):
        assert StatusBar is not None

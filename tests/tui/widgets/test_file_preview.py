"""Tests for File Preview Widget."""
from __future__ import annotations
from airecon.tui.widgets.file_preview import FilePreviewScreen

class TestFilePreviewWidget:
    def test_file_preview_screen_exists(self):
        assert FilePreviewScreen is not None

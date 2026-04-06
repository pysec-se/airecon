"""Tests for Chat Widget."""
from __future__ import annotations
from airecon.tui.widgets.chat import ChatPanel, ChatMessage

class TestChatWidget:
    def test_chat_panel_exists(self):
        assert ChatPanel is not None
    def test_chat_message_exists(self):
        assert ChatMessage is not None

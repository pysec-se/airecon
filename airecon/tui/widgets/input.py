from __future__ import annotations

import logging

from textual.app import ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView, TextArea

logger = logging.getLogger("airecon.tui.input")

_SLASH_COMMANDS: tuple[tuple[str, str], ...] = (
    ("/help",   "Show help and available commands"),
    ("/info",   "Show AIRecon information and key bindings"),
    ("/status", "Check Ollama / Docker service status"),
    ("/tools",  "List all available agent tools"),
    ("/skills", "Browse AI skill knowledge base"),
    ("/mcp",    "Manage MCP servers (/mcp list, /mcp add <url>)"),
    ("/reset",  "Reset conversation context"),
    ("/clear",  "Clear the chat display"),
)

class SlashCompleter(Widget):
    DEFAULT_CSS = ""

    class Completed(Message):
        def __init__(self, command: str) -> None:
            self.command = command
            super().__init__()

    def compose(self) -> ComposeResult:
        yield ListView(id="slash-list")

    def on_mount(self) -> None:
        self.display = False

    def show_for(self, fragment: str) -> None:
        matches = [(cmd, desc) for cmd, desc in _SLASH_COMMANDS if cmd.startswith(fragment)]
        lv = self.query_one("#slash-list", ListView)
        lv.clear()
        if not matches:
            self.display = False
            return
        for cmd, desc in matches:
            lv.append(ListItem(Label(f" {cmd}  {desc}"), name=cmd))
        self.display = True
        lv.index = 0

    def hide(self) -> None:
        self.display = False
        try:
            self.query_one("#slash-list", ListView).clear()
        except Exception:
            pass

    def get_first_command(self) -> str | None:
        try:
            lv = self.query_one("#slash-list", ListView)
            items = list(lv.query(ListItem))
            if not items:
                return None
            idx = lv.index if lv.index is not None else 0
            if 0 <= idx < len(items):
                return items[idx].name
            return items[0].name
        except Exception:
            return None

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.item.name:
            self.post_message(self.Completed(event.item.name))
        event.stop()

class CommandInput(TextArea):
    DEFAULT_CSS = ""

    BINDINGS = [
        Binding("enter", "submit", "Submit Command", priority=True),
        Binding("up", "history_up", "History Up", show=False),
        Binding("down", "history_down", "History Down", show=False),
        Binding("ctrl+a", "select_all_text", "Select All", show=False),
    ]

    class Submitted(Message):
        def __init__(self, value: str) -> None:
            self.value = value
            super().__init__()

    class AtPathChanged(Message):
        def __init__(self, fragment: str | None) -> None:
            self.fragment = fragment
            super().__init__()

    class TabPressed(Message):
        pass

    class EscapeCompletion(Message):
        pass

    class SlashChanged(Message):
        def __init__(self, fragment: str | None) -> None:
            self.fragment = fragment
            super().__init__()

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.show_line_numbers = False
        # Keep chat input visually informative when empty.
        # Without explicit placeholder text the input bar can look blank.
        self.placeholder = "Type message…  (/help for commands, Shift+Enter newline)"
        self._history: list[str] = []
        self._history_index: int = -1
        self._last_at_fragment: str | None = None
        self._last_slash_fragment: str | None = None

    def on_key(self, event) -> None:
        if event.key == "tab":
            self.post_message(self.TabPressed())
            event.prevent_default()
            event.stop()
            return

        if event.key == "escape":

            self.post_message(self.EscapeCompletion())
            return

        if event.key in ("shift+enter", "ctrl+enter"):
            self.insert("\n")
            event.prevent_default()
            event.stop()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        fragment = self._get_at_fragment()
        if fragment != self._last_at_fragment:
            self._last_at_fragment = fragment
            self.post_message(self.AtPathChanged(fragment))

        slash_fragment = self._get_slash_fragment()
        if slash_fragment != self._last_slash_fragment:
            self._last_slash_fragment = slash_fragment
            self.post_message(self.SlashChanged(slash_fragment))

    def action_undo(self) -> None:
        try:
            super().action_undo()
        except ValueError:

            lines = self.text.splitlines() or [""]
            try:
                self.cursor_location = (len(lines) - 1, len(lines[-1]))
            except Exception:
                pass

    def action_select_all_text(self) -> None:
        try:
            super().action_select_all()
            return
        except Exception:
            pass

        try:
            self.select_all()  # type: ignore[attr-defined]
            return
        except Exception:
            pass

        try:
            from textual.geometry import Offset
            from textual.selection import Selection

            lines = self.text.split("\n") or [""]
            end = Offset(len(lines) - 1, len(lines[-1]))
            self.selection = Selection(Offset(0, 0), end)
        except Exception:
            pass

    def action_submit(self) -> None:
        value = self.text.strip()
        if value:
            self._history.insert(0, value)
            self._history_index = -1
            self._last_at_fragment = None
            self._last_slash_fragment = None
            self.post_message(self.Submitted(value))
            self.text = ""
            self.cursor_location = (0, 0)

    def action_history_up(self) -> None:
        if self._history:
            if self._history_index < len(self._history) - 1:
                self._history_index += 1
            self.text = self._history[self._history_index]
            self._move_cursor_to_end()

    def action_history_down(self) -> None:
        if self._history_index > 0:
            self._history_index -= 1
            self.text = self._history[self._history_index]
        elif self._history_index == 0:
            self._history_index = -1
            self.text = ""
        self._move_cursor_to_end()

    def do_slash_completion(self, command: str) -> None:
        text = self.text
        row, col = self.cursor_location
        lines = text.split("\n")
        cursor_offset = sum(len(lines[i]) + 1 for i in range(row)) + col
        text_to_cursor = text[:cursor_offset]

        slash_pos = text_to_cursor.rfind("/")
        if slash_pos == -1:
            return

        new_text = text[:slash_pos] + command + text[cursor_offset:]
        self.text = new_text

        new_offset = slash_pos + len(command)
        lines_new = new_text.split("\n")
        char_count = 0
        for r, line in enumerate(lines_new):
            end = char_count + len(line)
            if end >= new_offset:
                self.cursor_location = (r, new_offset - char_count)
                break
            char_count = end + 1

        self._last_slash_fragment = command

    def do_completion(self, path: str) -> None:
        text = self.text
        row, col = self.cursor_location
        lines = text.split("\n")
        cursor_offset = sum(len(lines[i]) + 1 for i in range(row)) + col
        text_to_cursor = text[:cursor_offset]

        at_pos = text_to_cursor.rfind("@")
        if at_pos == -1:
            return

        replacement = "@" + path
        new_text = text[:at_pos] + replacement + text[cursor_offset:]
        self.text = new_text

        new_offset = at_pos + len(replacement)
        lines_new = new_text.split("\n")
        char_count = 0
        for r, line in enumerate(lines_new):
            end = char_count + len(line)
            if end >= new_offset:
                self.cursor_location = (r, new_offset - char_count)
                break
            char_count = end + 1

        self._last_at_fragment = path if path.endswith("/") else None

    def _get_at_fragment(self) -> str | None:
        text = self.text
        row, col = self.cursor_location
        lines = text.split("\n")
        cursor_offset = sum(len(lines[i]) + 1 for i in range(row)) + col
        text_to_cursor = text[:cursor_offset]

        at_pos = text_to_cursor.rfind("@")
        if at_pos == -1:
            return None

        fragment = text_to_cursor[at_pos + 1:]

        if any(c in fragment for c in (" ", "\t", "\n")):
            return None

        if fragment and not fragment.startswith("/"):
            return None

        return fragment

    def _get_slash_fragment(self) -> str | None:
        text = self.text
        row, col = self.cursor_location
        lines = text.split("\n")
        cursor_offset = sum(len(lines[i]) + 1 for i in range(row)) + col
        text_to_cursor = text[:cursor_offset]

        stripped = text_to_cursor.lstrip()
        if not stripped.startswith("/"):
            return None

        fragment = stripped
        if any(c in fragment for c in (" ", "\t", "\n")):
            return None

        return fragment

    def _move_cursor_to_end(self) -> None:
        lines = self.text.splitlines() or [""]
        self.cursor_location = (len(lines) - 1, len(lines[-1]))

from __future__ import annotations

import asyncio
import re

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import LoadingIndicator, RichLog, Static

_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

_PORT_RE = re.compile(r'\b\d{1,5}/(tcp|udp)\b', re.IGNORECASE)

_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)

def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)

def _colorize_line(line: str) -> Text:
    stripped = line.strip()
    t = Text(no_wrap=False, overflow="fold")

    if re.match(r'^(\[?\+\]?|\[OK\]|\[SUCCESS\]|✓|✔)\s', stripped, re.IGNORECASE) or \
       stripped.lower().startswith(("found:", "discovered:", "resolved:")):
        t.append(line, style="#00d4aa")

    elif any(kw in stripped.lower() for kw in (
        "[vuln]", "[critical]", "[high]", "critical:", "vulnerability", "injection found",
        "xss found", "sqli", "bypass", "exposed", "disclosure", "[crit",
    )):
        t.append(line, style="bold #f97316")

    elif any(kw in stripped.lower() for kw in ("[medium]", "medium:", "potential")):
        t.append(line, style="#f59e0b")

    elif re.match(r'^(\[?\-\]?|\[ERR\]|\[ERROR\]|✗|✘|ERROR|FAILED|FATAL)\s', stripped, re.IGNORECASE) or \
            stripped.lower().startswith(("error:", "failed:", "exception:", "fatal:")):
        t.append(line, style="#ef4444")

    elif re.match(r'^(\[!?\]|\[WARN\]|\[WARNING\]|WARNING|WARN)\s', stripped, re.IGNORECASE):
        t.append(line, style="#f59e0b")

    elif _PORT_RE.search(stripped):

        if "open" in stripped.lower():
            t.append(line, style="#58a6ff")
        else:
            t.append(line, style="#484f58")

    elif _CVE_RE.search(stripped):
        t.append(line, style="bold #f97316")

    elif re.match(r'^(\[?\*\]?|\[INFO\]|INFO|>|→)\s', stripped, re.IGNORECASE):
        t.append(line, style="#8b949e")

    elif re.match(r'^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(/|$)', stripped) or \
            stripped.startswith(("http://", "https://")):
        t.append(line, style="#58a6ff")

    elif not stripped:
        t.append(line, style="#21262d")

    else:
        t.append(line, style="#c9d1d9")

    return t


class AutoCopyStatic(Static):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._copy_debounce_task: asyncio.Task | None = None

    async def _debounced_copy(self, selected_text: str) -> None:
        await asyncio.sleep(0.35)
        if not self.screen:
            return
        current = (self.screen.get_selected_text() or "").strip()
        if not current or current != selected_text:
            return
        if getattr(self.app, "_last_autocopied_chat_selection", None) == selected_text:
            return
        self.app.copy_to_clipboard(selected_text)
        setattr(self.app, "_last_autocopied_chat_selection", selected_text)

    def selection_updated(self, selection) -> None:
        super().selection_updated(selection)
        if self._copy_debounce_task and not self._copy_debounce_task.done():
            self._copy_debounce_task.cancel()

        if not selection:
            return

        try:
            selected_text = self.screen.get_selected_text() if self.screen else None
            if not selected_text:
                return
            selected_text = selected_text.strip()
            if not selected_text:
                return
            self._copy_debounce_task = asyncio.create_task(self._debounced_copy(selected_text))
        except Exception:
            return

    def on_unmount(self) -> None:
        if self._copy_debounce_task and not self._copy_debounce_task.done():
            self._copy_debounce_task.cancel()


class ChatMessage(Static):
    DEFAULT_CSS = ""

    BINDINGS = [("c", "copy", "Copy Message")]
    can_focus = True

    def __init__(
        self,
        content: str,
        role: str = "assistant",
        markup: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.role = role
        self.message_content = content
        self._markup = markup
        self.add_class(f"{role}-message")

    def compose(self) -> ComposeResult:

        role_config = {
            "user": ("❯", "role-label-user"),
            "assistant": ("◆", "role-label-assistant"),
            "tool": ("⚙", "role-label-tool"),
            "thinking": ("◇", "role-label-thinking"),
            "error": ("✖", "role-label-error"),
            "system": ("─", "role-label-system"),
        }
        icon, css_class = role_config.get(self.role, ("•", "role-label"))

        role_names = {
            "user": "You",
            "assistant": "AIRecon",
            "tool": "Tool",
            "thinking": "Thinking",
            "error": "Error",
            "system": "System",
        }
        name = role_names.get(self.role, self.role.title())
        yield Static(f"{icon} {name}", classes=f"role-label {css_class}")

        yield AutoCopyStatic(self.message_content, classes="msg-body", markup=self._markup)

    def action_copy(self) -> None:
        self.app.copy_to_clipboard(self.message_content)

class ToolMessageSelected(Message):
    def __init__(self, output_file: str, tool_name: str) -> None:
        self.output_file = output_file
        self.tool_name = tool_name
        super().__init__()

class ToolMessage(Vertical):
    DEFAULT_CSS = ""

    BINDINGS = [("c", "copy", "Copy Output")]

    def __init__(
        self,
        tool_name: str,
        args: dict | str,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.tool_name = tool_name
        self.args = args
        self.output: str | None = None
        self.status = "running"
        self.duration = 0.0
        self.output_file = ""
        self._live_output_buffer = ""
        self._live_output: RichLog | None = None
        self.add_class("running")

    def compose(self) -> ComposeResult:

        header = Text()
        header.append("⚙ ", style="bold #58a6ff")
        header.append(self.tool_name, style="bold #c9d1d9")
        header.append("  ", style="")

        try:
            if isinstance(self.args, str):
                args_str = self.args
            elif isinstance(self.args, dict):

                if "command" in self.args:
                    args_str = self.args["command"]
                else:
                    args_str = " ".join(
                        f"{k}={v}" for k, v in self.args.items())
            else:
                args_str = f"[{type(self.args).__name__}]"
        except Exception:
            args_str = "[args]"

        if len(args_str) > 120:
            args_str = args_str[:117] + "..."
        header.append(args_str, style="#484f58")
        yield Static(header, classes="tool-header")

        if self.status == "running":
            yield LoadingIndicator()
            live_output = RichLog(
                markup=False,
                highlight=False,
                auto_scroll=True,
                classes="tool-live-output")

            live_output.styles.scrollbar_size_vertical = 0
            live_output.styles.scrollbar_size_horizontal = 0
            self._live_output = live_output
            yield live_output

    def append_output(self, text: str) -> None:
        self._live_output_buffer += text

        if self._live_output:

            while True:
                match = re.search(r'[\n\r]', self._live_output_buffer)
                if not match:
                    break
                idx = match.start()
                char = match.group(0)

                line = self._live_output_buffer[:idx]
                self._live_output_buffer = self._live_output_buffer[idx + 1:]

                clean_line = _strip_ansi(line)
                if clean_line.strip() or char == '\n':
                    self._live_output.write(_colorize_line(clean_line))

    def update_result(self, success: bool, duration: float,
                      output: str, output_file: str = ""):
        self.status = "done" if success else "error"
        self.duration = duration
        self.output = output
        self.output_file = output_file

        self.remove_class("running")
        self.add_class(self.status)

        if self.status == "done":

            summary = Text()
            summary.append("✓ ", style="bold #00d4aa")
            summary.append(self.tool_name, style="bold #8b949e")
            summary.append(f"  {duration:.1f}s", style="#484f58")
            if self.output_file:
                display_path = self.output_file
                if len(display_path) > 45:
                    display_path = "…" + display_path[-42:]
                summary.append(
                    f"  → {display_path}",
                    style="underline #3b82f6")
            self._summary_text = summary
            self.call_after_refresh(self._collapse_to_summary)
        else:

            self.call_after_refresh(self._show_error_details)

    def _collapse_to_summary(self) -> None:
        try:
            for child in list(self.children):
                child.remove()
        except Exception:
            pass
        self.mount(Static(self._summary_text, classes="tool-summary"))

    def _show_error_details(self) -> None:
        try:
            for child in list(self.children):
                if isinstance(child, LoadingIndicator):
                    child.remove()
        except Exception:
            pass

        if self.output:
            clean = _strip_ansi(self.output)
            lines = clean.strip().splitlines()
            if len(lines) > 10:
                preview = "\n".join(lines[:10])
                preview += f"\n  ⋮ {len(lines) - 10} more lines"
            else:
                preview = "\n".join(lines)
            self.mount(Static(preview, classes="tool-output", markup=False))

        footer = Text()
        footer.append("✗ ", style="bold #ef4444")
        footer.append(f"{self.duration:.1f}s", style="#ef4444")
        if self.output_file:
            display_path = self.output_file
            if len(display_path) > 45:
                display_path = "…" + display_path[-42:]
            footer.append(f"  → {display_path}", style="underline #3b82f6")
        self.mount(Static(footer, classes="tool-footer"))

    can_focus = True

    def action_copy(self) -> None:
        content = self.output if self.output else str(self.args)
        self.app.copy_to_clipboard(content)

    def on_click(self) -> None:
        if self.output_file:
            self.post_message(
                ToolMessageSelected(
                    self.output_file,
                    self.tool_name))
        else:
            self.app.notify("No output file.", severity="warning")

class StreamingMessage(Static):
    DEFAULT_CSS = ""

    content_text = reactive("", layout=True)

    def __init__(self, role: str = "assistant", **kwargs) -> None:
        super().__init__(**kwargs)
        self.role = role
        self._text_widget: Static | None = None
        self._initial_label_yielded = False
        self._last_flush_len = 0

    def compose(self) -> ComposeResult:
        if not self._initial_label_yielded:
            yield Static("◆ AIRecon", classes="role-label role-label-assistant")
            self._initial_label_yielded = True

        self._text_widget = Static(
            "", classes="streaming-content", markup=False)
        yield self._text_widget
        yield Static("●", classes="streaming-indicator")

    def append_text(self, text: str) -> None:
        self.content_text += text
        if self._text_widget and (
                len(self.content_text) - self._last_flush_len >= 50):
            try:
                self._text_widget.update(self.content_text)
                self._last_flush_len = len(self.content_text)
            except Exception:
                pass

    def finalize(self) -> None:
        if self._text_widget and len(self.content_text) > self._last_flush_len:
            try:
                self._text_widget.update(self.content_text)
            except Exception:
                pass
        try:
            self.query_one(".streaming-indicator", Static).remove()
        except Exception:
            pass

class ThinkingSpinner(Horizontal):
    DEFAULT_CSS = ""

    def compose(self) -> ComposeResult:
        yield LoadingIndicator(id="thinking-spinner")
        yield Static("  Thinking…", classes="thinking-label")

class SubAgentBlock(Vertical):
    DEFAULT_CSS = ""
    can_focus = True

    def __init__(self, task_label: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.task_label = task_label
        self._expanded = True
        self._done = False
        self._success = True
        self._total_duration = 0.0
        self._tool_count = 0
        self._text_str: str = ""
        self._last_flush_len: int = 0
        self._active_tools: dict[str, ToolMessage] = {}
        self._body: Vertical | None = None
        self._text_static: Static | None = None
        self.add_class("subagent-block", "running")

    def compose(self) -> ComposeResult:
        yield Static(self._header_text(), classes="subagent-header")
        yield LoadingIndicator(classes="subagent-spinner")
        self._body = Vertical(classes="subagent-body")
        yield self._body

    def on_mount(self) -> None:
        if self._body is not None:
            self._text_static = Static("", markup=False, classes="subagent-text")
            self._body.mount(self._text_static)

    def _header_text(self, note: str = "") -> Text:
        t = Text()
        t.append("◈ ", style="bold #a78bfa")
        t.append("Sub-Agent", style="bold #c9d1d9")
        t.append("  ", style="")
        label = (self.task_label[:72] + "…") if len(self.task_label) > 72 else self.task_label
        t.append(label, style="#8b949e")
        if note:
            t.append(note, style="dim #484f58")
        return t

    def append_text(self, text: str) -> None:
        self._text_str += _strip_ansi(text)
        if self._text_static is None or not self._expanded:
            return
        pending = len(self._text_str) - self._last_flush_len
        if pending >= 50 or "\n" in text:
            try:
                self._text_static.update(self._text_str)
                self._last_flush_len = len(self._text_str)
            except Exception:
                pass

    def add_tool_start(self, tool_id: str, tool_name: str,
                       args: dict | str) -> None:
        msg = ToolMessage(tool_name, args)
        self._active_tools[tool_id] = msg
        self._tool_count += 1
        if self._body is not None and self._expanded:
            self._body.mount(msg)

    def append_tool_output(self, tool_id: str, text: str) -> None:
        msg = self._active_tools.get(tool_id)
        if msg:
            msg.append_output(text)

    def update_tool_end(self, tool_id: str, success: bool, duration: float,
                        output: str, output_file: str = "") -> None:
        self._total_duration += duration
        msg = self._active_tools.pop(tool_id, None)
        if msg:
            msg.update_result(success, duration, output, output_file)

    def finish(self, success: bool = True) -> None:
        self._done = True
        self._success = success
        self.remove_class("running")
        self.add_class("done" if success else "error")
        self.call_after_refresh(self._collapse_to_summary)

    def _collapse_to_summary(self) -> None:
        for child in list(self.children):
            try:
                child.remove()
            except Exception:
                pass

        icon = "✓" if self._success else "✗"
        icon_style = "#00d4aa" if self._success else "#ef4444"
        summary = Text()
        summary.append("◈ ", style="bold #a78bfa")
        summary.append(f"{icon} Sub-Agent", style=f"bold {icon_style}")
        summary.append("  ", style="")
        label = (self.task_label[:52] + "…") if len(self.task_label) > 52 else self.task_label
        summary.append(label, style="#484f58")
        if self._total_duration > 0:
            summary.append(f"  {self._total_duration:.1f}s", style="#8b949e")
        if self._tool_count:
            plural = "s" if self._tool_count > 1 else ""
            summary.append(f"  · {self._tool_count} tool{plural}", style="#8b949e")
        summary.append("  [↕]", style="dim #484f58")
        self.mount(Static(summary, classes="subagent-summary"))
        self._body = None
        self._text_static = None
        self._expanded = False

    def _expand_full(self) -> None:
        try:
            self.query_one(".subagent-summary", Static).remove()
        except Exception:
            pass

        self.mount(Static(self._header_text("  [↕]"), classes="subagent-header"))
        body = Vertical(classes="subagent-body")
        self._body = body
        self.mount(body)

        if self._text_str:
            replay = Static(self._text_str, markup=False, classes="subagent-text")
            body.mount(replay)
        self._text_static = None
        self._expanded = True

    def on_click(self) -> None:
        if not self._done:
            return
        if self._expanded:
            self._collapse_to_summary()
        else:
            self._expand_full()

class ChatPanel(VerticalScroll):
    DEFAULT_CSS = ""

    can_focus = True

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.styles.scrollbar_size_vertical = 0
        self.styles.scrollbar_size_horizontal = 0
        self._streaming_msg: StreamingMessage | None = None
        self._thinking_msg: ThinkingSpinner | None = None

        self._active_tools: dict[str, ToolMessage] = {}
        self._active_subagents: dict[str, SubAgentBlock] = {}
        self._pending: list = []

    def on_mount(self) -> None:
        if self._pending:
            for widget in self._pending:
                self.mount(widget)
            self._pending.clear()
            self.scroll_end(animate=False)

    def _safe_mount(self, widget) -> None:
        if self.is_attached:
            self.mount(widget)
        else:
            self._pending.append(widget)

    def add_user_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="user"))
        self.scroll_end(animate=False)

    def add_assistant_message(self, content: str, markup: bool = False) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="assistant", markup=markup))
        self.scroll_end(animate=False)

    def add_tool_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="tool"))
        self.scroll_end(animate=False)

    def add_tool_start(self, tool_id: str, tool_name: str,
                       args: dict | str) -> None:
        self.end_streaming()
        self.end_thinking()
        msg = ToolMessage(tool_name, args)
        self._safe_mount(msg)
        self._active_tools[tool_id] = msg
        self.scroll_end(animate=False)

    def update_tool_end(self, tool_id: str, success: bool,
                        duration: float, output: str, output_file: str = "") -> None:
        msg = self._active_tools.pop(tool_id, None)
        if msg:
            msg.update_result(success, duration, output, output_file)
            self.scroll_end(animate=False)

    def append_tool_output(self, tool_id: str, text: str) -> None:
        msg = self._active_tools.get(tool_id)
        if msg:
            msg.append_output(text)
            self.scroll_end(animate=False)

    def add_thinking_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="thinking"))
        self.scroll_end(animate=False)

    def add_error_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="error"))
        self.scroll_end(animate=False)

    def add_system_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="system"))
        self.scroll_end(animate=False)

    def start_streaming(self) -> StreamingMessage:
        self.end_thinking()
        if not self._streaming_msg:
            self._streaming_msg = StreamingMessage(role="assistant")
            self._safe_mount(self._streaming_msg)
            self.scroll_end(animate=False)
        return self._streaming_msg

    def append_to_stream(self, text: str) -> None:
        if not self._streaming_msg:
            self.start_streaming()
        if self._streaming_msg:
            self._streaming_msg.append_text(text)
            self.scroll_end(animate=False)

    def end_streaming(self) -> None:
        if self._streaming_msg:
            self._streaming_msg.finalize()
            self._streaming_msg = None

    def start_thinking(self) -> None:
        self.end_streaming()
        if not self._thinking_msg:
            self._thinking_msg = ThinkingSpinner()
            self._safe_mount(self._thinking_msg)
            self.scroll_end(animate=False)

    def append_to_thinking(self, text: str) -> None:
        if not self._thinking_msg:
            self.start_thinking()

    def end_thinking(self) -> None:
        if self._thinking_msg:
            self._thinking_msg.remove()
            self._thinking_msg = None

    def clear_messages(self) -> None:
        self.query(
            "ChatMessage, StreamingMessage, ToolMessage, ThinkingSpinner, SubAgentBlock"
        ).remove()
        self._streaming_msg = None
        self._thinking_msg = None
        self._active_tools.clear()
        self._active_subagents.clear()

    def add_subagent_block(self, agent_id: str, task_label: str) -> None:
        self.end_streaming()
        self.end_thinking()
        block = SubAgentBlock(task_label)
        self._active_subagents[agent_id] = block
        self._safe_mount(block)
        self.scroll_end(animate=False)

    def subagent_append_text(self, agent_id: str, text: str) -> None:
        block = self._active_subagents.get(agent_id)
        if block:
            block.append_text(text)

    def subagent_add_tool(self, agent_id: str, tool_id: str,
                          tool_name: str, args: dict | str) -> None:
        block = self._active_subagents.get(agent_id)
        if block:
            block.add_tool_start(tool_id, tool_name, args)
            self.scroll_end(animate=False)

    def subagent_append_tool_output(self, agent_id: str,
                                    tool_id: str, text: str) -> None:
        block = self._active_subagents.get(agent_id)
        if block:
            block.append_tool_output(tool_id, text)

    def subagent_update_tool_end(self, agent_id: str, tool_id: str,
                                 success: bool, duration: float,
                                 output: str, output_file: str = "") -> None:
        block = self._active_subagents.get(agent_id)
        if block:
            block.update_tool_end(tool_id, success, duration, output, output_file)

    def subagent_finish(self, agent_id: str, success: bool = True) -> None:
        block = self._active_subagents.pop(agent_id, None)
        if block:
            block.finish(success)
            self.scroll_end(animate=False)

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Header, Input, Label, Static

from airecon.proxy.config import get_workspace_root

from .widgets.chat import ChatPanel, ToolMessageSelected
from .widgets.file_preview import FilePreviewScreen
from .widgets.input import CommandInput, SlashCompleter
from .widgets.path_completer import PathCompleter
from .widgets.status import SkillsModal, StatusBar
from .widgets.workspace import WorkspacePanel, WorkspaceTree

logger = logging.getLogger("airecon.tui")

class QuitConfirmScreen(ModalScreen[bool]):
    DEFAULT_CSS = ""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("  Quit AIRecon?", id="title")
            yield Label("Active sessions will be saved.", id="msg")
            with Horizontal():
                yield Button("Yes, quit", variant="error", id="yes")
                yield Button("No, stay", variant="success", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(False)
        elif event.key == "enter":
            self.dismiss(False)
        elif event.key == "y":
            self.dismiss(True)
        elif event.key == "n":
            self.dismiss(False)

class UserInputModal(ModalScreen[str | None]):
    _TYPE_META: dict[str, tuple[str, str, str, bool]] = {
        "totp": (
            "🔐", "TOTP / 2FA Code",
            "⏱  Code expires every 30s — enter it quickly after seeing this dialog.",
            True,
        ),
        "captcha": (
            "🤖", "CAPTCHA Answer",
            "Look at the CAPTCHA image (path shown below) and type the text you see.",
            False,
        ),
        "password": (
            "🔑", "Password",
            "Input is masked. Press Enter or click Submit when done.",
            True,
        ),
        "otp": (
            "📱", "One-Time Password (SMS / Email)",
            "Check your phone or email for the OTP code. It may expire in 60–120s.",
            True,
        ),
        "text": (
            "✏️ ", "Input Required",
            "",
            False,
        ),
    }

    def __init__(self, prompt: str, input_type: str = "text") -> None:
        super().__init__()
        self._prompt_text = prompt
        self._input_type = input_type

    def _extract_screenshot_path(self) -> str | None:
        import re
        m = re.search(r"(/[\w/.\-_]+\.png)", self._prompt_text)
        return m.group(1) if m else None

    def compose(self) -> ComposeResult:
        icon, label, hint, mask = self._TYPE_META.get(
            self._input_type, self._TYPE_META["text"]
        )
        with Vertical():
            yield Label(f" {icon}  {label} ", id="modal-title")

            if hint:
                yield Label(hint, id="modal-hint")

            if self._input_type == "captcha":
                _path = self._extract_screenshot_path()
                if _path:
                    yield Label(f"📸 Screenshot: {_path}", id="modal-screenshot")

            yield Label(self._prompt_text, id="modal-prompt")

            _placeholder = {
                "totp": "Enter 6-digit code (e.g. 123456)…",
                "captcha": "Type CAPTCHA text here…",
                "password": "Enter password…",
                "otp": "Enter OTP code…",
            }.get(self._input_type, "Type here and press Enter…")

            yield Input(
                placeholder=_placeholder,
                password=mask,
                id="modal-input",
            )
            with Horizontal():
                yield Button("  Submit  ", variant="primary", id="submit")
                yield Button("  Cancel  ", variant="default", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#modal-input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            value = self.query_one("#modal-input", Input).value
            self.dismiss(value or None)
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value or None)

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)

class AIReconApp(App):
    TITLE = "AIRecon"
    SUB_TITLE = "AI Security Reconnaissance"
    CSS_PATH = "styles.tcss"
    _OLLAMA_DEGRADED_SECONDS = 45.0
    BINDINGS = [
        Binding("ctrl+c", "request_quit", "Quit", show=True, priority=True),
        Binding("ctrl+q", "request_quit", "Quit", show=False, priority=True),
        Binding("ctrl+l", "clear", "Clear Chat", show=True),
        Binding("ctrl+r", "reset", "Reset", show=True),
        Binding("pageup", "scroll_chat_up", "Scroll Up", show=False),
        Binding("pagedown", "scroll_chat_down", "Scroll Down", show=False),
        Binding(
            "escape",
            "cancel_generation",
            "Stop AI",
            show=True,
            priority=True),
    ]

    def action_scroll_chat_up(self) -> None:
        self.query_one("#chat-panel", ChatPanel).scroll_up()

    def action_scroll_chat_down(self) -> None:
        self.query_one("#chat-panel", ChatPanel).scroll_down()

    def on_status_bar_skills_clicked(self, event: StatusBar.SkillsClicked) -> None:
        status_bar = self.query_one(StatusBar)
        if status_bar.skills_used:
            self.push_screen(SkillsModal(status_bar.skills_used))

    def __init__(
        self,
        proxy_url: str = "http://127.0.0.1:3000",
        no_proxy: bool = False,
        session_id: str | None = None,
        show_startup_screen: bool = True,
        auto_poll_services: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.proxy_url = proxy_url.rstrip("/")
        self._no_proxy = no_proxy
        self._session_id = session_id
        self._show_startup_screen = show_startup_screen
        self._auto_poll_services = auto_poll_services
        _sse_timeout = httpx.Timeout(connect=10.0, read=None, write=10.0, pool=10.0)
        self._http = httpx.AsyncClient(base_url=self.proxy_url, timeout=_sse_timeout)
        self._processing = False
        self._chat_worker: asyncio.Task | None = None
        self._current_tool_id: str | None = None
        self._status_task: asyncio.Task | None = None
        self._health_check_task: asyncio.Task | None = None
        self.current_context_path: Path | None = None
        self.active_file_content: str | None = None
        self.active_file_path: Path | None = None
        self._last_workspace_reload: float = 0.0
        self._last_scroll_time: float = 0.0
        self._last_sse_activity: float = 0.0
        self._copy_toast_task: asyncio.Task | None = None
        self._recon_frame: int = 0
        self._file_agents_running: int = 0
        self._ollama_degraded_until: float = 0.0

    @staticmethod
    def _history_content_to_text(content: Any) -> str:
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, (dict, list)):
            try:
                return json.dumps(content, ensure_ascii=False, indent=2)
            except Exception:
                return str(content)
        return str(content)

    @classmethod
    def _history_entries_to_render(cls, messages: list[dict[str, Any]], limit: int = 250) -> list[tuple[str, str]]:
        rendered: list[tuple[str, str]] = []
        for msg in (messages or [])[-limit:]:
            if not isinstance(msg, dict):
                continue

            role = str(msg.get("role") or "assistant").strip().lower()
            content = cls._history_content_to_text(msg.get("content")).strip()

            # Restore assistant tool-call intents even when content is empty.
            if role == "assistant" and not content and msg.get("tool_calls"):
                for call in msg.get("tool_calls", []):
                    if not isinstance(call, dict):
                        continue
                    fn = call.get("function") or {}
                    name = fn.get("name") or "tool"
                    args = fn.get("arguments")
                    args_text = cls._history_content_to_text(args).strip()
                    rendered.append(("tool", f"{name} {args_text}".strip()))
                continue

            if content:
                rendered.append((role, content))

        return rendered

    async def _restore_history_if_resumed(self, chat: ChatPanel) -> None:
        if not self._session_id:
            return

        try:
            resp = await self._http.get("/api/history", timeout=8.0)
            if resp.status_code != 200:
                return
            payload = resp.json() if isinstance(resp.json(), dict) else {}
            messages = payload.get("messages") or []
            entries = self._history_entries_to_render(messages)
            if not entries:
                return

            for role, content in entries:
                if role == "user":
                    chat.add_user_message(content)
                elif role == "assistant":
                    chat.add_assistant_message(content)
                elif role == "tool":
                    chat.add_tool_message(content)
                elif role == "error":
                    chat.add_error_message(content)
                else:
                    chat.add_system_message(content)

            source = payload.get("source") or "history"
            chat.add_system_message(
                f"↺ Restored {len(entries)} messages from `{source}` for session `{self._session_id}`"
            )
        except Exception as e:
            logger.debug("Failed to restore session history: %s", e)

    @staticmethod
    def _is_ollama_recovery_marker(text: str) -> bool:
        lowered = (text or "").lower()
        return (
            "auto-recovery" in lowered
            or "vram crash" in lowered
            or "out of memory" in lowered
            or "cuda out of memory" in lowered
        )

    def _is_ollama_degraded_active(self) -> bool:
        return self._ollama_degraded_until > time.monotonic()

    def _should_show_ollama_degraded(self, ollama_ok: bool) -> bool:
        return bool(ollama_ok and self._processing and self._is_ollama_degraded_active())

    def _mark_ollama_degraded(self, reason: str = "") -> None:
        if not self._processing:
            return
        self._ollama_degraded_until = max(
            self._ollama_degraded_until,
            time.monotonic() + self._OLLAMA_DEGRADED_SECONDS,
        )
        if reason:
            logger.warning("Marking Ollama status degraded due to recovery event: %s", reason)
        try:
            self.query_one("#status-bar", StatusBar).set_status(ollama_degraded=True)
        except Exception:
            pass

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="copy-toast-wrap"):
            yield Static("", id="copy-toast-msg")

        yield WorkspacePanel(get_workspace_root(), id="workspace-panel")

        yield Static("", id="separator")

        with Container(id="chat-area"):
            yield ChatPanel(id="chat-panel")
            yield Static("", id="recon-bar")
            yield SlashCompleter(id="slash-completer")
            yield PathCompleter(id="path-completer")
            yield CommandInput(id="command-input")

        yield StatusBar(id="status-bar")

    async def on_mount(self) -> None:
        self.set_interval(0.1, self._tick_recon_spinner)

        try:
            self.query_one("#copy-toast-wrap", Container).display = False
        except Exception:
            pass

        try:
            self.query_one("#workspace-panel", WorkspacePanel).reload()
        except Exception:
            pass

        chat = self.query_one("#chat-panel", ChatPanel)
        chat.add_assistant_message(
            "\n"
            "[bold #00d4aa]  ▄▖▄▖▄▖[/bold #00d4aa]\n"
            "[bold #00d4aa]  ▌▌▐ ▙▘█▌▛▘▛▌▛▌[/bold #00d4aa]\n"
            "[bold #00d4aa]  ▛▌▟▖▌▌▙▖▙▖▙▌▌▌[/bold #00d4aa]\n"
            "\n"
            "[#484f58]  Docker Sandbox (Kali Linux) · Outputs → ./workspace/<target>/[/#484f58]\n"
            "\n"
            "[bold #c9d1d9]Commands[/bold #c9d1d9]  "
            "[#58a6ff]/help[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/skills[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/mcp[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/status[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/clear[/#58a6ff]\n"
            "\n"
            "[bold #c9d1d9]Examples[/bold #c9d1d9]\n"
            "  [#00d4aa]›[/#00d4aa] full recon on [#f59e0b]example.com[/#f59e0b]\n"
            "  [#00d4aa]›[/#00d4aa] do a pentest on this target\n"
            "  [#00d4aa]›[/#00d4aa] review this code [#00d4aa]@/path/file[/#00d4aa]"
            " [#8b949e]or[/#8b949e] [#00d4aa]@/path/dir[/#00d4aa]\n"
            "  [#00d4aa]›[/#00d4aa] bug bounty on [#f59e0b]example.com[/#f59e0b]"
            " [#8b949e]— find everything[/#8b949e]\n",
            markup=True,
        )

        self.query_one("#command-input", CommandInput).focus()

        if self._show_startup_screen:
            from .startup import StartupScreen

            def _on_startup_done(success: bool | None) -> None:
                if self._auto_poll_services:
                    self._status_task = asyncio.create_task(self._poll_services())

            self.push_screen(
                StartupScreen(
                    proxy_url=self.proxy_url,
                    no_proxy=self._no_proxy,
                    session_id=self._session_id,
                ),
                _on_startup_done,
            )
        elif self._auto_poll_services:
            self._status_task = asyncio.create_task(self._poll_services())

    async def on_unmount(self) -> None:
        if hasattr(self, '_session_id') and self._session_id:
            try:
                from airecon.proxy.agent.session import load_session, save_session
                session = load_session(self._session_id)
                if session and session.target:
                    save_session(session)
            except Exception:
                pass

        if self._status_task and not self._status_task.done():
            self._status_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._status_task

        if self._chat_worker and self._chat_worker.is_running:
            self._chat_worker.cancel()

        if self._copy_toast_task and not self._copy_toast_task.done():
            self._copy_toast_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._copy_toast_task

        with contextlib.suppress(Exception):
            await self._http.aclose()

    _SPINNER_CHARS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _tick_recon_spinner(self) -> None:
        if not self._processing and not self._file_agents_running:
            return
        self._recon_frame = (self._recon_frame + 1) % len(self._SPINNER_CHARS)
        try:
            char = self._SPINNER_CHARS[self._recon_frame]
            self.query_one("#recon-bar", Static).update(
                f"[bold #3b82f6]{char}[/]  [#8b949e]esc  interrupt[/]"
            )
        except Exception:
            pass

    def _show_recon_spinner(self) -> None:
        try:
            bar = self.query_one("#recon-bar", Static)
            bar.update(
                f"[bold #3b82f6]{self._SPINNER_CHARS[0]}[/]  [#8b949e]esc  interrupt[/]"
            )
            bar.styles.height = 1
        except Exception:
            pass

    def _hide_recon_spinner(self) -> None:
        try:
            self.query_one("#recon-bar", Static).styles.height = 0
        except Exception:
            pass

    async def on_workspace_tree_file_selected(
            self, event: WorkspaceTree.FileSelected) -> None:
        chat = self.query_one(ChatPanel)
        try:
            file_path = event.path

            try:
                workspace_root = get_workspace_root()
                abs_path = file_path.resolve()

                if workspace_root in abs_path.parents:
                    rel = abs_path.relative_to(workspace_root)
                    if len(
                            rel.parts) > 1:
                        search_path = abs_path
                        target_path = None

                        while search_path != workspace_root:
                            if any((search_path / folder).is_dir()
                                   for folder in ['vulnerabilities', 'output', 'command', 'tools']):
                                target_path = search_path
                                break
                            search_path = search_path.parent

                        if not target_path:
                            target_path = abs_path if abs_path.is_dir() else abs_path.parent

                        self.query_one(
                            "#workspace-panel",
                            WorkspacePanel).update_vulnerabilities_path(target_path)
                    else:
                        self.query_one(
                            "#workspace-panel",
                            WorkspacePanel).clear_vulnerabilities_view()
            except Exception:
                pass

            def _read_file_sync() -> str:
                try:
                    if file_path.stat().st_size > 50_000:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            return f.read(50_000) + "\n... [TRUNCATED CONTEXT] ..."
                    return file_path.read_text(encoding="utf-8", errors="replace")
                except Exception as exc:
                    return f"Error reading file: {exc}"

            import asyncio
            content = await asyncio.to_thread(_read_file_sync)

            self.active_file_path = file_path
            self.active_file_content = content

            chat.add_system_message(
                f"File context loaded: [bold green]{file_path.name}[/bold green]. "
                "Use 'this file' or 'the loaded file' in your next prompt."
            )

            self._open_file_preview(str(file_path))

        except Exception as e:
            chat.add_error_message(f"Error reading file for context: {e}")
            self.active_file_path = None
            self.active_file_content = None

    def on_workspace_tree_directory_selected(
            self, event: WorkspaceTree.DirectorySelected) -> None:
        if event.control is not None and event.control.id != "workspace-tree":
            return

        self.current_context_path = event.path
        chat = self.query_one(ChatPanel)
        chat.add_system_message(f"Context set to: {event.path}")

        try:
            workspace_root = get_workspace_root().resolve()
            abs_path = event.path.resolve()

            if workspace_root in abs_path.parents or abs_path == workspace_root:
                if abs_path == workspace_root:
                    self.query_one(
                        "#workspace-panel",
                        WorkspacePanel).clear_vulnerabilities_view()
                    return

                rel = abs_path.relative_to(workspace_root)
                if len(rel.parts) >= 1:
                    search_path = abs_path
                    target_path = None

                    while search_path != workspace_root:
                        if any((search_path / folder).is_dir()
                               for folder in ['vulnerabilities', 'output', 'command', 'tools']):
                            target_path = search_path
                            break
                        search_path = search_path.parent

                    if not target_path:
                        target_path = abs_path if abs_path.is_dir() else abs_path.parent

                    self.query_one(
                        "#workspace-panel",
                        WorkspacePanel).update_vulnerabilities_path(target_path)
        except Exception:
            pass

    async def _poll_services(self) -> None:
        status_bar = self.query_one("#status-bar", StatusBar)
        chat = self.query_one("#chat-panel", ChatPanel)

        max_retries = 40
        connected = False
        proxy_reachable = False

        for attempt in range(max_retries):
            try:
                resp = await self._http.get("/api/status", timeout=3.0)
                if resp.status_code == 200:
                    data = resp.json()
                    ollama_ok = data.get("ollama", {}).get("connected", False)
                    docker_ok = data.get("docker", {}).get("connected", False)
                    model = data.get("ollama", {}).get("model", "—")
                    agent_stats = data.get("agent", {})
                    tool_counts = agent_stats.get("tool_counts", {})
                    exec_used = tool_counts.get("exec", 0)
                    subagents = tool_counts.get("subagents", 0)
                    token_info = agent_stats.get("token_usage", {})
                    tokens_used = token_info.get("cumulative", token_info.get("used", 0))
                    tokens_limit = token_info.get("limit", 65536)
                    skills_info = agent_stats.get("skills_used", [])
                    caido_data = agent_stats.get("caido", {})

                    proxy_reachable = True
                    status_bar.set_status(
                        ollama="online" if ollama_ok else "offline",
                        ollama_degraded=self._should_show_ollama_degraded(ollama_ok),
                        docker="online" if docker_ok else "offline",
                        model=model,
                        tokens=tokens_used,
                        token_limit=tokens_limit,
                        exec_used=exec_used,
                        subagents=subagents,
                        skills=skills_info,
                        caido_active=caido_data.get("active", False),
                        caido_findings=caido_data.get("findings_count", 0),
                    )

                    if ollama_ok and docker_ok:
                        connected = True
                        chat.add_assistant_message(
                            f"✅ Connected — **{model}** ready with Docker sandbox"
                        )
                        try:
                            sess_resp = await self._http.get("/api/session/current", timeout=3.0)
                            if sess_resp.status_code == 200:
                                sess = sess_resp.json().get("session")
                                # Only show session banner for explicit resume mode.
                                if sess and self._session_id and sess.get("session_id") == self._session_id:
                                    sid = sess.get("session_id", "?")
                                    target = sess.get("target") or "no target yet"
                                    scans = sess.get("scan_count", 0)
                                    chat.add_system_message(
                                        f"🔖 Active session: `{sid}` — {target}"
                                        + (f" ({scans} scans)" if scans else "")
                                    )
                        except Exception:
                            pass

                        await self._restore_history_if_resumed(chat)
                        break
            except Exception:
                pass

            await asyncio.sleep(1.0)

        if not connected:
            if proxy_reachable:
                data = {}
                try:
                    resp = await self._http.get("/api/status", timeout=3.0)
                    data = resp.json()
                except Exception:
                    pass
                ollama_ok = data.get("ollama", {}).get("connected", False)
                docker_ok = data.get("docker", {}).get("connected", False)
                issues = []
                if not ollama_ok:
                    issues.append("Ollama offline (check `ollama serve`)")
                if not docker_ok:
                    issues.append(
                        "Docker sandbox not running (check Docker daemon)")
                detail = " · ".join(issues) if issues else "services not ready"
                chat.add_error_message(
                    f"⚠️ Proxy is running but services are not ready: {detail}\n"
                    "Use `/status` for details."
                )
            else:
                chat.add_error_message(
                    "Cannot reach proxy server. Run `airecon proxy` "
                    "in a separate terminal, then type `/status` to retry."
                )
            return

        while True:
            await asyncio.sleep(5.0)

            try:
                self.query_one("#workspace-panel", WorkspacePanel).reload()
            except Exception:
                pass

            try:
                resp = await self._http.get("/api/status", timeout=3.0)
                if resp.status_code == 200:
                    data = resp.json()
                    ollama_ok = data.get("ollama", {}).get("connected", False)
                    docker_ok = data.get("docker", {}).get("connected", False)
                    model = data.get("ollama", {}).get("model", "—")
                    tool_counts = data.get("agent", {}).get("tool_counts", {})
                    exec_used = tool_counts.get("exec", 0)
                    subagents = tool_counts.get("subagents", 0) + self._file_agents_running
                    token_info = data.get("agent", {}).get("token_usage", {})
                    tokens_used = token_info.get("cumulative", token_info.get("used", 0))
                    tokens_limit = token_info.get("limit", 65536)
                    skills_info = data.get("agent", {}).get("skills_used", [])
                    caido_data = data.get("agent", {}).get("caido", {})
                    caido_active = caido_data.get("active", False)
                    caido_findings = caido_data.get("findings_count", 0)

                    self.query_one("#status-bar", StatusBar).set_status(
                        ollama="online" if ollama_ok else "offline",
                        ollama_degraded=self._should_show_ollama_degraded(ollama_ok),
                        docker="online" if docker_ok else "offline",
                        model=model,
                        tokens=tokens_used,
                        token_limit=tokens_limit,
                        exec_used=exec_used,
                        subagents=subagents,
                        skills=skills_info,
                        caido_active=caido_active,
                        caido_findings=caido_findings,
                    )
            except Exception:
                pass

    async def _check_services(self, verbose: bool = False) -> None:
        status_bar = self.query_one("#status-bar", StatusBar)
        chat = self.query_one("#chat-panel", ChatPanel)
        try:
            resp = await self._http.get("/api/status", timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                ollama = data.get("ollama", {})
                docker = data.get("docker", {})
                agent = data.get("agent", {})

                ollama_ok = ollama.get("connected", False)
                docker_ok = docker.get("connected", False)
                model = ollama.get("model", "—")

                tool_counts = agent.get("tool_counts", {})
                exec_used = tool_counts.get("exec", 0)
                subagents = tool_counts.get("subagents", 0)
                caido = agent.get("caido", {})
                caido_active = caido.get("active", False)
                caido_findings = caido.get("findings_count", 0)

                status_bar.set_status(
                    ollama="online" if ollama_ok else "offline",
                    ollama_degraded=self._should_show_ollama_degraded(ollama_ok),
                    docker="online" if docker_ok else "offline",
                    model=model,
                    exec_used=exec_used,
                    subagents=subagents,
                    caido_active=caido_active,
                    caido_findings=caido_findings,
                )

                if verbose:
                    status_md = f"""## 🟢 AIRecon Status Report

- **Ollama**: {'✅ Online' if ollama_ok else '❌ Offline'}
  - URL: `{ollama.get("url", "Unknown")}`
  - Model: `{model}`
- **Docker Sandbox**: {'✅ Running' if docker_ok else '❌ Stopped'}
  - Image: `{docker.get("image", "airecon-sandbox")}`

- **Messages**: {agent.get("message_count", 0)}
- **Commands Executed**: **{exec_used}**
"""
                    chat.add_assistant_message(status_md)
                else:
                    pass

            else:
                status_bar.set_status(ollama="offline", docker="offline")
                if verbose:
                    chat.add_error_message(
                        f"Status check failed: HTTP {resp.status_code}"
                    )
        except Exception as e:
            status_bar.set_status(ollama="offline", docker="offline")
            if verbose:
                chat.add_error_message(f"Status check error: {e}")

    async def _docker_health_monitor(self) -> None:
        from airecon.tui.startup import get_proxy_fatal_error, is_proxy_alive

        _DOCKER_FAILURE_THRESHOLD = 3
        _HTTP_WARN_THRESHOLD = 5
        _HTTP_HARD_THRESHOLD = 18
        _HTTP_TIMEOUT_IDLE = 12.0
        _HTTP_TIMEOUT_ACTIVE = 25.0
        _SSE_RECENT_WINDOW = 120.0

        consecutive_docker_failures = 0
        consecutive_http_failures = 0
        _warned_recovering = False

        while self._processing:
            try:
                await asyncio.sleep(5.0)

                if not self._processing:
                    break

                _status_timeout = _HTTP_TIMEOUT_ACTIVE if self._processing else _HTTP_TIMEOUT_IDLE
                resp = await self._http.get("/api/status", timeout=_status_timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    docker_ok = data.get("docker", {}).get("connected", False)

                    if not docker_ok:
                        consecutive_docker_failures += 1
                        if consecutive_docker_failures >= _DOCKER_FAILURE_THRESHOLD:
                            logger.error(
                                "Docker sandbox disconnected for %d consecutive checks — declaring dead",
                                consecutive_docker_failures,
                            )
                            chat = self.query_one("#chat-panel", ChatPanel)
                            if chat:
                                chat.add_error_message(
                                    "⚠️ **Docker Sandbox Disconnected!**\n\n"
                                    "The sandbox container has crashed or stopped. "
                                    "Recon cannot continue.\n\n"
                                    "**What happened:**\n"
                                    "- Container may have crashed due to resource limits\n"
                                    "- Docker daemon may have stopped\n"
                                    "- Container was manually stopped\n\n"
                                    "**Next steps:**\n"
                                    "1. Check Docker: `docker ps -a | grep airecon`\n"
                                    "2. Restart container or AIRecon\n"
                                    "3. Review logs: `docker logs airecon-sandbox-active`"
                                )
                            self._processing = False
                            self._hide_recon_spinner()
                            try:
                                chat.end_streaming()
                                chat.end_thinking()
                            except Exception:
                                pass
                            break
                        else:
                            logger.warning(
                                "Docker reported disconnected (check %d/%d) — waiting for auto-recovery",
                                consecutive_docker_failures,
                                _DOCKER_FAILURE_THRESHOLD,
                            )
                    else:
                        if consecutive_docker_failures > 0:
                            logger.info(
                                "Docker reconnected after %d failed check(s)",
                                consecutive_docker_failures,
                            )
                        consecutive_docker_failures = 0

                    if consecutive_http_failures > 0:
                        logger.info(
                            "Proxy recovered after %d failed check(s)",
                            consecutive_http_failures,
                        )
                        _warned_recovering = False
                    consecutive_http_failures = 0
                else:
                    sse_age = time.monotonic() - self._last_sse_activity
                    _EXTENDED_SSE_WINDOW = 180.0 if self._processing else _SSE_RECENT_WINDOW
                    if sse_age < _EXTENDED_SSE_WINDOW and is_proxy_alive():
                        logger.debug(
                            "Status endpoint returned HTTP %s but SSE is recent (%.0fs) and proxy thread is alive — treating as transient",
                            resp.status_code,
                            sse_age,
                        )
                        consecutive_http_failures = 0
                    else:
                        consecutive_http_failures += 1

            except httpx.ConnectError:
                sse_age = time.monotonic() - self._last_sse_activity

                _EXTENDED_SSE_WINDOW = 180.0 if self._processing else _SSE_RECENT_WINDOW

                if sse_age < _EXTENDED_SSE_WINDOW and is_proxy_alive():
                    logger.debug(
                        "Proxy port closed (ConnectError) but thread alive + SSE %.0fs ago — "
                        "likely mid-restart or event loop saturation, not counting as failure",
                        sse_age,
                    )
                    consecutive_http_failures = 0
                    consecutive_docker_failures = 0
                else:
                    consecutive_http_failures += 1
            except httpx.TimeoutException:
                sse_age = time.monotonic() - self._last_sse_activity

                _EXTENDED_SSE_WINDOW = 180.0 if self._processing else _SSE_RECENT_WINDOW

                if sse_age < _EXTENDED_SSE_WINDOW:
                    if consecutive_http_failures > 0 and consecutive_http_failures % 3 == 0:
                        logger.debug(
                            "Health check timeout (SSE age=%.0fs) — event loop saturated, skipping (count=%d)",
                            sse_age, consecutive_http_failures,
                        )
                    consecutive_http_failures = 0
                    consecutive_docker_failures = 0
                else:
                    logger.warning(
                        "Health check timeout AND SSE inactive (%.0fs) — proxy may be truly stuck",
                        sse_age,
                    )
                    consecutive_http_failures += 1
            except Exception as e:
                logger.debug("Health check error: %s", e)
                consecutive_http_failures += 1

            if consecutive_http_failures < _HTTP_WARN_THRESHOLD:
                continue

            proxy_thread_alive = is_proxy_alive()
            proxy_fatal = get_proxy_fatal_error()
            sse_age = time.monotonic() - self._last_sse_activity

            if (
                consecutive_http_failures == _HTTP_WARN_THRESHOLD
                and not _warned_recovering
            ):
                _warned_recovering = True
                if proxy_thread_alive and not proxy_fatal:
                    logger.warning(
                        "Proxy unreachable for %ds — thread alive, waiting for recovery "
                        "(SSE age=%.0fs)",
                        consecutive_http_failures * 5,
                        sse_age,
                    )
                    # Avoid false UI alarm while SSE is still active/recent.
                    if sse_age >= 180.0:
                        try:
                            chat = self.query_one("#chat-panel", ChatPanel)
                            if chat and self._processing:
                                chat.add_system_message(
                                    "Proxy temporarily unreachable; auto-recovery in progress (up to 90s)."
                                )
                        except Exception:
                            pass
                    continue

            if (
                not proxy_thread_alive
                or proxy_fatal
                or consecutive_http_failures >= _HTTP_HARD_THRESHOLD
            ):
                # If proxy thread is still alive and there is no fatal crash signal,
                # keep waiting longer before hard-abort. Under heavy LLM/tool load,
                # /api/status can timeout repeatedly while the SSE worker is still alive.
                if (
                    proxy_thread_alive
                    and not proxy_fatal
                    and self._processing
                    and consecutive_http_failures >= _HTTP_HARD_THRESHOLD
                ):
                    _MAX_STALE_SSE_GRACE = 240.0
                    if sse_age < _MAX_STALE_SSE_GRACE:
                        logger.warning(
                            "Proxy still unreachable for %ds but thread alive and no fatal error "
                            "(SSE age=%.0fs) — extending grace window",
                            consecutive_http_failures * 5,
                            sse_age,
                        )
                        continue

                    logger.error(
                        "Proxy thread alive but SSE stale for %.0fs (>=%.0fs) and /api/status unreachable — forcing abort",
                        sse_age,
                        _MAX_STALE_SSE_GRACE,
                    )

                logger.error(
                    "Proxy unreachable for %ds (thread_alive=%s, fatal=%r, SSE age=%.0fs) — aborting",
                    consecutive_http_failures * 5,
                    proxy_thread_alive,
                    proxy_fatal,
                    sse_age,
                )
                try:
                    chat = self.query_one("#chat-panel", ChatPanel)
                    if chat and self._processing:
                        _detail = proxy_fatal or "proxy thread stopped responding"
                        chat.add_error_message(
                            "⚠️ **Connection Lost!**\n\n"
                            f"Cannot reach AIRecon proxy: {_detail}\n\n"
                            "Please restart AIRecon."
                        )
                        self._processing = False
                except Exception:
                    pass
                break

    def _start_health_monitor(self) -> None:
        if not self._health_check_task:
            self._health_check_task = asyncio.create_task(
                self._docker_health_monitor(),
                name="docker-health-monitor"
            )
            logger.debug("Started Docker health monitor")

    def _stop_health_monitor(self) -> None:
        if self._health_check_task:
            self._health_check_task.cancel()
            self._health_check_task = None
            logger.debug("Stopped Docker health monitor")

    def on_tool_message_selected(self, message: ToolMessageSelected) -> None:
        logger.debug(f"App received selection: {message.output_file}")
        self._open_file_preview(message.output_file)

    def on_directory_tree_file_selected(
            self, event: DirectoryTree.FileSelected) -> None:
        self._open_file_preview(str(event.path))

    def _open_file_preview(self, file_path: str) -> None:
        try:
            p = Path(file_path)
            if not p.exists():
                p = Path.cwd() / file_path

            if p.exists():
                if p.is_dir():
                    return
                self.push_screen(
                    FilePreviewScreen(
                        str(p)), self.on_preview_result)
            else:
                self.query_one(ChatPanel).add_error_message(
                    f"File not found: {file_path}")
        except Exception as e:
            self.query_one(ChatPanel).add_error_message(
                f"Failed to open file: {e}")

    async def on_preview_result(self, result: Any) -> None:
        if isinstance(result, FilePreviewScreen.Submitted):
            abs_path = os.path.abspath(result.file_path)
            _abs = Path(abs_path)
            _cwd = Path(os.getcwd())
            display_path = (
                str(_abs.relative_to(_cwd))
                if _abs.is_relative_to(_cwd) else abs_path
            )

            chat = self.query_one(ChatPanel)
            chat.add_user_message(
                f"[FILE ANALYSIS: {display_path}]\n{result.user_prompt}"
            )
            chat.add_system_message(
                "[dim]Running as background sub-agent — main recon continues uninterrupted.[/dim]"
            )

            def _read_file_sync() -> str:
                try:
                    if _abs.stat().st_size > 100_000:
                        return _abs.read_text(errors="replace")[:100_000]
                    return _abs.read_text(errors="replace")
                except Exception as e:
                    return f"[Could not read file: {e}]"

            content = await asyncio.to_thread(_read_file_sync)

            self.run_worker(
                self._stream_file_analysis(abs_path, content, result.user_prompt)
            )

    def _clear_active_file_context(self) -> None:
        self.active_file_path = None
        self.active_file_content = None

    def on_command_input_at_path_changed(
            self, event: CommandInput.AtPathChanged) -> None:
        try:
            completer = self.query_one("#path-completer", PathCompleter)
            if event.fragment is None:
                completer.hide()
            else:
                completer.show_for(event.fragment)
        except Exception:
            pass

    def on_command_input_tab_pressed(
            self, event: CommandInput.TabPressed) -> None:
        try:
            slash_completer = self.query_one("#slash-completer", SlashCompleter)
            if slash_completer.display:
                cmd = slash_completer.get_first_command()
                if cmd:
                    cmd_input = self.query_one("#command-input", CommandInput)
                    cmd_input.do_slash_completion(cmd)
                    slash_completer.hide()
                return
        except Exception:
            pass

        try:
            completer = self.query_one("#path-completer", PathCompleter)
            if not completer.display:
                return
            path = completer.get_first_path()
            if not path:
                return
            cmd_input = self.query_one("#command-input", CommandInput)
            cmd_input.do_completion(path)
            if path.endswith("/"):
                completer.show_for(path)
            else:
                completer.hide()
        except Exception:
            pass

    def on_command_input_escape_completion(
            self, event: CommandInput.EscapeCompletion) -> None:
        try:
            slash_completer = self.query_one("#slash-completer", SlashCompleter)
            if slash_completer.display:
                slash_completer.hide()
        except Exception:
            pass
        try:
            completer = self.query_one("#path-completer", PathCompleter)
            if completer.display:
                completer.hide()
        except Exception:
            pass

    def on_command_input_slash_changed(
            self, event: CommandInput.SlashChanged) -> None:
        try:
            completer = self.query_one("#slash-completer", SlashCompleter)
            if event.fragment is None:
                completer.hide()
            else:
                completer.show_for(event.fragment)
        except Exception:
            pass

    def on_slash_completer_completed(
            self, event: SlashCompleter.Completed) -> None:
        try:
            cmd_input = self.query_one("#command-input", CommandInput)
            cmd_input.do_slash_completion(event.command)
            self.query_one("#slash-completer", SlashCompleter).hide()
            cmd_input.focus()
        except Exception:
            pass

    def on_path_completer_completed(
            self, event: PathCompleter.Completed) -> None:
        try:
            cmd_input = self.query_one("#command-input", CommandInput)
            cmd_input.do_completion(event.path)
            completer = self.query_one("#path-completer", PathCompleter)
            if event.path.endswith("/"):
                completer.show_for(event.path)
            else:
                completer.hide()
            cmd_input.focus()
        except Exception:
            pass

    async def on_command_input_submitted(
            self, message: CommandInput.Submitted) -> None:
        user_input = message.value.strip()
        if not user_input:
            return

        try:
            self.query_one("#slash-completer", SlashCompleter).hide()
        except Exception:
            pass
        try:
            self.query_one("#path-completer", PathCompleter).hide()
        except Exception:
            pass

        if user_input.startswith("/"):
            await self._handle_slash_command(user_input)
            return

        if self._processing:
            self.notify(
                "⏳ Agent is still working. Wait for it to finish.",
                severity="warning",
                timeout=3,
            )
            return

        chat = self.query_one("#chat-panel", ChatPanel)

        prompt = user_input
        if self.current_context_path:
            prompt = f"[CONTEXT: Focus on {self.current_context_path}]\n{user_input}"

        chat.add_user_message(user_input)

        chat.start_thinking()
        self._show_recon_spinner()

        self._chat_worker = self.run_worker(self._stream_chat_response(prompt))

    async def _stream_chat_response(
            self, prompt: str, inject_context: bool = True) -> None:
        logger.debug(f"Starting chat stream for prompt: {prompt[:50]}...")
        self._processing = True
        chat = self.query_one("#chat-panel", ChatPanel)

        self._start_health_monitor()

        try:

            if inject_context and self.active_file_content and self.active_file_path:
                file_ext = self.active_file_path.suffix.lower()
                file_path_str = str(self.active_file_path.resolve())

                file_context_message_parts = []

                if file_ext == ".json":
                    try:
                        parsed_content = json.loads(self.active_file_content)
                        if isinstance(parsed_content,
                                      dict) and "result" in parsed_content:
                            result_data = parsed_content["result"]
                            if isinstance(result_data,
                                          dict) and "stdout" in result_data:
                                stdout_content = result_data["stdout"].strip()
                                domains = [
                                    d.strip() for d in stdout_content.split("\n") if d.strip()]
                                count = len(domains)

                                file_context_message_parts.append(
                                    f"User loaded file: {file_path_str}\n"
                                    f"Type: Tool Output (JSON)\n"
                                    f"Content Summary: Contains {count} subdomains/targets.\n"
                                    f"Top 20 Targets: {', '.join(domains[:20])}...\n"
                                    f"INSTRUCTION: This file contains the target list. If the user asks to probe or scan these, use the file path '{file_path_str}' if the tool supports file input, or iterate through the high-value targets."
                                )
                            else:
                                file_context_message_parts.append(
                                    f"User loaded file: {file_path_str} (JSON Result). "
                                    f"Content snippet: {str(parsed_content)[:500]}..."
                                )
                        else:
                            file_context_message_parts.append(
                                f"User loaded file: {file_path_str} (JSON). Content snippet: {self.active_file_content[:500]}...")

                    except json.JSONDecodeError:
                        file_context_message_parts.append(
                            f"User loaded file: {file_path_str} (Raw Content). Snippet: {self.active_file_content[:500]}...")
                else:
                    file_context_message_parts.append(
                        f"User loaded file: {file_path_str}. Content snippet: {self.active_file_content[:500]}...")

                context_str = "\n".join(file_context_message_parts)
                prompt_with_context = f"[SYSTEM: ACTIVE FILE CONTEXT]\n{context_str}\n\n[USER PROMPT]\n{prompt}"

                _ctx_file_name = self.active_file_path.name if self.active_file_path else "file"
                self._clear_active_file_context()
                chat.add_system_message(
                    f"[dim]Sent context from {_ctx_file_name}[/dim]")
            else:
                prompt_with_context = prompt

            # Preflight with short retries to absorb transient proxy restarts.
            # This prevents immediate hard-fail when proxy socket is briefly unavailable.
            _preflight_ok = False
            for _attempt in range(3):
                try:
                    _status_resp = await self._http.get("/api/status", timeout=2.5)
                    if _status_resp.status_code == 200:
                        _preflight_ok = True
                        break
                except Exception as _e:
                    logger.debug(
                        "Chat preflight attempt %d failed: %s",
                        _attempt + 1,
                        _e,
                    )

                if _attempt < 2:
                    await asyncio.sleep(0.4 * (2 ** _attempt))

            if not _preflight_ok:
                logger.warning(
                    "Chat preflight could not confirm proxy readiness after retries; attempting stream anyway"
                )

            logger.debug(f"Connecting to proxy at {self.proxy_url}/api/chat")
            async with self._http.stream(
                "POST",
                "/api/chat",
                json={"message": prompt_with_context, "stream": True},
                headers={"Accept": "text/event-stream"},
                timeout=httpx.Timeout(30.0, read=None),
            ) as resp:
                logger.debug(f"Proxy response status: {resp.status_code}")

                if resp.status_code != 200:
                    body = await resp.aread()
                    error_msg = f"Proxy error ({resp.status_code}): {body.decode()[:500]}"
                    logger.error(error_msg)
                    chat.add_error_message(error_msg)
                    return

                streaming_started = False
                logger.debug("Start reading SSE stream...")

                async for line in resp.aiter_lines():
                    if not line:
                        continue

                    if line.startswith("event:"):
                        continue

                    if line.startswith("data: "):
                        data_str = line[6:]
                    elif line.startswith("data:"):
                        data_str = line[5:]
                    else:
                        continue

                    try:
                        event = json.loads(data_str)
                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Failed to parse SSE JSON: {data_str[:100]} - {e}")
                        continue

                    self._last_sse_activity = time.monotonic()

                    event_type = str(event.get("type", "") or "").strip()
                    if not event_type:
                        logger.debug("Received SSE payload without event type; ignoring")
                        continue

                    logger.debug(f"Received event: {event_type}")

                    if event_type == "text":
                        content = event.get("content", "")
                        if content:
                            if self._is_ollama_recovery_marker(content):
                                self._mark_ollama_degraded(content[:120])
                            if not streaming_started:
                                chat.start_streaming()
                                streaming_started = True
                            chat.append_to_stream(content)
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "thinking":
                        content = event.get("content", "")
                        if content:
                            chat.append_to_thinking(content)
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "tool_start":
                        tool_id = str(event.get("tool_id", "0"))
                        tool_name = event.get("tool", "unknown")
                        arguments = event.get("arguments", {})
                        logger.info(
                            f"Tool Start: {tool_name} args={arguments}")
                        chat.end_streaming()
                        chat.end_thinking()
                        streaming_started = False
                        chat.add_tool_start(tool_id, tool_name, arguments)

                    elif event_type == "tool_output":
                        tool_id = str(event.get("tool_id", "0"))
                        content = event.get("content", "")
                        if content:
                            _now = time.monotonic()
                            chat.append_tool_output(tool_id, content)
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "tool_end":
                        tool_id = str(event.get("tool_id", "0"))
                        success = event.get("success", False)
                        duration = event.get("duration", 0.0)
                        output_file = event.get("output_file", "")
                        result_preview = event.get("result_preview", "")
                        tool_counts = event.get("tool_counts", {}) or {}
                        token_info = event.get("token_usage", {}) or {}
                        skills_info = event.get("skills_used", []) or []
                        caido_data = event.get("caido", {}) or {}

                        logger.info(
                            f"Tool End: success={success} duration={duration}")

                        if not hasattr(chat, "_active_tools"):
                            chat._active_tools = {}
                        captured_tool_msg = chat._active_tools.pop(
                            tool_id, None)

                        def update_ui_on_tool_end(
                            _msg=captured_tool_msg,
                            _s=success, _d=duration, _r=result_preview, _o=output_file,
                            _tc=tool_counts,
                            _ti=token_info,
                            _sk=skills_info,
                            _cd=caido_data,
                        ):
                            if _msg:
                                _msg.update_result(_s, _d, _r, _o)
                            chat.scroll_end(animate=False)

                            try:
                                status_bar = self.query_one(
                                    "#status-bar", StatusBar)
                                status_update_kwargs = {}

                                if _tc:
                                    status_update_kwargs["exec_used"] = _tc.get(
                                        "exec", 0)
                                    status_update_kwargs["subagents"] = _tc.get(
                                        "subagents", 0)

                                if _ti:
                                    status_update_kwargs["tokens"] = _ti.get(
                                        "cumulative", _ti.get("used", 0))
                                    status_update_kwargs["token_limit"] = _ti.get(
                                        "limit", 65536)

                                if _sk:
                                    status_update_kwargs["skills"] = _sk

                                if _cd:
                                    status_update_kwargs["caido_active"] = _cd.get(
                                        "active", False)
                                    status_update_kwargs["caido_findings"] = _cd.get(
                                        "findings_count", 0)

                                if status_update_kwargs:
                                    status_bar.set_status(
                                        **status_update_kwargs)
                            except Exception:
                                pass

                            try:
                                import time as _time
                                now = _time.monotonic()
                                if now - self._last_workspace_reload >= 10.0:
                                    self._last_workspace_reload = now
                                    self.query_one(
                                        "#workspace-panel", WorkspacePanel).reload()
                            except Exception:
                                pass

                        self.call_later(update_ui_on_tool_end)

                    elif event_type == "error":
                        error_msg = event.get("message", "Unknown error")
                        if self._is_ollama_recovery_marker(str(error_msg)):
                            self._mark_ollama_degraded(str(error_msg)[:120])
                        logger.error(f"Agent Error Event: {error_msg}")

                        def show_error_safely():
                            chat.add_error_message(error_msg)

                        self.call_later(show_error_safely)

                        logger.error(f"Error event received: {error_msg}")

                    elif event_type == "user_input_required":
                        _req_id = event.get("request_id", "")
                        _prompt = event.get("prompt", "Input required")
                        _inp_type = event.get("input_type", "text")
                        logger.info(
                            "user_input_required: id=%s type=%s", _req_id, _inp_type
                        )

                        async def _handle_user_input_modal(
                            req_id: str = _req_id,
                            inp_type: str = _inp_type,
                            prompt_txt: str = _prompt,
                        ) -> None:
                            value: str | None = await self.push_screen_wait(
                                UserInputModal(prompt_txt, inp_type)
                            )
                            cancelled = value is None
                            
                            # Retry logic with exponential backoff (max 3 attempts)
                            _submit_success = False
                            for _attempt in range(3):
                                try:
                                    resp = await self._http.post(
                                        "/api/user-input",
                                        json={
                                            "request_id": req_id,
                                            "value": value or "",
                                            "cancelled": cancelled,
                                        },
                                    )
                                    if resp.status_code == 200:
                                        _submit_success = True
                                        break
                                    logger.warning(
                                        "user-input submit attempt %d failed: %s",
                                        _attempt + 1, resp.text
                                    )
                                except Exception as _e:
                                    logger.error(
                                        "user-input submit attempt %d failed: %s",
                                        _attempt + 1, _e
                                    )
                                
                                # Exponential backoff: 0.5s, 1s, 2s
                                if _attempt < 2:
                                    await asyncio.sleep(0.5 * (2 ** _attempt))
                            
                            if not _submit_success:
                                logger.error(
                                    "user-input submit failed after 3 attempts. "
                                    "The agent may timeout waiting for response."
                                )

                        self.call_later(_handle_user_input_modal)

                    elif event_type == "done":
                        logger.debug("Stream done")
                        if streaming_started:
                            chat.end_streaming()
                        break

            if streaming_started:
                chat.end_streaming()

        except httpx.ConnectError as e:
            msg = f"Cannot connect to proxy: {e}"
            logger.error(msg)
            chat.add_error_message(
                "Cannot connect to proxy. Make sure AIRecon proxy is running on "
                f"`{self.proxy_url}`"
            )
        except httpx.ReadTimeout as e:
            msg = f"Read timeout: {e}"
            logger.error(msg)
            chat.add_error_message(
                "Request timed out. The operation took too long.")
        except Exception as e:
            msg = f"Unexpected error in stream worker: {e}"
            logger.exception(msg)
            chat.add_error_message(f"Error: {str(e)}")
        finally:
            self._processing = False
            self._stop_health_monitor()
            try:
                chat.end_streaming()
                chat.end_thinking()
            except Exception:
                pass
            if not self._file_agents_running:
                self._hide_recon_spinner()
            logger.debug("Stream worker finished")

    async def _stream_file_analysis(
        self, file_path: str, content: str, task: str
    ) -> None:
        chat = self.query_one("#chat-panel", ChatPanel)
        agent_id = str(uuid.uuid4())
        success = True

        chat.add_subagent_block(agent_id, task)
        self._file_agents_running += 1
        self._show_recon_spinner()

        self._start_health_monitor()

        try:
            self.query_one("#status-bar", StatusBar).subagents_spawned += 1
        except Exception:
            pass

        try:
            async with self._http.stream(
                "POST",
                "/api/file-analyze",
                json={
                    "file_path": file_path,
                    "file_content": content,
                    "task": task,
                    "max_iterations": 30,
                },
                headers={"Accept": "text/event-stream"},
                timeout=None,
            ) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    chat.add_error_message(
                        f"File analysis error ({resp.status_code}): "
                        f"{body.decode()[:300]}"
                    )
                    success = False
                    return

                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        data_str = line[6:]
                    elif line.startswith("data:"):
                        data_str = line[5:]
                    else:
                        continue

                    try:
                        event = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

                    event_type = event.get("type", "")

                    if event_type == "text":
                        text = event.get("content", "")
                        if text:
                            chat.subagent_append_text(agent_id, text)
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "tool_start":
                        tool_id = str(event.get("tool_id", "0"))
                        tool_name = event.get("tool", "unknown")
                        arguments = event.get("arguments", {})
                        chat.subagent_add_tool(agent_id, tool_id, tool_name, arguments)

                    elif event_type == "tool_output":
                        tool_id = str(event.get("tool_id", "0"))
                        output = event.get("content", "")
                        if output:
                            chat.subagent_append_tool_output(agent_id, tool_id, output)

                    elif event_type == "tool_end":
                        tool_id = str(event.get("tool_id", "0"))
                        chat.subagent_update_tool_end(
                            agent_id, tool_id,
                            event.get("success", False),
                            event.get("duration", 0.0),
                            event.get("result_preview", ""),
                            event.get("output_file", ""),
                        )

                    elif event_type in ("done", "complete"):
                        break

        except Exception as e:
            logger.exception("File analysis stream error: %s", e)
            success = False
            chat.add_error_message(f"File analysis failed: {e}")
        finally:
            if self._file_agents_running <= 1 and not self._processing:
                self._stop_health_monitor()
            chat.subagent_finish(agent_id, success)
            self._file_agents_running = max(0, self._file_agents_running - 1)
            if not self._processing and not self._file_agents_running:
                self._hide_recon_spinner()
            try:
                status_bar = self.query_one("#status-bar", StatusBar)
                status_bar.subagents_spawned = max(
                    0, status_bar.subagents_spawned - 1
                )
            except Exception:
                pass

    async def _refresh_mcp_until_ready(self, show_tools: bool = False) -> None:
        chat = self.query_one("#chat-panel", ChatPanel)
        for _ in range(40):
            await asyncio.sleep(2.0)
            try:
                resp = await self._http.get("/api/mcp/list", timeout=8.0)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                servers = data.get("servers", [])
                init_count = int(data.get("initializing", 0) or 0)
                if init_count > 0:
                    continue

                lines: list[str] = [f"MCP Servers ({len(servers)})", "", "Configured MCP servers:"]
                any_ready = False
                for s in servers:
                    name = s.get("name", "?")
                    status = str(s.get("status") or "unknown")
                    tool_count = s.get("tool_count")
                    tools = s.get("tools") or []
                    tool_error = s.get("tool_error")
                    if status == "ready":
                        any_ready = True
                        lines.append("")
                        lines.append(f"🟢 {name} - Ready ({tool_count or 0} tools)")
                        if show_tools and tools:
                            lines.append("  Tools:")
                            for t in tools:
                                lines.append(f"  - {t}")
                    elif status == "error":
                        lines.append("")
                        lines.append(f"🔴 {name} - Error ({tool_error or 'unknown error'})")

                if any_ready:
                    chat.add_assistant_message("\n".join(lines))
                return
            except Exception:
                continue

    async def _handle_slash_command(self, cmd: str) -> None:
        chat = self.query_one("#chat-panel", ChatPanel)

        if cmd in ("/help", "/h"):
            chat.add_assistant_message(
                "AIRecon Commands\n\n"
                "- /help                 Show this help\n"
                "- /info                 Show AIRecon information\n"
                "- /status               Check service status\n"
                "- /tools                List available tools\n"
                "- /skills               Show AI skills\n"
                "- /mcp                  Manage MCP servers\n"
                "- /reset                Reset conversation\n"
                "- /clear                Clear chat display\n\n"
                "Note: For authenticated MCP endpoint, use auth:user/pass or auth:apikey:<token> after URL."
            )
        elif cmd == "/status":
            await self._check_services(verbose=True)
        elif cmd == "/skills":
            try:
                resp = await self._http.get("/api/skills")
                if resp.status_code == 200:
                    data = resp.json()
                    skills = data.get("skills", [])

                    from collections import Counter
                    cat_counts: Counter = Counter(
                        s.get("category", "uncategorized") for s in skills
                    )
                    lines = [f"AI Skills & Capabilities — {len(skills)} skills loaded\n"]
                    for cat, count in sorted(cat_counts.items()):
                        lines.append(f"  {cat:<22} {count} skills")
                    lines.append(
                        "\nSkills are auto-loaded per phase. "
                        "Active skills shown in status bar."
                    )
                    chat.add_assistant_message("\n".join(lines))
                else:
                    chat.add_error_message("Failed to fetch skills.")
            except Exception as e:
                chat.add_error_message(f"Error: {e}")
            self._processing = False

        elif cmd.startswith("/mcp"):
            parts = cmd.split()

            if len(parts) == 1 or (len(parts) >= 2 and parts[1] in {"help", "-h", "--help"}):
                chat.add_assistant_message(
                    "MCP command usage:\n"
                    "- /mcp add http://mcp_url auth:user/pass|auth:apikey:<token> [name]\n"
                    "- /mcp list\n"
                    "- /mcp list <name>\n"
                    "- /mcp enable <name>\n"
                    "- /mcp disable <name>"
                )
                self._processing = False
                return

            sub = parts[1] if len(parts) >= 2 else "help"

            if sub == "list":
                show_tools = "--tools" in parts or "-v" in parts
                if len(parts) >= 3 and not parts[2].startswith("-"):
                    target_name = parts[2].strip()
                    try:
                        resp = await self._http.get(f"/api/mcp/tools/{target_name}", timeout=30.0)
                        if resp.status_code == 200:
                            data = resp.json()
                            tools = data.get("tools", [])
                            total_tools = data.get("total_tools", 0)
                            truncated = bool(data.get("truncated", False))
                            # Limit display to first 10 tools to avoid overwhelming context
                            display_tools = tools[:15]
                            lines = [f"MCP Tools: {target_name}"]
                            if truncated:
                                lines.append(f"Showing {len(display_tools)} of {total_tools} tools")
                            else:
                                lines.append(f"Total tools: {total_tools}")
                            lines.append("")
                            for t in display_tools:
                                tool_name = t.get("name", "?") if isinstance(t, dict) else str(t)
                                lines.append(f"- {tool_name}")
                            if truncated and len(tools) > 15:
                                rest_count = len(tools) - 15
                                lines.append(f"... {rest_count} more tools omitted. Use `action='search_tools'` in mcp_* tool with a keyword to find specific tools.")
                            chat.add_assistant_message("\n".join(lines))
                        else:
                            chat.add_error_message(f"MCP list {target_name} failed ({resp.status_code}): {resp.text[:300]}")
                    except Exception as e:
                        chat.add_error_message(f"MCP list {target_name} failed: {e}")
                    self._processing = False
                    return

                try:
                    resp = await self._http.get("/api/mcp/list", timeout=8.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        servers = data.get("servers", [])
                        init_count = int(data.get("initializing", 0) or 0)
                        if not servers:
                            chat.add_assistant_message(
                                "MCP: no servers are configured yet.\n"
                                "Use `/mcp add http://mcp_url_sse auth:user/pass|auth:apikey:<token> [name]`."
                            )
                        else:
                            lines: list[str] = [f"MCP Servers ({len(servers)})\n"]
                            if init_count > 0:
                                lines.append(f"⏳ MCP servers are starting up ({init_count} initializing)...")
                                lines.append("Note: First startup may take longer. Tool availability will update automatically.\n")

                            lines.append("Configured MCP servers:")
                            for s in servers:
                                name = s.get("name", "?")
                                status = str(s.get("status") or "initializing")
                                enabled = bool(s.get("enabled", True))
                                tool_count = s.get("tool_count") or 0
                                total_tools = s.get("total_tools")
                                tools = s.get("tools") or []
                                tool_error = s.get("tool_error")

                                if total_tools is not None and total_tools > 0:
                                    display_text = f"{total_tools}"
                                    if total_tools > tool_count:
                                        display_text = f"{total_tools}"
                                    else:
                                        display_text = f"{total_tools}"
                                else:
                                    display_text = f"{tool_count}"

                                if not enabled:
                                    lines.append(f"⚪ {name} - Disabled")
                                elif status == "ready":
                                    lines.append(f"🟢 {name} - Ready ({display_text} tools)")
                                    if show_tools and tools:
                                        lines.append("  Tools:")
                                        for t in tools:
                                            lines.append(f"  - {t}")
                                elif status == "error":
                                    lines.append(f"🔴 {name} - Error ({tool_error or 'unknown error'})")
                                else:
                                    init_for = int(s.get("initializing_for") or 0)
                                    lines.append(f"🟡 {name} - Initializing... ({init_for}s)")

                            chat.add_assistant_message("\n".join(lines))

                            if init_count > 0:
                                self.run_worker(self._refresh_mcp_until_ready(show_tools=show_tools), exclusive=False)
                    else:
                        chat.add_error_message(f"MCP list failed ({resp.status_code}): {resp.text[:300]}")
                except Exception as e:
                    chat.add_error_message(
                        "MCP list request failed or timed out. "
                        f"Details: {e}"
                    )
                self._processing = False
                return

            if sub == "add" and len(parts) >= 3:
                mcp_url = parts[2].strip()
                mcp_name = None
                mcp_auth = None
                # Parse optional auth and name from remaining args
                for p in parts[3:]:
                    if p.startswith("auth:"):
                        # Handle auth:user/pass or auth:apikey:<token>
                        auth_val = p[len("auth:"):]
                        mcp_auth = auth_val
                    elif mcp_name is None:
                        mcp_name = p.strip()

                try:
                    resp = await self._http.post(
                        "/api/mcp/add",
                        json={"url": mcp_url, "auth": mcp_auth, "name": mcp_name},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        name = data.get("name", "?")
                        chat.add_assistant_message(
                            f"MCP server added: {name}\n"
                            "Use `/mcp enable <name>` or `/mcp disable <name>` to toggle.\n"
                            "Tool registry refreshed automatically."
                        )
                    else:
                        chat.add_error_message(f"MCP add failed ({resp.status_code}): {resp.text[:300]}")
                except Exception as e:
                    chat.add_error_message(f"Error MCP add: {e}")
                self._processing = False
                return

            if sub in {"enable", "disable"} and len(parts) >= 3:
                mcp_name = parts[2].strip()
                endpoint = "/api/mcp/enable" if sub == "enable" else "/api/mcp/disable"
                try:
                    resp = await self._http.post(endpoint, json={"name": mcp_name})
                    if resp.status_code == 200:
                        chat.add_assistant_message(f"MCP server '{mcp_name}' {sub}d successfully.")
                    else:
                        chat.add_error_message(f"MCP {sub} failed ({resp.status_code}): {resp.text[:300]}")
                except Exception as e:
                    chat.add_error_message(f"MCP {sub} failed: {e}")
                self._processing = False
                return

            chat.add_error_message(
                "Invalid /mcp format. Use:\n"
                "- /mcp add http://mcp_url auth:user/pass|auth:apikey:<token> [name]\n"
                "- /mcp list\n"
                "- /mcp list <name>\n"
                "- /mcp enable <name>\n"
                "- /mcp disable <name>"
            )
            self._processing = False

        elif cmd == "/tools":
            try:
                resp = await self._http.get("/api/tools")
                if resp.status_code == 200:
                    data = resp.json()
                    tools = data.get("tools", [])

                    lines = [f"Available Tools ({len(tools)})", ""]

                    for t in tools:
                        if "function" in t:
                            fn = t["function"]
                            name = str(fn.get("name", "?")).strip()
                            desc = str(fn.get("description", "")).strip()
                        else:
                            name = str(t.get("name", "?")).strip()
                            desc = str(t.get("description", "")).strip()

                        desc = desc.split("\n")[0].strip()
                        if len(desc) > 100:
                            desc = desc[:97].rstrip() + "..."
                        lines.append(f"- {name}: {desc or '-'}")

                    chat.add_assistant_message("\n".join(lines), markup=False)
                else:
                    chat.add_error_message("Failed to fetch tools")
            except Exception as e:
                chat.add_error_message(f"Error: {e}")
            self._processing = False

        elif cmd == "/info":
            info_text = """## ℹ️ AIRecon Information

**Key Bindings:**
- `ESC`: Stop current generation/thinking.
- `Ctrl+C`: Quit the application.
- `Ctrl+L`: Clear chat history.
- `Ctrl+R`: Reset conversation (clears context).
- `PgUp`/`PgDn`: Scroll chat.

**Commands:**
- `/help`: Show this help message.
- `/info`: Show AIRecon information.
- `/status`: Check service status.
- `/tools`: List available tools.
- `/skills`: Show AI skills.
- `/mcp`: Manage MCP servers.
- `/reset`: Reset conversation.
- `/clear`: Clear chat history.

**Tips:**
- You can ask the AI to run scans, search the web, or browse pages.
- Click a file in the workspace panel to load it as context for your next prompt."""
            chat.add_assistant_message(info_text)
            self._processing = False

        elif cmd == "/reset":
            await self.action_reset()
        elif cmd == "/clear":
            self.action_clear()
        else:
            chat.add_error_message(
                f"Unknown command: `{cmd}`. Type `/help` for available commands.")

    def action_clear(self) -> None:
        self.query_one("#chat-panel", ChatPanel).clear_messages()

    async def action_reset(self) -> None:
        chat = self.query_one("#chat-panel", ChatPanel)
        workspace = self.query_one("#workspace-panel", WorkspacePanel)

        try:
            await self._http.post("/api/reset")
            chat.clear_messages()
            workspace.reload()
            chat.add_assistant_message(
                "Conversation reset. Ready for a new session.")
            self._clear_active_file_context()
        except Exception as e:
            chat.add_error_message(f"Reset failed: {e}")

    async def action_cancel_generation(self) -> None:
        if self._chat_worker and self._chat_worker.is_running:
            self._chat_worker.cancel()

        self._processing = False

        chat = self.query_one("#chat-panel", ChatPanel)
        chat.add_system_message(
            "🛑 User stopped progress (killing running tools, agent stays active)...")
        self.notify("Tools stopped - agent ready for next command.", severity="information")

        chat.end_streaming()
        chat.end_thinking()

        try:
            await self._http.post("/api/stop", timeout=2.0)
        except Exception as e:
            logger.error(f"Failed to send stop signal: {e}")

    def action_request_quit(self) -> None:
        def _on_dismiss(confirmed: bool | None) -> None:
            if confirmed:
                self.run_worker(self.action_quit(), exclusive=True)
        self.push_screen(QuitConfirmScreen(), _on_dismiss)

    async def action_quit(self) -> None:
        try:
            await self._http.post("/api/stop", timeout=2.0)
        except Exception:
            pass

        if self._status_task and not self._status_task.done():
            self._status_task.cancel()

        try:
            import json
            import subprocess

            from airecon.proxy.config import get_config

            cfg = get_config()
            ollama_url = cfg.ollama_url.rstrip("/")
            model = cfg.ollama_model

            cmd = [
                "curl", "-s", "-X", "POST", f"{ollama_url}/api/generate",
                "-d", json.dumps({"model": model, "keep_alive": 0})
            ]

            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2)

        except Exception:
            pass

        try:
            await self._http.aclose()
        except Exception:
            pass

        self.exit()

    async def _hide_copy_toast_after_delay(self, seconds: float = 1.2) -> None:
        await asyncio.sleep(seconds)
        try:
            self.query_one("#copy-toast-wrap", Container).display = False
        except Exception:
            pass

    def _show_copy_toast(self, message: str = "Copied to clipboard") -> None:
        try:
            wrap = self.query_one("#copy-toast-wrap", Container)
            msg = self.query_one("#copy-toast-msg", Static)
            msg.update(message)
            wrap.display = True
            if self._copy_toast_task and not self._copy_toast_task.done():
                self._copy_toast_task.cancel()
            self._copy_toast_task = asyncio.create_task(self._hide_copy_toast_after_delay(1.2))
        except Exception:
            pass

    def copy_to_clipboard(self, content: str) -> None:
        try:
            import pyperclip
            pyperclip.copy(content)
            self._show_copy_toast("Copied to clipboard")
        except ImportError:
            self.notify(
                "pyperclip not installed. Clipboard disabled.",
                severity="warning")
        except Exception as e:
            self.notify(f"Clipboard error: {e}", severity="error")

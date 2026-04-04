import logging
import re
from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static, Label

from airecon.proxy.config import get_workspace_root

logger = logging.getLogger(__name__)

_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class ConfirmDelete(ModalScreen[bool]):
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        super().__init__()

    BINDINGS = [
        ("y", "confirm", "Yes (Y)"),
        ("n", "cancel", "No (N)"),
        ("escape", "cancel", "Cancel (Esc)"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(" Confirm Delete ", id="confirm-title")
            yield Label(f" {self.file_path}", id="confirm-path")
            with Horizontal(id="confirm-buttons"):
                yield Button("[Y] Yes, Delete", id="btn-yes", variant="error")
                yield Button("[N] No, Keep", id="btn-no", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-yes":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class FilePreviewScreen(ModalScreen):
    DEFAULT_CSS = ""

    class Submitted(Message):
        def __init__(self, file_path: str, user_prompt: str) -> None:
            self.file_path = file_path
            self.user_prompt = user_prompt
            super().__init__()

    def __init__(self, path: str, content: str | None = None) -> None:
        self.file_path = path
        self.content = content
        super().__init__()

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("c", "copy", "Copy Content"),
        ("d", "delete", "Delete File"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="preview-dialog"):
            display_path = self.file_path
            if len(display_path) > 60:
                display_path = "…" + display_path[-57:]
            yield Static(Text(f"  {display_path}"), id="preview-header")

            with VerticalScroll(id="preview-area"):
                yield Static(
                    Text(self.content or "Loading…"),
                    id="preview-content",
                )

            with Vertical(id="preview-footer"):
                yield Input(
                    placeholder="Ask about this file… (Enter to send with [CONTEXT])",
                    id="prompt-input",
                )
                with Horizontal(id="action-bar"):
                    yield Button("Close [Esc]", id="close-preview", classes="btn-close")
                    yield Button("Copy", id="copy-content", classes="btn-copy")
                    yield Button("Delete", id="delete-file", classes="btn-delete")
                    yield Button(
                        "Run with Context", id="run-context", classes="btn-run"
                    )

    def on_mount(self) -> None:
        if self.content is None:
            self._load_file_content()

    def _load_file_content(self) -> None:
        try:
            p = Path(self.file_path)
            if not p.exists():
                self._set_content(f"✗ File not found: {self.file_path}")
                return

            size = p.stat().st_size
            MAX_SIZE = 1 * 1024 * 1024

            if size > MAX_SIZE:
                with open(p, "r", errors="replace") as f:
                    head = f.read(5000)
                    f.seek(max(0, size - 500000))
                    tail = f.read()
                msg = (
                    f"\n\n  ⋮ LARGE FILE TRUNCATED ({size / 1024 / 1024:.2f} MB)\n"
                    f"  ⋮ Showing first 5KB and last 500KB\n\n"
                )
                content = (
                    _ANSI_ESCAPE_RE.sub("", head) + msg + _ANSI_ESCAPE_RE.sub("", tail)
                )
            else:
                raw = p.read_text(errors="replace")
                content = _ANSI_ESCAPE_RE.sub("", raw)

            self.content = content
            self._set_content(content)

        except Exception as e:
            self._set_content(f"✗ Error loading file: {e}")

    def _set_content(self, text: str) -> None:
        try:
            self.query_one("#preview-content", Static).update(Text(text))
        except Exception as e:
            logger.debug("Expected failure in _set_content update preview: %s", e)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-preview":
            self.dismiss()
        elif event.button.id == "copy-content":
            self.action_copy()
        elif event.button.id == "delete-file":
            self.action_delete()
        elif event.button.id == "run-context":
            self._submit()

    def _is_path_allowed_for_delete(self, candidate: Path) -> tuple[bool, str | None]:
        try:
            resolved = candidate.resolve()
        except Exception as e:
            return False, f"Cannot resolve path: {e}"

        workspace_root = get_workspace_root().resolve()
        project_root = Path(__file__).resolve().parents[2]

        def _inside_allowed_roots(path: Path) -> bool:
            return path.is_relative_to(workspace_root) or path.is_relative_to(
                project_root
            )

        if not _inside_allowed_roots(resolved):
            return False, "Access denied: file is outside workspace/project sandbox"

        if candidate.is_symlink():
            try:
                target = candidate.resolve()
            except Exception as e:
                return False, f"Cannot resolve symlink target: {e}"
            if not _inside_allowed_roots(target):
                return (
                    False,
                    "Access denied: symlink target is outside workspace/project sandbox",
                )

        return True, None

    def action_delete(self) -> None:
        """Delete the previewed file after confirmation."""
        p = Path(self.file_path)
        if not p.exists():
            self.notify("File no longer exists.", severity="error")
            return
        if not p.is_file():
            self.notify("Delete is only allowed for regular files.", severity="error")
            return

        allowed, err = self._is_path_allowed_for_delete(p)
        if not allowed:
            self.notify(err or "Delete blocked by sandbox policy.", severity="error")
            return

        def on_delete_result(result: bool | None) -> None:
            if result:
                self._perform_delete()

        self.app.push_screen(ConfirmDelete(self.file_path), on_delete_result)

    def _perform_delete(self) -> None:
        """Actually delete the file."""
        try:
            p = Path(self.file_path)
            if p.exists():
                p.unlink()
                deleted_msg = f"✗ File deleted: {self.file_path}"
                self.content = deleted_msg
                self._set_content(deleted_msg)

                active_path = getattr(self.app, "active_file_path", None)
                if isinstance(active_path, Path):
                    try:
                        if active_path.resolve() == p.resolve() and hasattr(
                            self.app, "_clear_active_file_context"
                        ):
                            self.app._clear_active_file_context()
                    except Exception as e:
                        logger.debug(
                            "Expected failure in _perform_delete clear active context: %s",
                            e,
                        )

                self.notify(f"✓ Deleted: {self.file_path}", severity="information")
        except Exception as e:
            self.notify(f"✗ Delete failed: {e}", severity="error")

    def action_copy(self) -> None:
        val = self.content or ""
        self.app.copy_to_clipboard(val)
        self.notify("Copied!", severity="information")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def _submit(self) -> None:
        inp = self.query_one("#prompt-input", Input)
        val = inp.value.strip()
        if val:
            self.dismiss(self.Submitted(self.file_path, val))
        else:
            self.notify("Enter an instruction first.", severity="warning")

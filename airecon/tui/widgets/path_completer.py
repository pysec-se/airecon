"""@/path autocomplete widget for CommandInput.

Shows a file/directory listing popup when the user types @ in the input.
Supports:
  @          → list home directory (~/)
  @/         → list filesystem root /
  @/ho       → list / filtered to entries starting with "ho"
  @/home/    → list /home/ contents
  @/home/u   → list /home/ filtered to "u*"
"""

from __future__ import annotations

import logging
from pathlib import Path

from textual.app import ComposeResult
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView

logger = logging.getLogger("airecon.tui.path_completer")

_MAX_COMPLETIONS = 15  # Max items shown in the dropdown


class PathCompleter(Widget):
    """Filesystem completion panel that appears above CommandInput.

    Lifecycle:
      show_for(fragment) → render matching entries, display widget
      hide()             → clear + hide widget
      get_first_path()   → used by Tab completion in the app

    Fires PathCompleter.Completed(path) when user clicks an entry.
    """

    DEFAULT_CSS = ""  # Defined in styles.tcss

    class Completed(Message):
        """Emitted when the user selects a completion entry.

        path: absolute path string; ends with '/' if it's a directory.
        """

        def __init__(self, path: str) -> None:
            self.path = path
            super().__init__()

    # ── Compose ─────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield ListView(id="path-list")

    def on_mount(self) -> None:
        self.display = False

    # ── Public API ───────────────────────────────────────────────────────────

    def show_for(self, fragment: str) -> None:
        """Update completions for the path fragment typed after '@'.

        Args:
            fragment: everything after the @ character.
                ""        → list ~/
                "/"       → list /
                "/ho"     → list / filtered to entries starting with "ho"
                "/home/"  → list /home/ contents
        """
        entries = _list_entries(fragment)
        lv = self.query_one("#path-list", ListView)
        lv.clear()

        if not entries:
            self.display = False
            return

        for abs_path, is_dir in entries:
            name = Path(abs_path).name
            suffix = "/" if is_dir else ""
            icon = "▸" if is_dir else " "
            # store full absolute path + optional "/" in ListItem.name
            full = abs_path + ("/" if is_dir else "")
            lv.append(ListItem(Label(f" {icon} {name}{suffix}"), name=full))

        self.display = True
        lv.index = 0

    def hide(self) -> None:
        """Hide the completer and clear its list."""
        self.display = False
        try:
            self.query_one("#path-list", ListView).clear()
        except Exception as _e:  # nosec B110 - widget may not be mounted yet
            logger.debug("PathCompleter.hide: could not clear list: %s", _e)

    def get_first_path(self) -> str | None:
        """Return the path of the first (or highlighted) item — for Tab completion."""
        try:
            lv = self.query_one("#path-list", ListView)
            items = list(lv.query(ListItem))
            if not items:
                return None
            # Use highlighted index if set; else fall back to index 0
            idx = lv.index if lv.index is not None else 0
            if 0 <= idx < len(items):
                return items[idx].name
            return items[0].name
        except Exception as _e:  # nosec B110 - widget may not be mounted yet
            logger.debug("PathCompleter.get_first_path: %s", _e)
            return None

    # ── Event Handlers ───────────────────────────────────────────────────────

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """User pressed Enter or clicked on a list item."""
        if event.item.name:
            self.post_message(self.Completed(event.item.name))
        event.stop()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _list_entries(fragment: str) -> list[tuple[str, bool]]:
    """Resolve fragment to (absolute_path, is_dir) entries.

    Returns up to _MAX_COMPLETIONS results sorted: dirs first, then files,
    both alphabetically.
    """
    if not fragment:
        # Just @ typed — browse home directory
        base = Path.home()
        prefix = ""
    elif fragment == "/":
        base = Path("/")
        prefix = ""
    else:
        p = Path(fragment)
        if fragment.endswith("/"):
            base = p
            prefix = ""
        else:
            base = p.parent
            prefix = p.name

    try:
        all_entries = sorted(
            base.iterdir(),
            key=lambda e: (not e.is_dir(), e.name.lower()),
        )
    except (PermissionError, OSError, NotADirectoryError):
        return []

    show_hidden = prefix.startswith(".")
    result: list[tuple[str, bool]] = []
    for entry in all_entries:
        name = entry.name
        if prefix and not name.startswith(prefix):
            continue
        if not show_hidden and name.startswith("."):
            continue
        result.append((str(entry), entry.is_dir()))
        if len(result) >= _MAX_COMPLETIONS:
            break

    return result

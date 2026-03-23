from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DirectoryTree, Static


class WorkspaceTree(DirectoryTree):
    """Tree view of the workspace."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.styles.scrollbar_size_vertical = 0
        self.styles.scrollbar_size_horizontal = 0

    def filter_paths(self, paths: list[Path]) -> list[Path]:
        filtered = [p for p in paths if not p.name.startswith(".")]
        return filtered[:500]


class WorkspacePanel(Vertical):
    """Panel showing workspace tree and auto-updating vulnerability panel."""

    DEFAULT_CSS = ""

    def __init__(self, workspace_path: Path, **kwargs) -> None:
        self.workspace_path = workspace_path
        self._current_target_path: Path | None = None
        self._vuln_tree_path: Path | None = None  # track what the mounted tree shows
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        with Vertical(id="workspace-section"):
            self.styles.scrollbar_size_vertical = 0
            self.styles.scrollbar_size_horizontal = 0
            yield Static("📂 WORKSPACE", id="workspace-header")
            yield WorkspaceTree(self.workspace_path, id="workspace-tree")

        with Vertical(id="vuln-section"):
            self.styles.scrollbar_size_vertical = 0
            self.styles.scrollbar_size_horizontal = 0
            yield Static("🐞 VULNERABILITIES", id="vuln-header")
            yield Static(
                "Scanning for vulnerabilities…",
                id="vuln-placeholder",
                markup=False,
            )
            # #vuln-tree is mounted dynamically when vuln files are found

    def on_mount(self) -> None:
        self.call_after_refresh(self._refresh_vuln_panel)

    # ------------------------------------------------------------------
    # Core auto-scan logic — called on every reload
    # ------------------------------------------------------------------

    def _find_best_vuln_target(self) -> tuple[Path | None, Path | None]:
        """
        Scan workspace and return (target_path, vuln_path) for the best target.
        Priority:
          1. Current target if it has vuln files
          2. Any target with vuln files (most recently modified first)
          3. Most recently modified target (even if vuln folder is empty)
          4. None if workspace is empty
        Returns (target_path, vuln_path) where vuln_path may be None/empty.
        """
        try:
            all_targets = sorted(
                [d for d in self.workspace_path.iterdir()
                 if d.is_dir() and not d.name.startswith(".")],
                key=lambda x: x.stat().st_mtime,
                reverse=True,
            )
        except Exception:
            return None, None

        if not all_targets:
            return None, None

        def _has_vuln_files(vp: "Path") -> bool:
            try:
                return vp.exists() and any(vp.iterdir())
            except OSError:
                return False

        # Prefer current target if it already has vuln files
        if self._current_target_path and self._current_target_path in all_targets:
            vp = self._current_target_path / "vulnerabilities"
            if _has_vuln_files(vp):
                return self._current_target_path, vp

        # Find any target that has vuln files
        for t in all_targets:
            vp = t / "vulnerabilities"
            if _has_vuln_files(vp):
                return t, vp

        # Fall back to most-recently-modified target (no vuln files yet)
        return all_targets[0], None

    def _refresh_vuln_panel(self) -> None:
        """Scan workspace and update the vulnerability panel automatically."""
        target_path, vuln_path = self._find_best_vuln_target()

        if target_path is None:
            self._show_placeholder(
                "No workspace targets found.\nStart a recon scan to begin.")
            self._remove_vuln_tree()
            return

        self._current_target_path = target_path

        if vuln_path is None:
            # Target found but no vuln files yet
            self._show_placeholder(
                f"No reports yet for {target_path.name}.\n"
                "Vulnerabilities will appear here automatically."
            )
            self._remove_vuln_tree()
            return

        # We have vuln files — show/update the tree
        self._show_vuln_tree(vuln_path)

    def _show_placeholder(self, msg: str) -> None:
        try:
            p = self.query_one("#vuln-placeholder", Static)
            p.update(msg)
            p.display = True
        except Exception:  # nosec B110 - widget may not exist yet
            pass

    def _remove_vuln_tree(self) -> None:
        try:
            self.query_one("#vuln-tree", WorkspaceTree).remove()
            self._vuln_tree_path = None
        except Exception:  # nosec B110 - tree may not be mounted
            pass

    def _show_vuln_tree(self, vuln_path: Path) -> None:
        """Mount or reload the vuln tree for the given path."""
        try:
            existing = self.query_one("#vuln-tree", WorkspaceTree)
            # Same path already mounted — just reload
            if self._vuln_tree_path == vuln_path:
                existing.reload()
            else:
                # Different path — remove and remount
                existing.remove()
                self._vuln_tree_path = None
                self._mount_vuln_tree(vuln_path)
        except Exception:
            # Tree not mounted yet
            self._mount_vuln_tree(vuln_path)

        # Hide placeholder
        try:
            self.query_one("#vuln-placeholder", Static).display = False
        except Exception:  # nosec B110 - widget may not exist yet
            pass

    def _mount_vuln_tree(self, vuln_path: Path) -> None:
        try:
            section = self.query_one("#vuln-section", Vertical)
            new_tree = WorkspaceTree(vuln_path, id="vuln-tree")
            section.mount(new_tree)
            self._vuln_tree_path = vuln_path
        except Exception:  # nosec B110 - mount is best-effort
            pass

    # ------------------------------------------------------------------
    # Public API used by app.py
    # ------------------------------------------------------------------

    def update_vulnerabilities_path(self, target_path: Path) -> None:
        """Called when user clicks a folder in the workspace tree."""
        self._current_target_path = target_path
        self._refresh_vuln_panel()

    def clear_vulnerabilities_view(self) -> None:
        self._show_placeholder(
            "No target selected.\nSelect a workspace folder to view reports.")
        self._remove_vuln_tree()

    def reload(self) -> None:
        """Reload workspace tree and auto-refresh vuln panel."""
        try:
            self.query_one("#workspace-tree", WorkspaceTree).reload()
        except Exception:  # nosec B110 - reload is best-effort
            pass
        # Always auto-scan — no dependency on _current_target_path being set
        try:
            self._refresh_vuln_panel()
        except Exception:  # nosec B110 - refresh is best-effort
            pass

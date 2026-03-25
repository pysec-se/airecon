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


class VulnTree(WorkspaceTree):
    """Directory tree rooted at workspace, showing only targets with vuln files.

    Filter logic per depth relative to workspace root:
      depth 1 — target dir   : show only if target/vulnerabilities/ has files
      depth 2 — subdir        : show only the 'vulnerabilities' folder
      depth 3+ — inside vulns : show everything (non-hidden)
    """

    def __init__(self, workspace_path: Path, *args, **kwargs) -> None:
        self._workspace_root = workspace_path.resolve()
        super().__init__(workspace_path, *args, **kwargs)

    def filter_paths(self, paths: list[Path]) -> list[Path]:
        result = []
        for p in paths:
            if p.name.startswith("."):
                continue
            try:
                rel = p.resolve().relative_to(self._workspace_root)
                depth = len(rel.parts)
            except ValueError:
                continue

            if depth == 1:
                # Target directory — include only if vulnerabilities/ has content
                vuln_dir = p / "vulnerabilities"
                try:
                    if vuln_dir.exists() and any(vuln_dir.iterdir()):
                        result.append(p)
                except OSError:
                    pass
            elif depth == 2:
                # Subfolder of target — include only the vulnerabilities dir
                if p.name == "vulnerabilities":
                    result.append(p)
            else:
                # Inside vulnerabilities or deeper — include all non-hidden
                result.append(p)

        return result[:500]


class WorkspacePanel(Vertical):
    """Panel showing workspace tree and auto-updating vulnerability panel."""

    DEFAULT_CSS = ""

    def __init__(self, workspace_path: Path, **kwargs) -> None:
        self.workspace_path = workspace_path
        self._current_target_path: Path | None = None
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
    # Helper: count targets that have vulnerability files
    # ------------------------------------------------------------------

    def _count_targets_with_vulns(self) -> int:
        count = 0
        try:
            for d in self.workspace_path.iterdir():
                if not d.is_dir() or d.name.startswith("."):
                    continue
                vp = d / "vulnerabilities"
                try:
                    if vp.exists() and any(vp.iterdir()):
                        count += 1
                except OSError:
                    pass
        except Exception:
            pass
        return count

    def _has_any_targets(self) -> bool:
        try:
            return any(
                d for d in self.workspace_path.iterdir()
                if d.is_dir() and not d.name.startswith(".")
            )
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Core refresh logic
    # ------------------------------------------------------------------

    def _refresh_vuln_panel(self) -> None:
        """Scan all targets and update the vulnerability panel."""
        count = self._count_targets_with_vulns()

        if count == 0:
            if not self._has_any_targets():
                self._show_placeholder(
                    "No workspace targets found.\nStart a recon scan to begin.")
            else:
                self._show_placeholder(
                    "No vulnerability reports yet.\n"
                    "Vulnerabilities will appear here automatically.")
            self._remove_vuln_tree()
            self._update_header()
            return

        # Ensure tree is mounted once, then reload to pick up new files
        self._ensure_vuln_tree()
        self._reload_vuln_tree()

        try:
            self.query_one("#vuln-placeholder", Static).display = False
        except Exception:  # nosec B110
            pass

        self._update_header(count)

    # ------------------------------------------------------------------
    # Header management
    # ------------------------------------------------------------------

    def _update_header(self, count: int | None = None) -> None:
        try:
            h = self.query_one("#vuln-header", Static)
            if self._current_target_path:
                h.update(f"🐞 VULNERABILITIES — {self._current_target_path.name}")
            elif count:
                label = f"{count} target" + ("s" if count != 1 else "")
                h.update(f"🐞 VULNERABILITIES ({label})")
            else:
                h.update("🐞 VULNERABILITIES")
        except Exception:  # nosec B110
            pass

    # ------------------------------------------------------------------
    # Vuln tree mount / reload / remove
    # ------------------------------------------------------------------

    def _ensure_vuln_tree(self) -> None:
        """Mount VulnTree if not already mounted."""
        try:
            self.query_one("#vuln-tree", VulnTree)
        except Exception:
            self._mount_vuln_tree()

    def _mount_vuln_tree(self) -> None:
        try:
            section = self.query_one("#vuln-section", Vertical)
            new_tree = VulnTree(self.workspace_path, id="vuln-tree")
            section.mount(new_tree)
        except Exception:  # nosec B110
            pass

    def _reload_vuln_tree(self) -> None:
        try:
            self.query_one("#vuln-tree", VulnTree).reload()
        except Exception:  # nosec B110
            pass

    def _remove_vuln_tree(self) -> None:
        try:
            self.query_one("#vuln-tree").remove()
        except Exception:  # nosec B110
            pass

    def _show_placeholder(self, msg: str) -> None:
        try:
            p = self.query_one("#vuln-placeholder", Static)
            p.update(msg)
            p.display = True
        except Exception:  # nosec B110
            pass

    # ------------------------------------------------------------------
    # Public API used by app.py
    # ------------------------------------------------------------------

    def update_vulnerabilities_path(self, target_path: Path) -> None:
        """Called when user clicks a folder in the workspace tree."""
        self._current_target_path = target_path
        self._update_header()
        self._reload_vuln_tree()

    def clear_vulnerabilities_view(self) -> None:
        self._current_target_path = None
        self._update_header()

    def reload(self) -> None:
        """Reload workspace tree and refresh vuln panel."""
        try:
            self.query_one("#workspace-tree", WorkspaceTree).reload()
        except Exception:  # nosec B110
            pass
        try:
            self._refresh_vuln_panel()
        except Exception:  # nosec B110
            pass

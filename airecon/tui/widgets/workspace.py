from __future__ import annotations

import logging
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DirectoryTree, Static

logger = logging.getLogger(__name__)


class WorkspaceTree(DirectoryTree):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.styles.scrollbar_size_vertical = 0
        self.styles.scrollbar_size_horizontal = 0

    def filter_paths(self, paths: list[Path]) -> list[Path]:
        filtered = [p for p in paths if not p.name.startswith(".")]
        return filtered[:500]


class VulnTree(WorkspaceTree):
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
                vuln_dir = p / "vulnerabilities"
                try:
                    if vuln_dir.exists() and any(vuln_dir.iterdir()):
                        result.append(p)
                except OSError:
                    pass
            elif depth == 2:
                if p.name == "vulnerabilities":
                    result.append(p)
            else:
                result.append(p)

        return result[:500]


class WorkspacePanel(Vertical):
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

    def on_mount(self) -> None:
        self.call_after_refresh(self._refresh_vuln_panel)

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
        except Exception as e:
            logger.debug("Expected failure in _count_targets_with_vulns: %s", e)
        return count

    def _has_any_targets(self) -> bool:
        try:
            return any(
                d
                for d in self.workspace_path.iterdir()
                if d.is_dir() and not d.name.startswith(".")
            )
        except Exception:
            return False

    def _refresh_vuln_panel(self) -> None:
        count = self._count_targets_with_vulns()

        if count == 0:
            if not self._has_any_targets():
                self._show_placeholder(
                    "No workspace targets found.\nStart a recon scan to begin."
                )
            else:
                self._show_placeholder(
                    "No vulnerability reports yet.\n"
                    "Vulnerabilities will appear here automatically."
                )
            self._remove_vuln_tree()
            self._update_header()
            return

        self._ensure_vuln_tree()
        self._reload_vuln_tree()

        try:
            self.query_one("#vuln-placeholder", Static).display = False
        except Exception as e:
            logger.debug(
                "Expected failure in _refresh_vuln_panel hide placeholder: %s", e
            )

        self._update_header(count)

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
        except Exception as e:
            logger.debug("Expected failure in _update_header: %s", e)

    def _ensure_vuln_tree(self) -> None:
        try:
            self.query_one("#vuln-tree", VulnTree)
        except Exception:
            self._mount_vuln_tree()

    def _mount_vuln_tree(self) -> None:
        try:
            section = self.query_one("#vuln-section", Vertical)
            new_tree = VulnTree(self.workspace_path, id="vuln-tree")
            section.mount(new_tree)
        except Exception as e:
            logger.debug("Expected failure in _mount_vuln_tree: %s", e)

    def _reload_vuln_tree(self) -> None:
        try:
            self.query_one("#vuln-tree", VulnTree).reload()
        except Exception as e:
            logger.debug("Expected failure in _reload_vuln_tree: %s", e)

    def _remove_vuln_tree(self) -> None:
        try:
            nodes = list(self.query("#vuln-tree"))
            if nodes:
                nodes[0].remove()
        except Exception as e:
            logger.debug("Expected failure in _remove_vuln_tree: %s", e)

    def _show_placeholder(self, msg: str) -> None:
        try:
            p = self.query_one("#vuln-placeholder", Static)
            p.update(msg)
            p.display = True
        except Exception as e:
            logger.debug("Expected failure in _show_placeholder: %s", e)

    def update_vulnerabilities_path(self, target_path: Path) -> None:
        self._current_target_path = target_path
        self._update_header()
        self._reload_vuln_tree()

    def clear_vulnerabilities_view(self) -> None:
        self._current_target_path = None
        self._update_header()

    def reload(self) -> None:
        try:
            self.query_one("#workspace-tree", WorkspaceTree).reload()
        except Exception as e:
            logger.debug("Expected failure in reload workspace tree: %s", e)
        try:
            self._refresh_vuln_panel()
        except Exception as e:
            logger.debug("Expected failure in reload refresh vuln panel: %s", e)

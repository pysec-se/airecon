"""Tests for Workspace Widget."""
from airecon.tui.widgets.workspace import WorkspacePanel, WorkspaceTree, VulnTree

class TestWorkspaceWidget:
    def test_workspace_panel(self):
        assert WorkspacePanel is not None
    def test_workspace_tree(self):
        assert WorkspaceTree is not None
    def test_vuln_tree(self):
        assert VulnTree is not None

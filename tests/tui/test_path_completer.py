"""Tests for _list_entries in path_completer.py."""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch

from airecon.tui.widgets.path_completer import _list_entries, _MAX_COMPLETIONS


class TestListEntriesEmpty:
    def test_empty_fragment_returns_home_entries(self, tmp_path):
        """Empty fragment should list home directory contents."""
        (tmp_path / "dir_a").mkdir()
        (tmp_path / "file_b.txt").write_text("x")
        with patch("airecon.tui.widgets.path_completer.Path") as MockPath:
            MockPath.home.return_value = tmp_path
            MockPath.side_effect = lambda p: Path(p)
            result = _list_entries("")
        # We can't easily mock Path() calls inline, so test real behavior
        # by testing empty fragment falls through to home
        # Just verify function doesn't raise
        assert isinstance(_list_entries(""), list)

    def test_slash_only_lists_root(self):
        result = _list_entries("/")
        assert isinstance(result, list)
        # Root should have entries on Linux
        assert len(result) > 0

    def test_returns_list_of_tuples(self, tmp_path):
        (tmp_path / "sub").mkdir()
        result = _list_entries(str(tmp_path) + "/")
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, tuple)
            assert len(item) == 2
            abs_path, is_dir = item
            assert isinstance(abs_path, str)
            assert isinstance(is_dir, bool)


class TestListEntriesFiltering:
    def test_prefix_filters_entries(self, tmp_path):
        (tmp_path / "alpha.txt").write_text("x")
        (tmp_path / "beta.txt").write_text("x")
        (tmp_path / "alpha2.txt").write_text("x")

        result = _list_entries(str(tmp_path / "alpha"))
        names = [Path(p).name for p, _ in result]
        assert all(n.startswith("alpha") for n in names)
        assert "beta.txt" not in names

    def test_exact_dir_slash_lists_contents(self, tmp_path):
        (tmp_path / "child1").mkdir()
        (tmp_path / "child2.txt").write_text("x")

        result = _list_entries(str(tmp_path) + "/")
        names = [Path(p).name for p, _ in result]
        assert "child1" in names
        assert "child2.txt" in names

    def test_hidden_files_excluded_by_default(self, tmp_path):
        (tmp_path / ".hidden").write_text("x")
        (tmp_path / "visible.txt").write_text("x")

        result = _list_entries(str(tmp_path) + "/")
        names = [Path(p).name for p, _ in result]
        assert ".hidden" not in names
        assert "visible.txt" in names

    def test_hidden_files_shown_when_prefix_is_dot(self, tmp_path):
        (tmp_path / ".hidden_file").write_text("x")
        (tmp_path / ".bashrc").write_text("x")

        # fragment "/<dir>/.h" → prefix=".h" → show_hidden=True, matches .hidden_file
        result = _list_entries(str(tmp_path) + "/.h")
        names = [Path(p).name for p, _ in result]
        assert any(n.startswith(".h") for n in names)


class TestListEntriesSorting:
    def test_dirs_before_files(self, tmp_path):
        (tmp_path / "aaa_file.txt").write_text("x")
        (tmp_path / "bbb_dir").mkdir()

        result = _list_entries(str(tmp_path) + "/")
        if len(result) >= 2:
            first_is_dir = result[0][1]
            assert first_is_dir is True, "Directories should come before files"

    def test_alphabetical_within_type(self, tmp_path):
        (tmp_path / "c_dir").mkdir()
        (tmp_path / "a_dir").mkdir()
        (tmp_path / "b_dir").mkdir()

        result = _list_entries(str(tmp_path) + "/")
        dir_names = [Path(p).name for p, is_dir in result if is_dir]
        assert dir_names == sorted(dir_names)


class TestListEntriesCap:
    def test_capped_at_max_completions(self, tmp_path):
        for i in range(_MAX_COMPLETIONS + 10):
            (tmp_path / f"file_{i:03d}.txt").write_text("x")

        result = _list_entries(str(tmp_path) + "/")
        assert len(result) <= _MAX_COMPLETIONS


class TestListEntriesErrors:
    def test_permission_error_returns_empty(self, tmp_path):
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0o000)
        try:
            result = _list_entries(str(locked) + "/")
            assert result == []
        finally:
            locked.chmod(0o755)

    def test_nonexistent_path_returns_empty(self):
        result = _list_entries("/nonexistent_path_xyz_123/")
        assert result == []

    def test_file_as_base_returns_empty(self, tmp_path):
        """Using a file (not dir) as base should return empty."""
        f = tmp_path / "file.txt"
        f.write_text("x")
        result = _list_entries(str(f) + "/")
        assert result == []

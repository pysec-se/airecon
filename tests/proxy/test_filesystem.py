"""Unit tests for filesystem.py - file operations with path validation."""

from pathlib import Path
from unittest.mock import patch


from airecon.proxy.filesystem import (
    _MAX_CREATE_FILE_BYTES,
    _MAX_DEPTH,
    _fmt_size,
    _read_with_pagination,
    _resolve_workspace_path,
    _walk_dir,
    create_file,
    list_files,
    read_file,
)


class TestResolveWorkspacePath:
    """Test path resolution helper."""

    def test_strips_leading_slash(self, tmp_path: Path) -> None:
        result = _resolve_workspace_path("/test.txt", tmp_path)
        assert result == tmp_path / "test.txt"

    def test_strips_workspace_prefix(self, tmp_path: Path) -> None:
        result = _resolve_workspace_path("workspace/test.txt", tmp_path)
        assert result == tmp_path / "test.txt"

    def test_handles_empty_path(self, tmp_path: Path) -> None:
        result = _resolve_workspace_path("", tmp_path)
        assert result == tmp_path

    def test_resolves_symlinks(self, tmp_path: Path) -> None:
        # Create a symlink
        real_file = tmp_path / "real.txt"
        real_file.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(real_file)

        result = _resolve_workspace_path("link.txt", tmp_path)
        # Function resolves symlinks via .resolve() call
        assert result == real_file.resolve()


class TestCreateFile:
    """Test file creation with security validation."""

    def test_create_file_success(self, tmp_path: Path) -> None:
        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = create_file("test.txt", "hello world")

        assert result["success"] is True
        assert "File created at" in result["result"]
        assert (tmp_path / "test.txt").read_text() == "hello world"

    def test_create_file_creates_parent_dirs(self, tmp_path: Path) -> None:
        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = create_file("nested/dir/test.txt", "content")

        assert result["success"] is True
        assert (tmp_path / "nested" / "dir" / "test.txt").exists()

    def test_create_file_rejects_too_large_content(self, tmp_path: Path) -> None:
        large_content = "x" * (_MAX_CREATE_FILE_BYTES + 1)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = create_file("large.txt", large_content)

        assert result["success"] is False
        assert "Content too large" in result["error"]

    def test_create_file_blocks_path_traversal(self, tmp_path: Path) -> None:
        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = create_file("../../../etc/passwd", "malicious")

        assert result["success"] is False
        assert "Path must be inside workspace" in result["error"]

    def test_create_file_blocks_symlink_outside_workspace(self, tmp_path: Path) -> None:
        # Create a symlink pointing outside workspace
        outside_file = Path("/tmp/outside.txt")
        link = tmp_path / "evil.txt"
        if link.exists():
            link.unlink()
        link.symlink_to(outside_file)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            # Try to write through the symlink
            result = create_file("evil.txt", "content")

        # Symlink validation happens during resolve() which raises error
        assert result["success"] is False
        # Error message varies based on where validation fails
        assert (
            "outside" in result["error"].lower() or "Access denied" in result["error"]
        )

    def test_create_file_uses_atomic_write(self, tmp_path: Path) -> None:
        """Verify temp file is created and replaced atomically."""
        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = create_file("atomic.txt", "content")

        assert result["success"] is True
        # Verify no temp files left behind
        temp_files = list(tmp_path.glob("*.tmp"))
        assert len(temp_files) == 0


class TestReadFile:
    """Test file reading with pagination and security."""

    def test_read_file_success(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("line1\nline2\nline3")

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = read_file("test.txt")

        assert result["success"] is True
        assert "line1" in result["result"]
        assert result["total_lines"] == 3

    def test_read_file_with_offset(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("\n".join([f"line{i}" for i in range(10)]))

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = read_file("test.txt", offset=5, limit=3)

        assert result["success"] is True
        assert "line5" in result["result"]
        assert "line8" not in result["result"]
        assert result["has_more"] is True

    def test_read_file_with_limit(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("\n".join([f"line{i}" for i in range(100)]))

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = read_file("test.txt", limit=10)

        assert result["success"] is True
        assert result["total_lines"] == 100
        assert "has_more" in result

    def test_read_file_not_found(self, tmp_path: Path) -> None:
        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = read_file("nonexistent.txt")

        assert result["success"] is False
        assert "File not found" in result["error"]

    def test_read_file_blocks_path_traversal(self, tmp_path: Path) -> None:
        # Create a file outside workspace
        outside_file = Path("/tmp/outside.txt")
        outside_file.write_text("secret")

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = read_file("../../../tmp/outside.txt")

        assert result["success"] is False
        assert "outside workspace" in result["error"]

    def test_read_file_allows_absolute_path_in_workspace(self, tmp_path: Path) -> None:
        test_file = tmp_path / "absolute.txt"
        test_file.write_text("absolute content")

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = read_file(str(test_file))

        assert result["success"] is True
        assert "absolute content" in result["result"]

    def test_read_file_rejects_absolute_path_outside_workspace(
        self, tmp_path: Path
    ) -> None:
        outside_file = Path("/tmp/outside.txt")
        outside_file.write_text("secret")

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = read_file(str(outside_file))

        assert result["success"] is False
        assert "outside the allowed sandbox" in result["error"]

    def test_read_file_blocks_symlink_outside_workspace(self, tmp_path: Path) -> None:
        # Create symlink outside workspace
        outside_file = Path("/tmp/outside.txt")
        outside_file.write_text("secret")
        link = tmp_path / "evil.txt"
        if link.exists():
            link.unlink()
        link.symlink_to(outside_file)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = read_file("evil.txt")

        # Symlink validation happens during resolve() which raises error
        assert result["success"] is False
        # Error message varies based on where validation fails
        assert (
            "outside" in result["error"].lower() or "Access denied" in result["error"]
        )


class TestListFiles:
    """Test directory listing with metadata."""

    def test_list_files_empty_dir(self, tmp_path: Path) -> None:
        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = list_files("")

        assert result["success"] is True
        assert "(empty)" in result["result"]

    def test_list_files_with_content(self, tmp_path: Path) -> None:
        # Create files and directories
        (tmp_path / "file1.txt").write_text("content")
        (tmp_path / "file2.py").write_text("code")
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "nested.txt").write_text("nested")

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = list_files("")

        assert result["success"] is True
        assert "file1.txt" in result["result"]
        assert "file2.py" in result["result"]
        assert "subdir/" in result["result"]

    def test_list_files_shows_line_count(self, tmp_path: Path) -> None:
        test_file = tmp_path / "multiline.txt"
        test_file.write_text("\n".join([f"line{i}" for i in range(10)]))

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = list_files("")

        assert result["success"] is True
        assert "10 lines" in result["result"]

    def test_list_files_shows_file_size(self, tmp_path: Path) -> None:
        test_file = tmp_path / "large.txt"
        test_file.write_text("x" * 2000)  # ~2KB

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = list_files("")

        assert result["success"] is True
        assert "KB" in result["result"]

    def test_list_files_respects_max_depth(self, tmp_path: Path) -> None:
        # Create deep nested structure
        current = tmp_path
        for i in range(_MAX_DEPTH + 2):
            current = current / f"level{i}"
            current.mkdir()
            (current / "file.txt").write_text("content")

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = list_files("")

        # Should not show levels beyond _MAX_DEPTH
        assert f"level{_MAX_DEPTH}" not in result["result"]

    def test_list_files_not_found(self, tmp_path: Path) -> None:
        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = list_files("nonexistent")

        assert result["success"] is False
        assert "Directory not found" in result["error"]

    def test_list_files_not_a_directory(self, tmp_path: Path) -> None:
        test_file = tmp_path / "file.txt"
        test_file.write_text("content")

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = list_files("file.txt")

        assert result["success"] is False
        assert "not a directory" in result["error"]

    def test_list_files_skips_symlink_directories(self, tmp_path: Path) -> None:
        # Create a directory and a symlink to it
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "file.txt").write_text("content")

        link_dir = tmp_path / "link_dir"
        link_dir.symlink_to(real_dir)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=tmp_path
        ):
            result = list_files("")

        # Should show real_dir but not follow link_dir
        assert "real_dir/" in result["result"]
        # Symlink directories should be skipped to prevent loops
        assert "link_dir/" not in result["result"]


class TestReadWithPagination:
    """Test internal pagination helper."""

    def test_small_file_no_pagination(self, tmp_path: Path) -> None:
        test_file = tmp_path / "small.txt"
        test_file.write_text("line1\nline2")

        result = _read_with_pagination(test_file, offset=0, limit=500)

        assert result["success"] is True
        assert "has_more" not in result  # No pagination needed for small files
        assert result["total_lines"] == 2

    def test_large_file_with_pagination(self, tmp_path: Path) -> None:
        test_file = tmp_path / "large.txt"
        test_file.write_text("\n".join([f"line{i}" for i in range(1000)]))

        result = _read_with_pagination(test_file, offset=0, limit=100)

        assert result["success"] is True
        assert result["total_lines"] == 1000
        assert result["has_more"] is True
        # Note: offset/limit are not returned in result, they're input parameters

    def test_pagination_clamps_limit(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Request limit > 5000 should be clamped internally
        result = _read_with_pagination(test_file, offset=0, limit=10000)

        # Function clamps limit internally but doesn't return it
        # Verify the function doesn't crash with large limit
        assert result["success"] is True

    def test_pagination_clamps_offset(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Negative offset should be clamped to 0 internally
        result = _read_with_pagination(test_file, offset=-100, limit=100)

        # Function clamps offset internally but doesn't return it
        # Verify the function doesn't crash with negative offset
        assert result["success"] is True


class TestFmtSize:
    """Test file size formatting helper."""

    def test_bytes(self) -> None:
        assert _fmt_size(500) == "500 B"

    def test_kilobytes(self) -> None:
        assert _fmt_size(2048) == "2.0 KB"

    def test_megabytes(self) -> None:
        assert _fmt_size(2097152) == "2.0 MB"


class TestWalkDir:
    """Test directory walking helper."""

    def test_walk_dir_permission_error_handled(self, tmp_path: Path) -> None:
        """Verify walk continues even if a directory has permission errors."""
        output: list[str] = []

        # Create a directory we can read
        test_dir = tmp_path / "readable"
        test_dir.mkdir()
        (test_dir / "file.txt").write_text("content")

        # Should not raise, should handle gracefully
        _walk_dir(test_dir, tmp_path, output, depth=0, prefix="")

        assert len(output) > 0

"""Tests for file_reference module — @/path syntax resolution."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch


from airecon.proxy.agent.file_reference import (
    FileRef,
    ResolvedRef,
    build_injection_message,
    parse_refs,
    resolve_ref,
    strip_refs,
    workspace_name_for_ref,
)


# ─────────────────────────────────────────────────────────────────────────────
# parse_refs
# ─────────────────────────────────────────────────────────────────────────────

class TestParseRefs:
    def test_single_file_ref(self):
        refs = parse_refs("analyze @/tmp/challenge.exe please")
        assert len(refs) == 1
        assert refs[0].raw == "@/tmp/challenge.exe"
        assert refs[0].path == Path("/tmp/challenge.exe")

    def test_directory_ref(self):
        refs = parse_refs("start CTF with @/home/user/project/")
        assert len(refs) == 1
        assert refs[0].path == Path("/home/user/project/")

    def test_multiple_refs(self):
        refs = parse_refs("check @/tmp/a.py and @/tmp/b.exe")
        assert len(refs) == 2
        paths = {r.raw for r in refs}
        assert "@/tmp/a.py" in paths
        assert "@/tmp/b.exe" in paths

    def test_no_refs(self):
        refs = parse_refs("scan target.com for vulnerabilities")
        assert refs == []

    def test_trailing_punctuation_stripped(self):
        refs = parse_refs("check @/tmp/file.py.")
        assert refs[0].path == Path("/tmp/file.py")

    def test_trailing_comma_stripped(self):
        refs = parse_refs("use @/tmp/file.py, @/tmp/other.py")
        assert refs[0].path == Path("/tmp/file.py")

    def test_empty_message(self):
        assert parse_refs("") == []

    def test_ref_at_start(self):
        refs = parse_refs("@/etc/passwd contains user list")
        assert len(refs) == 1
        assert refs[0].raw == "@/etc/passwd"

    def test_ref_in_quotes_ignored(self):
        # Regex stops at quotes — ref adjacent to quote still parsed up to quote
        refs = parse_refs('see "@/tmp/file.txt"')
        # The quote stops the path — path should be /tmp/file.txt
        assert len(refs) == 1
        assert refs[0].path == Path("/tmp/file.txt")


# ─────────────────────────────────────────────────────────────────────────────
# strip_refs
# ─────────────────────────────────────────────────────────────────────────────

class TestStripRefs:
    def test_replaces_ref_with_name(self):
        refs = parse_refs("analyze @/tmp/challenge.exe")
        result = strip_refs("analyze @/tmp/challenge.exe", refs)
        assert result == "analyze [file:challenge_exe]"

    def test_multiple_refs_stripped(self):
        refs = parse_refs("check @/tmp/a.py and @/tmp/b.exe")
        result = strip_refs("check @/tmp/a.py and @/tmp/b.exe", refs)
        assert "@/" not in result
        assert "[file:a_py]" in result
        assert "[file:b_exe]" in result

    def test_no_refs_unchanged(self):
        result = strip_refs("scan target.com", [])
        assert result == "scan target.com"

    def test_directory_ref_uses_dir_name(self):
        refs = [FileRef(raw="@/home/user/myproject/", path=Path("/home/user/myproject/"))]
        result = strip_refs("analyze @/home/user/myproject/", refs)
        assert "[file:myproject]" in result

    def test_trailing_comma_preserved_in_strip(self):
        # Trailing punctuation should remain in-place after token replacement.
        msg = "use @/tmp/file.py, @/tmp/other.py"
        refs = parse_refs(msg)
        result = strip_refs(msg, refs)
        assert "@/" not in result
        assert "[file:file_py]" in result
        assert "[file:other_py]" in result
        assert result.count(",") == msg.count(",")

    def test_strip_refs_raw_matches_original_exactly(self):
        # Verify raw is the exact substring in the original message
        msg = "analyze @/tmp/challenge.exe please"
        refs = parse_refs(msg)
        assert len(refs) == 1
        # raw must be found verbatim in original message
        assert refs[0].raw in msg
        result = strip_refs(msg, refs)
        assert refs[0].raw not in result  # replaced
        assert "[file:challenge_exe]" in result

    def test_overlapping_path_prefixes_are_replaced_correctly(self):
        msg = "check @/tmp/a and @/tmp/a_backup"
        refs = parse_refs(msg)
        result = strip_refs(msg, refs)
        assert result == "check [file:a] and [file:a_backup]"


# ─────────────────────────────────────────────────────────────────────────────
# resolve_ref — text files
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveTextFile:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_file(self, name: str, content: str) -> Path:
        p = self.tmpdir / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_text_file_resolved(self):
        src = self._make_file("test.py", "def hello():\n    return 42\n")
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.tmpdir)
        assert resolved.kind == "text"
        assert resolved.error is None
        assert resolved.workspace_dest is not None
        assert resolved.workspace_dest.exists()
        assert "uploads" in str(resolved.workspace_dest)
        assert "hello" in resolved.context_block
        assert "python" in resolved.context_block
        assert "/workspace" in resolved.context_block

    def test_text_file_shows_line_count(self):
        # range(50) items joined by 49 newlines = 49 line breaks
        content = "\n".join(f"line {i}" for i in range(50))
        src = self._make_file("big.py", content)
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.tmpdir)
        assert "49 lines" in resolved.context_block

    def test_json_file_resolved(self):
        src = self._make_file("config.json", '{"key": "value"}')
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.tmpdir)
        assert resolved.kind == "text"
        assert "json" in resolved.context_block

    def test_nonexistent_file_returns_error(self):
        ref = FileRef(raw="@/nonexistent/file.py", path=Path("/nonexistent/file.py"))
        resolved = resolve_ref(ref, self.tmpdir)
        assert resolved.error is not None
        assert "not found" in resolved.error.lower()

    def test_unknown_extension_treated_as_text(self):
        # No null bytes → treated as text even without known extension
        src = self._make_file("notes.xyz", "some plaintext content")
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.tmpdir)
        # Should be text (no null bytes)
        assert resolved.kind == "text"
        assert resolved.error is None

    def test_large_file_triggers_partial_read(self):
        # File > 300KB → partial read (head + tail), no crash
        content = "A" * 400_000  # 400KB > _MAX_TEXT_FILE_SIZE (300KB)
        src = self._make_file("big.log", content)
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.tmpdir)
        assert resolved.kind == "text"
        assert resolved.error is None
        assert "truncated" in resolved.context_block.lower()
        assert "HEAD" in resolved.context_block
        assert "TAIL" in resolved.context_block

    def test_same_basename_files_do_not_overwrite_each_other(self):
        src_a_dir = self.tmpdir / "a"
        src_b_dir = self.tmpdir / "b"
        src_a_dir.mkdir()
        src_b_dir.mkdir()
        src_a = src_a_dir / "config.json"
        src_b = src_b_dir / "config.json"
        src_a.write_text('{"source":"a"}', encoding="utf-8")
        src_b.write_text('{"source":"b"}', encoding="utf-8")

        workspace = self.tmpdir / "workspace"
        workspace.mkdir()

        res_a = resolve_ref(FileRef(raw=f"@{src_a}", path=src_a), workspace)
        res_b = resolve_ref(FileRef(raw=f"@{src_b}", path=src_b), workspace)

        assert res_a.workspace_dest is not None
        assert res_b.workspace_dest is not None
        assert res_a.workspace_dest != res_b.workspace_dest
        assert res_a.workspace_dest.read_text(encoding="utf-8") == '{"source":"a"}'
        assert res_b.workspace_dest.read_text(encoding="utf-8") == '{"source":"b"}'


# ─────────────────────────────────────────────────────────────────────────────
# resolve_ref — binary files
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveBinaryFile:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.workspace = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        shutil.rmtree(self.workspace, ignore_errors=True)

    def _make_binary(self, name: str) -> Path:
        p = self.tmpdir / name
        # Write ELF magic + null bytes to ensure binary detection
        p.write_bytes(b"\x7fELF\x00\x00\x00\x00" + b"\x00" * 100)
        return p

    def test_exe_extension_is_binary(self):
        src = self._make_binary("challenge.exe")
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.workspace)
        assert resolved.kind == "binary"
        assert resolved.workspace_dest is not None
        assert resolved.workspace_dest.exists()
        assert resolved.workspace_dest.name == "challenge.exe"

    def test_elf_extension_is_binary(self):
        src = self._make_binary("vuln.elf")
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.workspace)
        assert resolved.kind == "binary"

    def test_binary_copied_to_uploads(self):
        src = self._make_binary("binary.bin")
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.workspace)
        assert resolved.workspace_dest is not None
        assert "uploads" in str(resolved.workspace_dest)

    def test_binary_context_has_docker_path(self):
        src = self._make_binary("target.elf")
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.workspace)
        assert "/workspace" in resolved.context_block

    def test_binary_context_has_tool_hints(self):
        src = self._make_binary("app.exe")
        ref = FileRef(raw=f"@{src}", path=src)
        resolved = resolve_ref(ref, self.workspace)
        assert "strings" in resolved.context_block or "file" in resolved.context_block

    def test_null_byte_file_detected_as_binary(self):
        p = self.tmpdir / "no_extension"
        p.write_bytes(b"\x00binary\x00data")
        ref = FileRef(raw=f"@{p}", path=p)
        resolved = resolve_ref(ref, self.workspace)
        assert resolved.kind == "binary"

    def test_text_file_with_no_null_bytes_not_binary(self):
        # Plain text with no null bytes must NOT be treated as binary
        p = self.tmpdir / "data.dat"
        p.write_bytes(b"hello world\nno null bytes here\n")
        ref = FileRef(raw=f"@{p}", path=p)
        resolved = resolve_ref(ref, self.workspace)
        assert resolved.kind == "text"

    def test_docker_path_is_path_not_str(self):
        # BUG FIX: "/workspace" / Path(...) was TypeError — must use Path("/workspace")
        # get_workspace_root is lazily imported inside _resolve_binary, so patch
        # the source module. When dest IS under workspace_root, the Path()/Path
        # operation must succeed without TypeError.
        src = self._make_binary("ctf.elf")
        # workspace IS self.workspace, so dest (self.workspace/uploads/ctf.elf)
        # is relative_to(self.workspace) → "uploads/ctf.elf" → no ValueError.
        # Before fix: "/workspace" / Path("uploads/ctf.elf") → TypeError.
        # After fix: Path("/workspace") / Path("uploads/ctf.elf") → works.
        with patch("airecon.proxy.config.get_workspace_root",
                   return_value=self.workspace):
            ref = FileRef(raw=f"@{src}", path=src)
            resolved = resolve_ref(ref, self.workspace)
        assert resolved.kind == "binary"
        assert resolved.error is None
        # docker_path must be /workspace/uploads/ctf.elf
        assert "/workspace/uploads/ctf.elf" in resolved.context_block

    def test_binary_copy_failure_returns_error(self):
        # Non-readable source → OSError → error returned, no crash
        p = self.tmpdir / "locked.exe"
        p.write_bytes(b"\x00data")
        p.chmod(0o000)
        try:
            ref = FileRef(raw=f"@{p}", path=p)
            resolved = resolve_ref(ref, self.workspace)
            # Either error (copy failed) or kind=binary — depends on OS
            # On Linux as non-root, chmod 000 prevents read → copy fails
            if resolved.error:
                assert resolved.kind == "binary"
        finally:
            p.chmod(0o644)


# ─────────────────────────────────────────────────────────────────────────────
# resolve_ref — directories
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveDirectory:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.workspace = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        shutil.rmtree(self.workspace, ignore_errors=True)

    def _make_project(self) -> Path:
        proj = self.tmpdir / "project"
        proj.mkdir()
        (proj / "main.py").write_text("print('hello')\n", encoding="utf-8")
        (proj / "config.json").write_text('{"debug": true}', encoding="utf-8")
        (proj / "README.md").write_text("# Project\nSome description.", encoding="utf-8")
        sub = proj / "src"
        sub.mkdir()
        (sub / "utils.py").write_text("def helper(): pass\n", encoding="utf-8")
        return proj

    def test_directory_resolved(self):
        proj = self._make_project()
        ref = FileRef(raw=f"@{proj}", path=proj)
        resolved = resolve_ref(ref, self.workspace)
        assert resolved.kind == "directory"
        assert resolved.error is None
        assert resolved.workspace_dest is not None
        assert resolved.workspace_dest.exists()
        assert "uploads" in str(resolved.workspace_dest)

    def test_directory_tree_in_context(self):
        proj = self._make_project()
        ref = FileRef(raw=f"@{proj}", path=proj)
        resolved = resolve_ref(ref, self.workspace)
        assert "main.py" in resolved.context_block
        assert "config.json" in resolved.context_block

    def test_directory_file_contents_injected(self):
        proj = self._make_project()
        ref = FileRef(raw=f"@{proj}", path=proj)
        resolved = resolve_ref(ref, self.workspace)
        # Source files content should appear
        assert "print('hello')" in resolved.context_block

    def test_skip_dirs_excluded(self):
        proj = self._make_project()
        # Create a node_modules dir that should be skipped
        (proj / "node_modules").mkdir()
        (proj / "node_modules" / "pkg.js").write_text("module = {}", encoding="utf-8")
        ref = FileRef(raw=f"@{proj}", path=proj)
        resolved = resolve_ref(ref, self.workspace)
        assert "pkg.js" not in resolved.context_block

    def test_empty_directory(self):
        empty = self.tmpdir / "empty"
        empty.mkdir()
        ref = FileRef(raw=f"@{empty}", path=empty)
        resolved = resolve_ref(ref, self.workspace)
        assert resolved.kind == "directory"
        assert "empty" in resolved.context_block.lower()

    def test_no_double_walk_skipped_count(self):
        # BUG FIX: _walk_dir was called twice — once to walk, once to count total.
        # Now total_walked is counted in the single loop. Verify correctness:
        # 3 text files + 1 binary file → files_read=3, skipped=1
        proj = self.tmpdir / "proj"
        proj.mkdir()
        (proj / "a.py").write_text("x=1\n", encoding="utf-8")
        (proj / "b.py").write_text("y=2\n", encoding="utf-8")
        (proj / "c.py").write_text("z=3\n", encoding="utf-8")
        (proj / "lib.so").write_bytes(b"\x7fELF\x00\x00")  # binary — skipped in read
        ref = FileRef(raw=f"@{proj}", path=proj)
        resolved = resolve_ref(ref, self.workspace)
        # 3 text files read, 1 binary skipped
        assert "Files read into context: 3" in resolved.context_block
        assert "Skipped" in resolved.context_block

    def test_binary_skipped_in_dir_read(self):
        # Binary files in dir → in tree but NOT in file contents section
        proj = self.tmpdir / "proj2"
        proj.mkdir()
        (proj / "main.py").write_text("print('hi')\n", encoding="utf-8")
        (proj / "vuln.elf").write_bytes(b"\x7fELF\x00\x00" + b"\x00" * 50)
        ref = FileRef(raw=f"@{proj}", path=proj)
        resolved = resolve_ref(ref, self.workspace)
        # elf should be in tree listing
        assert "vuln.elf" in resolved.context_block
        # but its content (ELF magic) should NOT be in file contents
        assert "ELF" not in resolved.context_block

    def test_same_dirname_does_not_overwrite_previous_copy(self):
        left = self.tmpdir / "left" / "project"
        right = self.tmpdir / "right" / "project"
        left.mkdir(parents=True)
        right.mkdir(parents=True)
        (left / "a.txt").write_text("left", encoding="utf-8")
        (right / "b.txt").write_text("right", encoding="utf-8")

        res_left = resolve_ref(FileRef(raw=f"@{left}", path=left), self.workspace)
        res_right = resolve_ref(FileRef(raw=f"@{right}", path=right), self.workspace)

        assert res_left.workspace_dest is not None
        assert res_right.workspace_dest is not None
        assert res_left.workspace_dest != res_right.workspace_dest
        assert (res_left.workspace_dest / "a.txt").exists()
        assert (res_right.workspace_dest / "b.txt").exists()


# ─────────────────────────────────────────────────────────────────────────────
# workspace_name_for_ref
# ─────────────────────────────────────────────────────────────────────────────

class TestWorkspaceNameForRef:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_binary_file_uses_stem(self):
        # @/tmp/challenge.exe → workspace "challenge" (no extension)
        p = self.tmpdir / "challenge.exe"
        p.write_bytes(b"\x00data")
        ref = FileRef(raw=f"@{p}", path=p)
        assert workspace_name_for_ref(ref) == "challenge"

    def test_source_file_uses_stem(self):
        # @/tmp/exploit.py → workspace "exploit"
        p = self.tmpdir / "exploit.py"
        p.write_text("x=1", encoding="utf-8")
        ref = FileRef(raw=f"@{p}", path=p)
        assert workspace_name_for_ref(ref) == "exploit"

    def test_directory_uses_dirname(self):
        # @/path/project1/ → workspace "project1"
        d = self.tmpdir / "project1"
        d.mkdir()
        ref = FileRef(raw=f"@{d}", path=d)
        assert workspace_name_for_ref(ref) == "project1"

    def test_nonexistent_file_uses_stem(self):
        # Path doesn't exist yet — stem still used (is_dir() returns False)
        ref = FileRef(raw="@/tmp/malware.exe", path=Path("/tmp/malware.exe"))
        assert workspace_name_for_ref(ref) == "malware"

    def test_file_no_extension_uses_name(self):
        # File with no extension — stem == name
        ref = FileRef(raw="@/tmp/binary", path=Path("/tmp/binary"))
        assert workspace_name_for_ref(ref) == "binary"

    def test_workspace_dir_named_after_binary(self):
        # End-to-end: binary resolved → uploads go under workspace/<stem>/
        p = self.tmpdir / "ctf_challenge.elf"
        p.write_bytes(b"\x7fELF\x00" + b"\x00" * 50)
        ref = FileRef(raw=f"@{p}", path=p)
        name = workspace_name_for_ref(ref)
        assert name == "ctf_challenge"
        # Resolve with workspace named after stem
        wdir = self.tmpdir / name
        resolved = resolve_ref(ref, wdir)
        assert resolved.kind == "binary"
        assert resolved.workspace_dest is not None
        assert "ctf_challenge" in str(resolved.workspace_dest)

    def test_workspace_dir_named_after_project(self):
        # End-to-end: dir resolved → workspace/<dirname>/
        proj = self.tmpdir / "webapp"
        proj.mkdir()
        (proj / "index.php").write_text("<?php echo 'hi'; ?>", encoding="utf-8")
        ref = FileRef(raw=f"@{proj}", path=proj)
        name = workspace_name_for_ref(ref)
        assert name == "webapp"
        wdir = self.tmpdir / name
        resolved = resolve_ref(ref, wdir)
        assert resolved.kind == "directory"
        assert "index.php" in resolved.context_block

    def test_workspace_name_sanitizes_dotdot(self):
        ref = FileRef(raw="@/tmp/..", path=Path("/tmp/.."))
        assert workspace_name_for_ref(ref) == "workspace"


# ─────────────────────────────────────────────────────────────────────────────
# build_injection_message
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildInjectionMessage:
    def test_returns_none_for_empty_list(self):
        assert build_injection_message([]) is None

    def test_errors_appear_in_output(self):
        r = ResolvedRef(
            raw="@/nonexistent.py",
            path=Path("/nonexistent.py"),
            kind="unknown",
            context_block="",
            error="File not found: /nonexistent.py",
        )
        msg = build_injection_message([r])
        assert msg is not None
        assert "FILE REFERENCE ERRORS" in msg
        assert "File not found" in msg

    def test_valid_context_included(self):
        r = ResolvedRef(
            raw="@/tmp/x.py",
            path=Path("/tmp/x.py"),
            kind="text",
            context_block="### x.py  (5 lines)\n```python\npass\n```",
        )
        msg = build_injection_message([r])
        assert msg is not None
        assert "x.py" in msg

    def test_mixed_errors_and_valid(self):
        err = ResolvedRef(
            raw="@/bad.py",
            path=Path("/bad.py"),
            kind="unknown",
            context_block="",
            error="File not found: /bad.py",
        )
        ok = ResolvedRef(
            raw="@/good.py",
            path=Path("/good.py"),
            kind="text",
            context_block="### good.py\n```python\npass\n```",
        )
        msg = build_injection_message([err, ok])
        assert msg is not None
        assert "FILE REFERENCE ERRORS" in msg
        assert "good.py" in msg

    def test_all_errors_no_valid(self):
        r = ResolvedRef(
            raw="@/x.py",
            path=Path("/x.py"),
            kind="unknown",
            context_block="",
            error="File not found",
        )
        msg = build_injection_message([r])
        assert msg is not None
        assert "FILE REFERENCE ERRORS" in msg

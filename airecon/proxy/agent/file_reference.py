"""File reference resolution for @/path syntax in user prompts.

Supports:
    @/path/to/file.exe      → binary: copy to Docker workspace, inject info
    @/path/to/source.py     → text: inject content into context
    @/path/to/project/      → directory: inject tree + key file contents
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("airecon.file_reference")

# Matches @/absolute/path — stops at whitespace or quote
_AT_REF_RE = re.compile(r"@(/[^\s\"'<>]+)")

# Binary extensions — copy to workspace, let LLM use execute tools on them
_BINARY_EXTENSIONS = frozenset({
    ".exe", ".elf", ".bin", ".so", ".dll", ".dylib",
    ".o", ".out", ".pyc", ".pyd", ".wasm", ".ko",
    ".sys", ".drv", ".class", ".jar", ".apk", ".dex",
    ".img", ".iso", ".rom", ".fw",
})

# Text/source extensions — read content directly
_TEXT_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb",
    ".go", ".rs", ".java", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".swift", ".kt", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".html", ".css", ".json",
    ".xml", ".yaml", ".yml", ".toml", ".ini", ".conf",
    ".cfg", ".env", ".sql", ".md", ".txt", ".log",
    ".dockerfile", ".tf", ".lua", ".pl", ".r",
    ".asm", ".s", ".nasm",  # Assembly (useful for CTF RE)
})

# Skip these dirs when walking a directory reference
_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", ".tox", "dist", "build", "target", ".idea",
    ".vscode", "vendor", "deps", ".cache", ".mypy_cache",
})

# Limits
_MAX_TEXT_FILE_SIZE = 300_000   # 300KB per single text file
_MAX_DIR_FILES = 40             # Max files to read from a directory
_MAX_DIR_FILE_SIZE = 50_000     # 50KB per file when scanning a dir
_MAX_TOTAL_DIR_CONTENT = 200_000  # 200KB total directory content


def _sanitize_workspace_name(name: str) -> str:
    """Return a safe workspace subdirectory name."""
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", name).strip("._-")
    if not safe or safe in {".", ".."}:
        return "workspace"
    return safe


@dataclass
class FileRef:
    """A parsed @/path reference from the user message."""
    raw: str        # Original token e.g. "@/tmp/challenge.exe"
    path: Path      # Resolved absolute path
    start: int = 0  # Start offset in original message (inclusive)
    end: int = 0    # End offset in original message (exclusive)


@dataclass
class ResolvedRef:
    """Result of resolving a FileRef."""
    raw: str
    path: Path
    kind: str                          # "binary" | "text" | "directory" | "unknown"
    context_block: str                 # System message content to inject
    workspace_dest: Path | None = None # Where referenced content was copied
    error: str | None = None


def parse_refs(message: str) -> list[FileRef]:
    """Extract all @/path tokens from a user message."""
    refs: list[FileRef] = []
    for m in _AT_REF_RE.finditer(message):
        path_str = m.group(1)      # "/path/..."
        # Trim trailing punctuation that may not be part of the path
        trimmed = path_str.rstrip(".,;:!?)")
        if not trimmed.startswith("/"):
            continue
        strip_count = len(path_str) - len(trimmed)
        token_start = m.start(0)   # starts at "@"
        token_end = m.end(0) - strip_count
        if token_end <= token_start:
            continue
        raw = message[token_start:token_end]
        refs.append(
            FileRef(
                raw=raw,
                path=Path(trimmed),
                start=token_start,
                end=token_end,
            )
        )
    return refs


def strip_refs(message: str, refs: list[FileRef]) -> str:
    """Remove @/path tokens from message, replacing with human description."""
    if not refs:
        return message

    result = message
    # Replace from right to left so stored spans remain valid.
    for ref in sorted(refs, key=lambda r: r.start, reverse=True):
        name = ref.path.name or "ref"
        # Avoid dots/spaces so target extraction doesn't treat replacement as domain.
        safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", name).strip("_") or "ref"
        replacement = f"[file:{safe_name}]"
        if ref.end > ref.start:
            result = result[:ref.start] + replacement + result[ref.end:]
        else:
            # Backward-compatible path for tests/manual FileRef construction.
            result = result.replace(ref.raw, replacement)
    return result


def resolve_ref(
    ref: FileRef,
    workspace_target_dir: Path,
) -> ResolvedRef:
    """Resolve a single file reference to context content.

    Args:
        ref: The parsed @/path reference.
        workspace_target_dir: The target's workspace directory,
            e.g. <workspace_root>/<target>/. Files are copied here
            so Docker can access them at /workspace/<target>/...
    """
    path = ref.path

    if not path.exists():
        return ResolvedRef(
            raw=ref.raw,
            path=path,
            kind="unknown",
            context_block="",
            error=f"File not found: {path}",
        )

    if path.is_dir():
        return _resolve_directory(ref, workspace_target_dir)

    ext = path.suffix.lower()

    if ext in _BINARY_EXTENSIONS or _is_binary_file(path):
        return _resolve_binary(ref, workspace_target_dir)

    return _resolve_text(ref, workspace_target_dir)


# ──────────────────────────────────────────────────────────────────────────────
# Handlers
# ──────────────────────────────────────────────────────────────────────────────

def _resolve_binary(ref: FileRef, workspace_dir: Path) -> ResolvedRef:
    """Copy binary to workspace so Docker can analyze it."""
    path = ref.path

    try:
        dest = _copy_file_to_uploads(path, workspace_dir)
        logger.info("Copied binary %s → %s", path, dest)
    except OSError as e:
        return ResolvedRef(
            raw=ref.raw, path=path, kind="binary", context_block="",
            error=f"Failed to copy '{path.name}': {e}",
        )

    docker_path = _docker_path_for(dest, fallback=Path("/workspace/uploads") / path.name)

    size_kb = path.stat().st_size // 1024
    ext = path.suffix.lower()

    # Determine file category for hints
    if ext == ".exe" or ext in (".dll", ".sys"):
        arch_hint = "Windows PE binary"
        tools_hint = (
            "file, strings -n 6, checksec, "
            "objdump -d, wine (if 32/64-bit exe)"
        )
    elif ext in (".elf", ".out", ".so", ".ko"):
        arch_hint = "ELF binary"
        tools_hint = "file, strings -n 6, checksec, readelf -h, objdump -d, ltrace, strace"
    elif ext in (".apk", ".dex"):
        arch_hint = "Android APK/DEX"
        tools_hint = "apktool d, jadx, strings, dexdump"
    elif ext in (".jar", ".class"):
        arch_hint = "Java bytecode"
        tools_hint = "javap -c, cfr decompiler, strings"
    elif ext == ".pyc":
        arch_hint = "Python compiled bytecode"
        tools_hint = "python3 -m dis, uncompyle6"
    else:
        arch_hint = "binary file"
        tools_hint = "file, strings -n 6, xxd | head -30, binwalk"

    context_block = f"""[FILE REFERENCE — BINARY]
Name      : {path.name}
Type      : {arch_hint}
Size      : {size_kb} KB
Host path : {path}
Docker path: {docker_path}

The file has been copied into the Docker workspace.
Use the execute tool to analyze it:
  file {docker_path}
  strings -n 6 {docker_path} | head -60
  checksec --file={docker_path}
  {tools_hint.split(",")[0].strip()} {docker_path}

Suggested first steps depending on task:
  CTF/Reversing  → file + strings + ltrace + r2 -A + pdg @ main
  Malware analysis → strings + xxd + strace + ltrace
  Vuln research  → checksec + ROPgadget + gdb
"""

    return ResolvedRef(
        raw=ref.raw,
        path=path,
        kind="binary",
        context_block=context_block,
        workspace_dest=dest,
    )


def _resolve_text(ref: FileRef, workspace_dir: Path) -> ResolvedRef:
    """Read text/source file, copy to workspace, and inject its content."""
    path = ref.path
    size = path.stat().st_size
    try:
        dest = _copy_file_to_uploads(path, workspace_dir)
    except OSError as e:
        return ResolvedRef(
            raw=ref.raw, path=path, kind="text", context_block="",
            error=f"Failed to copy '{path.name}': {e}",
        )
    docker_path = _docker_path_for(dest, fallback=Path("/workspace/uploads") / path.name)

    if size > _MAX_TEXT_FILE_SIZE:
        # File too large — just show header and tail
        text_block = _read_partial(path, max_bytes=_MAX_TEXT_FILE_SIZE)
    else:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return ResolvedRef(
                raw=ref.raw, path=path, kind="text", context_block="",
                error=str(e),
            )
        text_block = _format_text_block(path, content)
    context_block = f"""[FILE REFERENCE — TEXT]
Name      : {path.name}
Host path : {path}
Docker path: {docker_path}

{text_block}
"""

    return ResolvedRef(
        raw=ref.raw,
        path=path,
        kind="text",
        context_block=context_block,
        workspace_dest=dest,
    )


def _resolve_directory(ref: FileRef, workspace_dir: Path) -> ResolvedRef:
    """Copy a directory to workspace, then inject tree + key file contents."""
    path = ref.path
    try:
        dest, copied_files = _copy_directory_to_uploads(path, workspace_dir)
    except OSError as e:
        return ResolvedRef(
            raw=ref.raw, path=path, kind="directory", context_block="",
            error=f"Failed to copy directory '{path.name}': {e}",
        )
    docker_path = _docker_path_for(dest, fallback=Path("/workspace/uploads") / path.name)
    tree_lines: list[str] = []
    file_contents: list[str] = []
    total_content_size = 0
    files_read = 0
    total_walked = 0

    # Build tree and collect readable files — single walk
    for fpath in _walk_dir(path):
        total_walked += 1
        rel = fpath.relative_to(path)
        ext = fpath.suffix.lower()
        size = fpath.stat().st_size

        tree_lines.append(f"  {rel}  ({size // 1024}KB)" if size > 1024 else f"  {rel}")

        # Read source/text files up to limits
        if (
            ext in _TEXT_EXTENSIONS
            and size <= _MAX_DIR_FILE_SIZE
            and files_read < _MAX_DIR_FILES
            and total_content_size < _MAX_TOTAL_DIR_CONTENT
        ):
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                block = _format_text_block(fpath, content, base=path)
                file_contents.append(block)
                total_content_size += len(content)
                files_read += 1
            except OSError:
                pass

    tree_str = "\n".join(tree_lines) if tree_lines else "  (empty)"
    content_str = "\n\n".join(file_contents) if file_contents else ""

    skipped = total_walked - files_read
    summary = (
        f"Files copied: {copied_files} | Files read: {files_read}"
        + (f" | Skipped (too large/binary): {skipped}" if skipped > 0 else "")
    )

    context_block = f"""[FILE REFERENCE — DIRECTORY]
Path : {path}
Docker path: {docker_path}
{summary}

Directory tree:
{tree_str}

--- File Contents ---
{content_str if content_str else "(no readable source files found)"}
"""

    return ResolvedRef(
        raw=ref.raw,
        path=path,
        kind="directory",
        context_block=context_block,
        workspace_dest=dest,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _walk_dir(base: Path):
    """Yield all files under base, skipping _SKIP_DIRS."""
    for item in sorted(base.rglob("*")):
        if item.is_file() and not item.is_symlink():
            # Skip if any parent component is in _SKIP_DIRS
            parts = set(item.relative_to(base).parts[:-1])
            if parts & _SKIP_DIRS:
                continue
            yield item


def _copy_file_to_uploads(src: Path, workspace_dir: Path) -> Path:
    """Copy a single file into workspace uploads/ and return destination path."""
    uploads_dir = workspace_dir / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    dest = _unique_file_path(uploads_dir, src.name)
    shutil.copy2(src, dest)
    return dest


def _copy_directory_to_uploads(src_dir: Path, workspace_dir: Path) -> tuple[Path, int]:
    """Copy directory tree into workspace uploads/, skipping heavy cache dirs/symlinks."""
    uploads_dir = workspace_dir / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    dest_name = src_dir.name or "directory"
    dest_dir = _unique_directory_path(uploads_dir, dest_name)
    dest_dir.mkdir(parents=True, exist_ok=True)

    copied_files = 0
    for root, dirs, files in os.walk(src_dir, topdown=True, followlinks=False):
        root_path = Path(root)
        dirs[:] = [
            d for d in dirs
            if d not in _SKIP_DIRS and not (root_path / d).is_symlink()
        ]
        for fname in files:
            src_file = root_path / fname
            if src_file.is_symlink():
                continue
            rel = src_file.relative_to(src_dir)
            dst_file = dest_dir / rel
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dst_file)
            copied_files += 1
    return dest_dir, copied_files


def _docker_path_for(path: Path, fallback: Path) -> Path:
    """Convert a host workspace path to container /workspace path."""
    try:
        from ..config import get_workspace_root
        workspace_root = get_workspace_root()
        return Path("/workspace") / path.relative_to(workspace_root)
    except (ValueError, Exception):
        return fallback


def _format_text_block(
    path: Path,
    content: str,
    base: Path | None = None,
) -> str:
    label = str(path.relative_to(base)) if base else path.name
    lang = _ext_to_lang(path.suffix.lower())
    lines = content.count("\n")
    return f"### {label}  ({lines} lines)\n```{lang}\n{content}\n```"


def _ext_to_lang(ext: str) -> str:
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".php": "php", ".rb": "ruby", ".go": "go", ".rs": "rust",
        ".java": "java", ".c": "c", ".cpp": "cpp", ".h": "c",
        ".cs": "csharp", ".sh": "bash", ".bash": "bash",
        ".ps1": "powershell", ".sql": "sql", ".json": "json",
        ".xml": "xml", ".yaml": "yaml", ".yml": "yaml",
        ".html": "html", ".css": "css", ".asm": "asm", ".s": "asm",
        ".nasm": "nasm",
    }.get(ext, "")


def _is_binary_file(path: Path) -> bool:
    """Heuristic check: read first 1024 bytes, count null bytes."""
    try:
        with path.open("rb") as f:
            chunk = f.read(1024)
        return b"\x00" in chunk
    except OSError:
        return False


def _read_partial(path: Path, max_bytes: int) -> str:
    try:
        size = path.stat().st_size
        head_bytes = max(1, max_bytes // 2)
        tail_bytes = max(1, max_bytes // 4)

        with path.open("rb") as f:
            head_raw = f.read(head_bytes)

        with path.open("rb") as f:
            f.seek(max(size - tail_bytes, 0))
            tail_raw = f.read(tail_bytes)

        head = head_raw.decode("utf-8", errors="replace")
        tail = tail_raw.decode("utf-8", errors="replace")
        lang = _ext_to_lang(path.suffix.lower())
        size_kb = max(1, size // 1024)
        return (
            f"### {path.name}  ({size_kb} KB — truncated, file too large)\n"
            f"```{lang}\n"
            f"--- HEAD ---\n{head}\n"
            f"...\n"
            f"--- TAIL ---\n{tail}\n"
            f"```"
        )
    except OSError as e:
        return f"Error reading {path.name}: {e}"


def workspace_name_for_ref(ref: FileRef) -> str:
    """Return the workspace subdirectory name to use for a file/dir reference.

    - Directory ref  @/path/project1/   → "project1"
    - Binary file    @/path/challenge.exe → "challenge"  (stem, no extension)
    - Text file      @/path/source.py    → "source"     (stem, no extension)
    - Unknown/empty path                 → "workspace"  (fallback)
    """
    path = ref.path
    # Directory: use the directory name directly
    if path.is_dir():
        return _sanitize_workspace_name(path.name or "workspace")
    # File: stem (name without extension) is cleaner as a workspace folder name
    stem = path.stem
    return _sanitize_workspace_name(stem if stem else (path.name or "workspace"))


def _unique_file_path(parent_dir: Path, filename: str) -> Path:
    """Return a non-colliding file path under parent_dir."""
    base = Path(filename)
    stem = base.stem
    suffix = base.suffix
    candidate = parent_dir / filename
    if not candidate.exists():
        return candidate

    idx = 1
    while True:
        candidate = parent_dir / f"{stem}_{idx}{suffix}"
        if not candidate.exists():
            return candidate
        idx += 1


def _unique_directory_path(parent_dir: Path, dirname: str) -> Path:
    """Return a non-colliding directory path under parent_dir."""
    candidate = parent_dir / dirname
    if not candidate.exists():
        return candidate

    idx = 1
    while True:
        candidate = parent_dir / f"{dirname}_{idx}"
        if not candidate.exists():
            return candidate
        idx += 1


def build_injection_message(resolved: list[ResolvedRef]) -> str | None:
    """Build the system message to inject for all resolved refs.

    Returns None if there's nothing useful to inject.
    """
    parts: list[str] = []

    errors = [r for r in resolved if r.error]
    valid = [r for r in resolved if not r.error]

    if errors:
        err_lines = "\n".join(f"  - {r.path}: {r.error}" for r in errors)
        parts.append(f"[FILE REFERENCE ERRORS]\n{err_lines}")

    for r in valid:
        parts.append(r.context_block)

    return "\n\n".join(parts) if parts else None

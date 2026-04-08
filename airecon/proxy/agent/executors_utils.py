"""
Utility tools executor: python_session, edit_file, think, notes.
"""

from __future__ import annotations

import json
import logging
import secrets
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import get_workspace_root

logger = logging.getLogger("airecon.agent")


# === Python Session Management ===


class _PythonSession:
    """Persistent Python interpreter session."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._namespace: dict[str, Any] = {}
        self._history: list[str] = []
        self.last_updated = time.time()
        self._bootstrap()

    def _bootstrap(self):
        """Initialize session with common imports."""
        bootstrap = """
import os
import sys
import json
import re
import base64
import hashlib
import random
import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote, unquote

# Workspace helper
def ws(path):
    from airecon.proxy.config import get_workspace_root
    return str(get_workspace_root() / path)

# Print helper
def jprint(data):
    print(json.dumps(data, indent=2, default=str))

# Convenience: http request (if requests available)
try:
    import requests
except ImportError:
    requests = None
"""
        self._exec(bootstrap)

    def _exec(self, code: str) -> dict[str, Any]:
        """Execute code and capture output."""
        from io import StringIO

        result_value = None
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = StringIO()
        sys.stderr = StringIO()

        try:
            # Compile to check syntax
            try:
                compile(code, "<python_session>", "single")
            except SyntaxError as e:
                return {
                    "output": "",
                    "error": f"SyntaxError: {e.msg} (line {e.lineno})",
                    "result": None,
                }

            # Execute in namespace
            try:
                # If it's a print statement, we'll exec and capture output
                if code.strip().startswith(("print(", "print ")):
                    exec(code, self._namespace)  # nosec B102 -- intentional for Python REPL
                else:
                    # Try eval first to capture result of expression
                    try:
                        result_value = eval(code, self._namespace)  # nosec B307 -- intentional for Python REPL
                        self._namespace["_"] = result_value
                    except (SyntaxError, NameError):
                        # Not an expression or undefined, use exec
                        exec(code, self._namespace)  # nosec B102 -- intentional for Python REPL
            except Exception as e:
                tb = traceback.format_exc()
                return {
                    "output": "",
                    "error": f"{type(e).__name__}: {e}\n{tb}",
                    "result": None,
                }

            # Get captured output
            stdout_val = sys.stdout.getvalue()
            stderr_val = sys.stderr.getvalue()

            output = stdout_val + stderr_val
            return {
                "output": output.strip(),
                "error": None,
                "result": str(result_value) if result_value is not None else None,
            }

        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def execute(self, code: str) -> dict[str, Any]:
        """Execute code and update session."""
        self.last_updated = time.time()
        result = self._exec(code)
        self._history.append(code)
        if len(self._history) > 100:
            self._history = self._history[-100:]
        return result

    def get_state(self) -> dict[str, Any]:
        """Return namespace snapshot."""
        state = {}
        for k, v in self._namespace.items():
            if k.startswith("__"):
                continue
            try:
                if isinstance(v, (str, int, float, bool, list, dict, tuple, set)):
                    state[k] = repr(v)[:200]
            except Exception as _e:
                state[k] = "<unrepresentable>"
        return state


# === Notes System ===


class _NotesManager:
    """Manages structured notes with categories and tags."""

    def __init__(self, storage_dir: Path):
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.notes_index: dict[str, dict] = {}
        self._load_index()

    def _load_index(self):
        index_file = self.storage_dir / "notes_index.json"
        if index_file.exists():
            try:
                self.notes_index = json.loads(index_file.read_text(encoding="utf-8"))
            except Exception as _e:
                self.notes_index = {}

    def _save_index(self):
        index_file = self.storage_dir / "notes_index.json"
        index_file.write_text(json.dumps(self.notes_index, indent=2), encoding="utf-8")

    def create(
        self,
        category: str,
        title: str,
        content: str,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new note."""
        note_id = (
            f"note_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
        )
        note = {
            "id": note_id,
            "category": category,
            "title": title,
            "content": content,
            "tags": tags or [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
        }
        self.notes_index[note_id] = note
        self._save_index()
        # Also write individual markdown file for wiki export
        note_file = self.storage_dir / f"{note_id}.md"
        note_file.write_text(self._to_markdown(note), encoding="utf-8")
        return {
            "success": True,
            "message": (
                "Working note saved. This is session documentation only, "
                "not a final vulnerability report."
            ),
            "artifact_type": "working_note",
            "report_generated": False,
            "note_id": note_id,
            "note_path": str(note_file),
            "note": note,
        }

    def _to_markdown(self, note: dict) -> str:
        return f"""# {note["title"]}

**Category:** {note["category"]}
**Created:** {note["created_at"]}
**Tags:** {note.get("tags", [])}

{note["content"]}
"""

    def list_notes(
        self,
        category: str | None = None,
        tag: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        notes = list(self.notes_index.values())
        if category:
            notes = [n for n in notes if str(n.get("category", "")) == str(category)]
        if tag:
            wanted = str(tag).strip().lower()
            notes = [
                n
                for n in notes
                if wanted in {str(t).strip().lower() for t in n.get("tags", [])}
            ]
        notes.sort(
            key=lambda n: (
                str(n.get("updated_at", "")),
                str(n.get("created_at", "")),
                str(n.get("id", "")),
            ),
            reverse=True,
        )
        return [
            {
                "id": n.get("id", ""),
                "title": n.get("title", ""),
                "category": n.get("category", ""),
                "tags": list(n.get("tags", []) or []),
                "created_at": n.get("created_at", ""),
                "updated_at": n.get("updated_at", ""),
            }
            for n in notes[: max(1, int(limit))]
        ]

    def search(
        self,
        query: str,
        category: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        needle = str(query or "").strip().lower()
        if not needle:
            return []

        notes = list(self.notes_index.values())
        if category:
            notes = [n for n in notes if str(n.get("category", "")) == str(category)]

        matches: list[dict[str, Any]] = []
        for note in notes:
            haystack = "\n".join(
                [
                    str(note.get("title", "")),
                    str(note.get("content", "")),
                    str(note.get("category", "")),
                    " ".join(str(t) for t in note.get("tags", []) or []),
                ]
            ).lower()
            if needle not in haystack:
                continue
            matches.append(note)

        matches.sort(
            key=lambda n: (
                str(n.get("updated_at", "")),
                str(n.get("created_at", "")),
                str(n.get("id", "")),
            ),
            reverse=True,
        )
        return matches[: max(1, int(limit))]

    def get(self, note_id: str) -> dict[str, Any] | None:
        return self.notes_index.get(str(note_id or "").strip())

    def export_wiki(self, output_path: Path) -> dict[str, Any]:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        notes = list(self.notes_index.values())
        notes.sort(
            key=lambda n: (
                str(n.get("category", "")),
                str(n.get("created_at", "")),
                str(n.get("id", "")),
            )
        )

        sections = ["# Notes Wiki", ""]
        current_category = None
        for note in notes:
            category = str(note.get("category", "uncategorized"))
            if category != current_category:
                current_category = category
                sections.append(f"## {category.title()}")
                sections.append("")
            sections.append(self._to_markdown(note).rstrip())
            sections.append("")

        output_path.write_text("\n".join(sections).strip() + "\n", encoding="utf-8")
        return {
            "success": True,
            "path": str(output_path),
            "count": len(notes),
        }


class _UtilsExecutorMixin:
    """Mixin providing utility tools: python_session, edit_file, think, notes."""

    def __init__(self) -> None:
        super().__init__()  # Ensure parent init
        self._ensure_utils_runtime_state()

    def _get_notes_storage_dir(self) -> Path | None:
        ws_root = get_workspace_root()
        target = ""

        state = getattr(self, "state", None)
        if state is not None:
            target = str(getattr(state, "active_target", "") or "").strip()

        if not target:
            session = getattr(self, "_session", None)
            if session is not None:
                target = str(getattr(session, "target", "") or "").strip()

        target = target.strip().strip("/")
        if not target:
            return None
        return ws_root / target / "notes"

    def _notes_manager_unavailable_result(self) -> dict[str, Any]:
        return {
            "success": False,
            "error": (
                "Notes require an active target. Start or switch to a target first "
                "so notes are stored under workspace/<target>/notes."
            ),
        }

    def _ensure_utils_runtime_state(self) -> None:
        if not hasattr(self, "_python_sessions") or not isinstance(
            self._python_sessions, dict
        ):
            self._python_sessions = {}
        if not hasattr(self, "_python_session_timeout") or not isinstance(
            self._python_session_timeout, (int, float)
        ):
            self._python_session_timeout = 300
        if not hasattr(self, "_thoughts_log") or not isinstance(
            self._thoughts_log, list
        ):
            self._thoughts_log = []
        try:
            notes_dir = self._get_notes_storage_dir()
            current_dir = getattr(self, "_notes_manager_dir", None)
            if notes_dir is None:
                self._notes_manager = None
                self._notes_manager_dir = None
            elif (
                not hasattr(self, "_notes_manager")
                or self._notes_manager is None
                or current_dir != notes_dir
            ):
                self._notes_manager = _NotesManager(notes_dir)
                self._notes_manager_dir = notes_dir
        except Exception as exc:
            logger.debug("Utility notes manager init failed: %s", exc)
            self._notes_manager = None
            self._notes_manager_dir = None

    # === Python Session ===
    async def _execute_python_session_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        code = arguments.get("code", "").strip()
        session_id = arguments.get("session_id", "default")

        if not code:
            return False, 0.0, {"success": False, "error": "code is required"}, None

        self._ensure_utils_runtime_state()
        self._cleanup_python_sessions()

        if session_id not in self._python_sessions:
            self._python_sessions[session_id] = _PythonSession(session_id)

        session = self._python_sessions[session_id]
        result = session.execute(code)

        success = result["error"] is None
        output_data = {
            "success": success,
            "output": result["output"],
            "result": result["result"],
            "session_id": session_id,
            "session_state": session.get_state(),
        }
        if result["error"]:
            output_data["error"] = result["error"]

        return success, time.time() - start_time, output_data, None

    def _cleanup_python_sessions(self) -> None:
        self._ensure_utils_runtime_state()
        now = time.time()
        expired = [
            sid
            for sid, s in self._python_sessions.items()
            if now - s.last_updated > self._python_session_timeout
        ]
        for sid in expired:
            del self._python_sessions[sid]

    # === Edit File ===
    async def _execute_edit_file_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        path = arguments.get("path", "")
        old_str = arguments.get("old_str", "")
        new_str = arguments.get("new_str", "")

        if not path or old_str is None or new_str is None:
            return (
                False,
                0.0,
                {"success": False, "error": "path, old_str, new_str are required"},
                None,
            )

        # Resolve path
        ws_root = get_workspace_root()
        file_path = (ws_root / path).resolve()
        try:
            file_path.relative_to(ws_root.resolve())
        except ValueError:
            return (
                False,
                0.0,
                {"success": False, "error": "Path outside workspace"},
                None,
            )

        if not file_path.exists():
            return (
                False,
                0.0,
                {"success": False, "error": f"File not found: {path}"},
                None,
            )

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            return False, 0.0, {"success": False, "error": f"Failed to read: {e}"}, None

        if old_str not in content:
            return (
                False,
                0.0,
                {
                    "success": False,
                    "error": "old_str not found in file (exact match required)",
                },
                None,
            )

        # Count occurrences
        count = content.count(old_str)
        if count > 1:
            # Replace only first occurrence to be surgical
            new_content = content.replace(old_str, new_str, 1)
        else:
            new_content = content.replace(old_str, new_str)

        try:
            file_path.write_text(new_content, encoding="utf-8")
            return (
                True,
                time.time() - start_time,
                {
                    "success": True,
                    "path": path,
                    "lines_modified": 1,
                    "total_occurrences": count,
                    "preview": f"Replaced first occurrence of {len(old_str)} chars with {len(new_str)} chars",
                },
                None,
            )
        except Exception as e:
            return (
                False,
                time.time() - start_time,
                {"success": False, "error": f"Failed to write: {e}"},
                None,
            )

    # === Think ===
    async def _execute_think_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        thought = arguments.get("thought", "").strip()
        category = arguments.get("category", "observation")
        confidence = arguments.get("confidence")

        if not thought:
            return False, 0.0, {"success": False, "error": "thought is required"}, None

        self._ensure_utils_runtime_state()
        entry = {
            "timestamp": datetime.now().isoformat(),
            "thought": thought,
            "category": category,
        }
        if confidence is not None:
            try:
                entry["confidence"] = float(confidence)
            except Exception as _e:
                entry["confidence"] = None

        self._thoughts_log.append(entry)

        # Also write to log file
        try:
            ws_root = get_workspace_root()
            phase = "unknown"
            if hasattr(self, "_get_current_phase"):
                try:
                    phase = self._get_current_phase().value
                except Exception as _e:
                    logger.debug("Failed to read current phase for thoughts log: %s", _e)
            log_file = ws_root / "output" / f"thoughts_{phase}.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{entry['timestamp']}] [{category.upper()}] {thought}\n")
        except Exception as e:
            logger.debug("Failed to write thoughts log: %s", e)

        return (
            True,
            time.time() - start_time,
            {
                "success": True,
                "entry": entry,
                "total_thoughts": len(self._thoughts_log),
            },
            None,
        )

    # === Notes ===
    async def _execute_create_note_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        category = arguments.get("category")
        title = arguments.get("title")
        content = arguments.get("content")
        tags = arguments.get("tags", [])

        if not category or not title or not content:
            return (
                False,
                0.0,
                {"success": False, "error": "category, title, content are required"},
                None,
            )

        if category not in {
            "vulnerability",
            "methodology",
            "finding",
            "question",
            "plan",
            "observation",
            "todo",
        }:
            return (
                False,
                0.0,
                {"success": False, "error": f"Invalid category: {category}"},
                None,
            )

        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        result = self._notes_manager.create(category, title, content, tags)
        return True, time.time() - start_time, result, None

    async def _execute_list_notes_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        category = arguments.get("category")
        tag = arguments.get("tag")
        limit = int(arguments.get("limit", 50))

        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        notes = self._notes_manager.list_notes(category=category, tag=tag, limit=limit)
        return (
            True,
            time.time() - start_time,
            {
                "success": True,
                "notes": notes,
                "count": len(notes),
            },
            None,
        )

    async def _execute_search_notes_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        query = arguments.get("query", "").strip()
        category = arguments.get("category")
        limit = int(arguments.get("limit", 20))

        if not query:
            return False, 0.0, {"success": False, "error": "query is required"}, None

        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        results = self._notes_manager.search(query, category=category, limit=limit)
        return (
            True,
            time.time() - start_time,
            {
                "success": True,
                "results": results,
                "count": len(results),
            },
            None,
        )

    async def _execute_read_note_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        note_id = arguments.get("note_id", "")

        if not note_id:
            return False, 0.0, {"success": False, "error": "note_id is required"}, None

        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        note = self._notes_manager.get(note_id)
        if note is None:
            return (
                False,
                0.0,
                {"success": False, "error": f"Note not found: {note_id}"},
                None,
            )

        return (
            True,
            time.time() - start_time,
            {
                "success": True,
                "note": note,
            },
            None,
        )

    async def _execute_export_notes_wiki_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        output_path = arguments.get("output_path")
        if output_path:
            ws_root = get_workspace_root()
            full_path = ws_root / str(output_path)
        else:
            full_path = self._notes_manager.storage_dir / "wiki.md"
        result = self._notes_manager.export_wiki(full_path)
        return True, time.time() - start_time, result, None

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

from .models import ToolExecution
from .executors_catalog import _READ_FILE_CONTENT_TRUNCATION_THRESHOLD

from ..config import get_workspace_root
from ..filesystem import create_file, list_files, read_file
from ..web_search import web_search

logger = logging.getLogger("airecon.agent")

_TARGET_RELATIVE_PATHS = frozenset(
    {
        "uploads",
        "output",
        "notes",
        "tools",
        "vulnerabilities",
        "command",
    }
)


class _FilesystemExecutorMixin:
    async def _execute_filesystem_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        def _strip_workspace_prefix(p: str) -> str:
            p = p.removeprefix("workspace/")
            return p.removeprefix("/workspace/")

        def _display_path(raw_path: str) -> str:
            clean = _strip_workspace_prefix(raw_path)
            active_target = self.state.active_target or ""
            if not active_target:
                return clean
            prefix = f"{active_target}/"
            if not clean.startswith(prefix):
                return clean
            candidate = clean[len(prefix) :]
            root = candidate.split("/", 1)[0]
            if root in _TARGET_RELATIVE_PATHS:
                return candidate
            return clean

        def _runtime_path(raw_path: str) -> str:
            clean = _strip_workspace_prefix(raw_path)
            if not clean:
                return clean
            if os.path.isabs(clean):
                return clean
            if clean.startswith("skills/"):
                return str((Path(__file__).resolve().parents[1] / clean).resolve())
            active_target = self.state.active_target or ""
            if active_target and not clean.startswith(f"{active_target}/"):
                return os.path.join(active_target, clean)
            return clean

        def _resolve_allowed_path(p: str) -> Path | None:
            ws = get_workspace_root()
            project_root = Path(__file__).resolve().parents[2]
            resolved = Path(p).resolve() if os.path.isabs(p) else (ws / p).resolve()
            try:
                resolved.relative_to(ws.resolve())
                return resolved
            except ValueError:
                try:
                    resolved.relative_to(project_root)
                    return resolved
                except ValueError:
                    return None

        try:
            history_arguments = dict(arguments)
            history_path = _display_path(str(arguments.get("path", "")))
            runtime_path = _runtime_path(str(arguments.get("path", "")))

            if _resolve_allowed_path(runtime_path) is None:
                return False, 0.0, {
                    "success": False,
                    "error": (
                        "Path traversal attempt blocked: "
                        f"'{runtime_path}' resolves outside allowed paths."
                    ),
                }, None

            history_arguments["path"] = history_path
            call_arguments = dict(arguments)
            call_arguments["path"] = runtime_path

            if tool_name == "create_file":
                result = await asyncio.to_thread(create_file, **call_arguments)
            elif tool_name == "read_file":
                path_arg_clean = history_arguments.get("path", "")
                if "skills/" in path_arg_clean and path_arg_clean.endswith(".md"):
                    skill_name = os.path.basename(
                        path_arg_clean).replace(".md", "")
                    if skill_name not in self.state.skills_used:
                        self.state.skills_used.append(skill_name)
                result = await asyncio.to_thread(
                    read_file,
                    path=call_arguments.get("path", ""),
                    offset=int(call_arguments.get("offset", 0)),
                    limit=int(call_arguments.get("limit", 500)),
                )
            elif tool_name == "list_files":
                result = await asyncio.to_thread(
                    list_files,
                    path=call_arguments.get("path", ""),
                )
            else:
                result = {
                    "success": False,
                    "error": f"Unknown filesystem tool: {tool_name}"}

            success = result.get("success", False)
            try:
                self._save_tool_output(tool_name, history_arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Filesystem tool exec error: %s", e)

        duration = time.time() - start_time

        history_result = result
        if tool_name == "read_file" and success:
            content = result.get("result", "")
            if len(content) > _READ_FILE_CONTENT_TRUNCATION_THRESHOLD:
                history_result = {
                    "success": True,
                    "result": f"<File content loaded ({len(content)} chars). Truncated in history.>",
                    "truncated": True,
                }

        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=history_arguments,
                result=history_result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1
        return success, duration, result, self._last_output_file

    async def _execute_web_search_tool(
        self,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        try:
            result = await web_search(
                query=arguments.get("query", ""),
                max_results=arguments.get("max_results", 10),
            )
            success = result.get("success", False)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Web search tool error: %s", e)

        duration = time.time() - start_time

        saved_path: str | None = None
        if success and self.state.active_target:
            try:
                host_output = (
                    get_workspace_root()
                    / self.state.active_target
                    / "output"
                )
                host_output.mkdir(parents=True, exist_ok=True)
                dork_file = host_output / "dork_results.txt"
                query = arguments.get("query", "")
                entry = (
                    f"\n{'=' * 60}\n"
                    f"QUERY: {query}\n"
                    f"{'=' * 60}\n"
                    f"{result.get('result', '')}\n"
                )
                with open(dork_file, "a", encoding="utf-8") as f:
                    f.write(entry)
                saved_path = "output/dork_results.txt"

                result = dict(result)
                result["saved_to"] = saved_path
                result["result"] = (
                    result.get("result", "")
                    + f"\n\n[Auto-saved to {saved_path}]"
                )
            except Exception as e:
                logger.warning("Failed to auto-save dork results: %s", e)

        self.state.tool_history.append(
            ToolExecution(
                tool_name="web_search", arguments=arguments,
                result=result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1
        return success, duration, result, saved_path

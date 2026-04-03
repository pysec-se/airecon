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
from .executors_catalog import (
    _REPORT_FILE_PATTERNS,
)

logger = logging.getLogger("airecon.agent")


class _FilesystemExecutorMixin:
    async def _execute_filesystem_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        try:
            path_arg = arguments.get("path", "")
            if path_arg.startswith("workspace/"):
                path_arg = path_arg[10:]
            elif path_arg.startswith("/workspace/"):
                path_arg = path_arg[11:]

            if self.state.active_target:
                if not path_arg.startswith(self.state.active_target) and not os.path.isabs(
                        path_arg):
                    path_arg = os.path.join(
                        self.state.active_target,
                        path_arg)

            workspace_root = get_workspace_root()
            resolved = (workspace_root / path_arg).resolve()
            try:
                resolved.relative_to(workspace_root.resolve())
            except ValueError:
                return False, 0.0, {
                    "success": False,
                    "error": f"Path traversal attempt blocked: '{path_arg}' resolves outside workspace.",
                }, None

            arguments["path"] = path_arg

            if tool_name == "create_file":

                _raw_path = str(arguments.get("path", "")).strip()
                _is_skill_file = "skills/" in _raw_path.replace("\\", "/")
                basename_lower = Path(_raw_path).name.lower()
                if (
                    not _is_skill_file
                    and basename_lower.endswith(".md")
                    and any(token in basename_lower for token in _REPORT_FILE_PATTERNS)
                ):
                    return False, 0.0, {
                        "success": False,
                        "error": (
                            "BLOCKED: Writing vulnerability findings to markdown is forbidden. "
                            "Use create_vulnerability_report for confirmed findings."
                        ),
                    }, None
                result = await asyncio.to_thread(create_file, **arguments)
            elif tool_name == "read_file":
                path_arg_clean = arguments.get("path", "")
                if "skills/" in path_arg_clean and path_arg_clean.endswith(".md"):
                    skill_name = os.path.basename(
                        path_arg_clean).replace(".md", "")
                    if skill_name not in self.state.skills_used:
                        self.state.skills_used.append(skill_name)
                result = await asyncio.to_thread(
                    read_file,
                    path=path_arg_clean,
                    offset=int(arguments.get("offset", 0)),
                    limit=int(arguments.get("limit", 500)),
                )
            elif tool_name == "list_files":
                result = await asyncio.to_thread(
                    list_files,
                    path=arguments.get("path", ""),
                )
            else:
                result = {
                    "success": False,
                    "error": f"Unknown filesystem tool: {tool_name}"}

            success = result.get("success", False)
            try:
                self._save_tool_output(tool_name, arguments, result)
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
                tool_name=tool_name, arguments=arguments,
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

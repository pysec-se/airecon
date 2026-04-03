from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from typing import Any

from ..config import get_workspace_root

logger = logging.getLogger("airecon.agent")

class _WorkspaceMixin:

    _FILE_EXTENSIONS = frozenset({
        "json", "txt", "xml", "html", "htm", "csv", "yaml", "yml", "md", "rst",
        "py", "js", "ts", "sh", "rb", "go", "php", "java", "c", "cpp", "h",
        "log", "conf", "cfg", "ini", "toml", "lock", "env",
        "pdf", "png", "jpg", "jpeg", "gif", "svg", "ico",
        "zip", "tar", "gz", "bz2", "xz", "whl", "deb", "rpm",
        "out", "bin", "exe", "so", "dylib",
    })

    _WORKSPACE_SCAN_EXTENSIONS = frozenset({
        ".txt", ".json", ".html", ".htm", ".csv", ".xml",
        ".out", ".md", ".log", ".nmap",
    })

    def _scan_workspace_state(self, target: str) -> str:
        try:
            base_dir = str(get_workspace_root() / target)
            if not os.path.exists(base_dir):
                return ""

            output_dir = os.path.join(base_dir, "output")
            tools_dir = os.path.join(base_dir, "tools")
            vuln_dir = os.path.join(base_dir, "vulnerabilities")

            files_info = []

            if os.path.exists(output_dir):
                for f in sorted(os.listdir(output_dir)):
                    ext = os.path.splitext(f)[1].lower()
                    if ext not in self._WORKSPACE_SCAN_EXTENSIONS:
                        continue
                    path = os.path.join(output_dir, f)
                    size = os.path.getsize(path)
                    lines = 0

                    if size < 1_000_000 and ext in {
                            ".txt", ".csv", ".out", ".log", ".nmap"}:
                        try:
                            with open(path, "r", errors="ignore") as fh:
                                lines = sum(1 for _ in fh)
                        except Exception:
                            pass
                    info = f"- /workspace/{target}/output/{f} ({size} bytes"
                    if lines:
                        info += f", {lines} lines"
                    info += ")"
                    files_info.append(info)

            if os.path.exists(tools_dir):
                for f in sorted(os.listdir(tools_dir)):
                    files_info.append(
                        f"- [SCRIPT] /workspace/{target}/tools/{f}")

            if os.path.exists(vuln_dir):
                for f in sorted(os.listdir(vuln_dir)):
                    if f.endswith(".md"):
                        files_info.append(
                            f"- [REPORTED] /workspace/{target}/vulnerabilities/{f}")

            if not files_info:
                return ""

            return (
                f"[SYSTEM: WORKSPACE for {target}]\n"
                + "\n".join(files_info)
            )
        except Exception as e:
            logger.error(f"Error scanning workspace: {e}")
            return ""

    def _extract_targets_from_text(self, text: str) -> list[str]:
        if not text:
            return []
        seen: set[str] = set()
        targets: list[str] = []

        for m in re.finditer(
                r"\b((?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?)\b", text):
            candidate = m.group(1)
            octets = candidate.split(":")[0].split(".")
            if all(o.isdigit() and int(o) <= 255 for o in octets):
                if candidate not in seen:
                    seen.add(candidate)
                    targets.append(candidate)

        for m in re.finditer(
                r"\b(localhost(?::\d{1,5})?)\b", text, re.IGNORECASE):
            candidate = m.group(1).lower()
            if candidate not in seen:
                seen.add(candidate)
                targets.append(candidate)

        for m in re.finditer(
                r"\b[a-z0-9.-]+\.[a-z]{2,}\b", text, re.IGNORECASE):
            candidate = m.group(0).lower()
            ext = candidate.rsplit(".", 1)[-1]
            if ext in self._FILE_EXTENSIONS:
                continue
            if self._is_placeholder_target(candidate):
                continue
            if candidate not in seen:
                seen.add(candidate)
                targets.append(candidate)
        return targets

    def _is_placeholder_target(self, value: str) -> bool:
        if not value:
            return False
        val = value.lower()
        return val in {"example.com",
                       "test.com"} or val.endswith(".example.com")

    def _replace_placeholder_targets(self, data: Any) -> Any:
        if not self.state.active_target:
            return data
        target = self.state.active_target
        if isinstance(data, str):
            return data.replace("example.com", target).replace(
                "test.com", target)
        if isinstance(data, list):
            return [self._replace_placeholder_targets(v) for v in data]
        if isinstance(data, dict):
            return {k: self._replace_placeholder_targets(
                v) for k, v in data.items()}
        return data

    def _normalize_tool_args(
        self,
        tool_name: str,
        arguments: Any,
        user_message: str | None = None,
    ) -> dict[str, Any]:
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except Exception:
                arguments = {}
        if not isinstance(arguments, dict):
            return {}
        args = dict(arguments)
        if self.state.active_target:
            args = self._replace_placeholder_targets(args)
        return args

    def _save_tool_output(
        self, tool_name: str, args: dict[str, Any], result: dict[str, Any]
    ) -> str | None:
        try:

            target = self.state.active_target or "unknown"
            base_dir = str(get_workspace_root() / target)

            command_dir = os.path.join(base_dir, "command")
            output_dir = os.path.join(base_dir, "output")
            os.makedirs(command_dir, exist_ok=True)
            os.makedirs(output_dir, exist_ok=True)
            os.makedirs(os.path.join(base_dir, "tools"), exist_ok=True)
            os.makedirs(
                os.path.join(
                    base_dir,
                    "vulnerabilities"),
                exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            succeeded = result.get("success", False)

            json_filepath = os.path.join(
                command_dir, f"{tool_name}_{timestamp}.json")
            with open(json_filepath, "w") as f:
                json.dump(
                    {"tool": tool_name, "args": args, "result": result,
                     "timestamp": timestamp, "success": succeeded},
                    f, indent=2,
                )

            if not succeeded:
                self._last_output_file = json_filepath
                return json_filepath

            _SKIP_OUTPUT_TXT = {
                "execute",
                "create_file",
                "read_file",
                "list_files",
                "web_search",
                "browser_action",
                "create_vulnerability_report",
                "advanced_fuzz",
                "quick_fuzz",
                "deep_fuzz",
                "run_parallel_agents",
                "caido_list_requests",
                "caido_send_request",
                "caido_automate",
                "caido_get_findings",
                "caido_set_scope",
                "spawn_agent",
            }
            if tool_name in _SKIP_OUTPUT_TXT:
                self._last_output_file = json_filepath
                return json_filepath

            txt_content = ""
            if isinstance(result, dict) and "result" in result:
                res_data = result["result"]
                if isinstance(res_data, dict) and "stdout" in res_data:
                    txt_content = res_data["stdout"]
                else:
                    txt_content = str(res_data)

            if txt_content:
                txt_filename = f"{tool_name}_{timestamp}.txt"
                txt_filepath = os.path.join(output_dir, txt_filename)
                with open(txt_filepath, "w") as f:
                    f.write(str(txt_content))
                self._last_output_file = txt_filepath
                return txt_filepath
            else:
                self._last_output_file = json_filepath
                return json_filepath

        except Exception as e:
            logger.error(f"Error saving tool output: {e}")
        return None

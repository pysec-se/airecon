from __future__ import annotations

import json
import logging
import re
import shlex
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

from .models import ToolExecution

logger = logging.getLogger("airecon.agent")


class _ObserveExecutorMixin:
    async def _exec_record_hypothesis(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()

        claim = str(arguments.get("claim", "")).strip()
        status = str(arguments.get("status", "pending")).lower()
        hyp_id = str(arguments.get("hypothesis_id", "")).strip()
        evidence = str(arguments.get("evidence", "")).strip()
        test_plan = str(arguments.get("test_plan", "")).strip()
        phase = str(arguments.get("phase", "RECON")).upper()

        valid_statuses = {"pending", "testing", "confirmed", "refuted"}
        if status not in valid_statuses:
            return (
                False,
                time.time() - start_time,
                {
                    "success": False,
                    "error": f"Invalid status '{status}'. Must be one of: {sorted(valid_statuses)}",
                },
                None,
            )

        if not claim:
            return (
                False,
                time.time() - start_time,
                {
                    "success": False,
                    "error": "record_hypothesis requires a non-empty 'claim'.",
                },
                None,
            )

        if hyp_id:
            updated = self.state.update_hypothesis(hyp_id, status, evidence or None)
            duration = time.time() - start_time
            if updated:
                return (
                    True,
                    duration,
                    {
                        "success": True,
                        "action": "updated",
                        "hypothesis_id": hyp_id,
                        "status": status,
                        "message": f"Hypothesis {hyp_id} updated to '{status}'.",
                    },
                    None,
                )

            logger.debug("Hypothesis ID '%s' not found — creating new entry.", hyp_id)

        new_id = self.state.add_hypothesis(claim, test_plan, phase=phase)
        if new_id and status != "pending":
            self.state.update_hypothesis(new_id, status, evidence or None)

        duration = time.time() - start_time
        if not new_id:
            return (
                True,
                duration,
                {
                    "success": True,
                    "action": "deduplicated",
                    "message": "A semantically identical hypothesis already exists.",
                },
                None,
            )

        return (
            True,
            duration,
            {
                "success": True,
                "action": "created",
                "hypothesis_id": new_id,
                "status": status,
                "message": (
                    f"Hypothesis '{claim[:80]}' recorded as '{status}'. "
                    f"ID: {new_id}. Use this ID to update status after testing."
                ),
            },
            None,
        )

    async def _execute_http_observe_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        url = self._str_arg(arguments, "url")
        if not url:
            return (
                False,
                0.0,
                {
                    "success": False,
                    "error": "http_observe requires a 'url' argument.",
                },
                None,
            )

        method = (self._str_arg(arguments, "method") or "GET").upper()
        headers: dict[str, str] = {}
        raw_headers = arguments.get("headers")
        if isinstance(raw_headers, dict):
            headers = {str(k): str(v) for k, v in raw_headers.items()}
        body = self._str_arg(arguments, "body")
        save_as = self._str_arg(arguments, "save_as")
        compare_to = self._str_arg(arguments, "compare_to")

        _follow_raw = arguments.get("follow_redirects", False)
        follow_redirects = (
            _follow_raw
            if isinstance(_follow_raw, bool)
            else str(_follow_raw).lower() == "true"
        )

        _timeout_raw = arguments.get("timeout")
        if _timeout_raw is None:
            from ..config import get_config

            _timeout_raw = get_config().observe_request_timeout
        try:
            req_timeout = max(5, min(120, int(_timeout_raw)))
        except (TypeError, ValueError):
            from ..config import get_config

            req_timeout = get_config().observe_request_timeout

        cmd_parts = [
            "curl",
            "-s",
            "-i",
            "--max-time",
            str(req_timeout),
            "-X",
            method,
        ]
        if not follow_redirects:
            cmd_parts.append("--no-location")
        for h_name, h_val in headers.items():
            cmd_parts.extend(["-H", f"{h_name}: {h_val}"])
        if body:
            cmd_parts.extend(["--data-raw", body])
        cmd_parts.append(url)

        curl_cmd = " ".join(shlex.quote(p) for p in cmd_parts)

        try:
            exec_result = await self.engine.execute_tool(
                "execute",
                {"command": curl_cmd, "timeout": req_timeout + 5},
            )
            raw_output = (
                exec_result.get("stdout")
                or exec_result.get("result")
                or exec_result.get("output")
                or ""
            )
            exec_error = exec_result.get("error") or exec_result.get("stderr") or ""
            exec_success = bool(exec_result.get("success", True))
            exit_code = exec_result.get("exit_code")

            # If command failed but no error message, generate one from exit code / raw output
            if not exec_success and not exec_error:
                if exit_code is not None and exit_code != 0:
                    exec_error = f"curl exited with code {exit_code}"
                elif raw_output:
                    exec_error = raw_output.strip()[:200]
                else:
                    # Handle case where exit_code is None, 0, or empty
                    exit_code_str = (
                        str(exit_code) if exit_code is not None else "unknown"
                    )
                    exec_error = f"curl command returned exit code {exit_code_str} with no output"
        except Exception as _e:
            duration = time.time() - start_time
            return False, duration, {"success": False, "error": str(_e)}, None

        parsed = self._parse_http_response(raw_output)
        status_code = parsed["status_code"]
        headers_out = parsed["headers"]
        body_out = parsed["body"]
        body_size = len(body_out.encode("utf-8", errors="replace"))

        result: dict[str, Any] = {
            "success": exec_success,
            "url": url,
            "method": method,
            "status_code": status_code,
            "status_line": parsed["status_line"],
            "headers": headers_out,
            "body": body_out[:4000],
            "body_truncated": body_size > 4000,
            "body_size_bytes": body_size,
            "response_time_ms": int((time.time() - start_time) * 1000),
        }
        if exec_error and not exec_success:
            result["error"] = exec_error[:500]

        if save_as and save_as.strip():
            baseline_entry: dict[str, Any] = {
                "status_code": status_code,
                "status_line": parsed["status_line"],
                "headers": headers_out,
                "body": body_out[:4000],
                "body_size_bytes": body_size,
            }
            self.state.http_baselines[save_as.strip()] = baseline_entry
            result["saved_as"] = save_as.strip()

        if compare_to and compare_to.strip():
            baseline = self.state.http_baselines.get(compare_to.strip())
            if baseline is None:
                result["diff_error"] = (
                    f"No baseline named '{compare_to}' found. Use save_as first."
                )
            else:
                diff = self._diff_http_responses(baseline, result)
                result["diff"] = diff
                result["compared_to"] = compare_to.strip()

        if exec_success and self._session:
            _url_params = list(parse_qs(urlparse(url).query).keys())
            _body_params: list[str] = []
            if body:
                try:
                    _body_json = json.loads(body)
                    if isinstance(_body_json, dict):
                        _body_params = list(_body_json.keys())
                except (ValueError, TypeError):
                    _body_params = list(parse_qs(body).keys())
            param_names = _url_params + _body_params
            self._session.app_model.update_from_response(
                url=url,
                method=method,
                status_code=status_code,
                headers=headers_out,
                body_excerpt=body_out[:2000],
                param_names=param_names,
            )

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                duration=duration,
                status="success" if exec_success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return exec_success, duration, result, None

    @staticmethod
    def _parse_http_response(raw: str) -> dict[str, Any]:
        if not raw:
            return {"status_code": 0, "status_line": "", "headers": {}, "body": ""}

        blocks = re.split(r"(?m)^HTTP/", raw)

        last_block = ("HTTP/" + blocks[-1]) if len(blocks) > 1 else raw

        lines = (
            last_block.split("\r\n") if "\r\n" in last_block else last_block.split("\n")
        )
        status_line = lines[0].strip() if lines else ""

        status_code = 0
        m = re.match(r"HTTP/[\d.]+\s+(\d{3})", status_line)
        if m:
            status_code = int(m.group(1))

        headers: dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False
        for line in lines[1:]:
            if in_body:
                body_lines.append(line)
            elif line.strip() == "":
                in_body = True
            else:
                colon_idx = line.find(":")
                if colon_idx > 0:
                    h_name = line[:colon_idx].strip()
                    h_val = line[colon_idx + 1 :].strip()

                    if h_name.lower() in headers:
                        headers[h_name.lower()] = headers[h_name.lower()] + "; " + h_val
                    else:
                        headers[h_name.lower()] = h_val

        body = "\n".join(body_lines)
        return {
            "status_code": status_code,
            "status_line": status_line,
            "headers": headers,
            "body": body,
        }

    @staticmethod
    def _diff_http_responses(
        baseline: dict[str, Any],
        current: dict[str, Any],
    ) -> dict[str, Any]:
        diff: dict[str, Any] = {}

        b_code = baseline.get("status_code", 0)
        c_code = current.get("status_code", 0)
        if b_code != c_code:
            diff["status_code_changed"] = {"from": b_code, "to": c_code}

        b_headers = baseline.get("headers", {})
        c_headers = current.get("headers", {})
        all_keys = set(b_headers) | set(c_headers)
        header_changes: dict[str, Any] = {}
        for k in all_keys:
            bv = b_headers.get(k)
            cv = c_headers.get(k)
            if bv != cv:
                header_changes[k] = {"from": bv, "to": cv}
        if header_changes:
            diff["header_changes"] = header_changes

        b_size = baseline.get("body_size_bytes", 0)
        c_size = current.get("body_size_bytes", 0)
        size_delta = c_size - b_size
        if abs(size_delta) > 0:
            diff["body_size_delta_bytes"] = size_delta

        b_body = (baseline.get("body") or "")[:500]
        c_body = (current.get("body") or "")[:500]
        if b_body != c_body:
            diff["body_changed"] = True
            diff["body_baseline_excerpt"] = b_body[:200]
            diff["body_current_excerpt"] = c_body[:200]
        else:
            diff["body_changed"] = False

        security_headers = [
            "location",
            "set-cookie",
            "x-frame-options",
            "content-security-policy",
            "www-authenticate",
            "access-control-allow-origin",
            "x-powered-by",
            "server",
        ]
        notable: dict[str, str] = {}
        for sh in security_headers:
            if sh in c_headers:
                notable[sh] = c_headers[sh]
        if notable:
            diff["security_headers_present"] = notable

        diff["significant_change"] = bool(
            diff.get("status_code_changed")
            or diff.get("body_size_delta_bytes", 0) > 50
            or diff.get("header_changes")
        )
        return diff

    async def _execute_code_analysis_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..semgrep import run_code_analysis

        self._last_output_file = None
        start_time = time.time()

        target_path = self._str_arg(arguments, "target_path") or "."
        rules = arguments.get("rules") or None
        languages = arguments.get("languages") or None

        active_target = self.state.active_target or "unknown"
        from .validators import validate_target_path

        _base = (
            "/workspace"
            if target_path.startswith("/")
            else f"/workspace/{active_target}"
        )
        _ok, _resolved = validate_target_path(target_path, _base)
        if not _ok:
            return (
                False,
                0.0,
                {"success": False, "error": f"Invalid target_path: {_resolved}"},
                None,
            )
        target_path = str(_resolved)

        try:
            result = await run_code_analysis(
                engine=self.engine,
                target_path=target_path,
                rules=rules,
                languages=languages,
            )

            findings_capped = result.get("findings", [])[:50]

            _stdout_lines: list[str] = []
            for _f in findings_capped:
                _sev = str(_f.get("severity", "MEDIUM")).upper()
                _rule = _f.get("rule_id", "unknown")
                _msg = _f.get("message", "")
                _file = _f.get("file", "")
                _line = _f.get("start_line", "?")
                _code = _f.get("code_snippet", "")
                _stdout_lines.append(f"[{_sev}] {_rule}: {_msg}")
                if _file:
                    _stdout_lines.append(f"  File: {_file}:{_line}")
                if _code:
                    _stdout_lines.append(f"  Code: {_code}")
            res_dict = {
                "success": True,
                "summary": result.get("summary", ""),
                "total": result.get("total", 0),
                "findings": findings_capped,
                "errors": result.get("errors", []),
                "stdout": "\n".join(_stdout_lines),
            }

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("code_analysis error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=res_dict,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_schemathesis_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        schema_url = self._str_arg(arguments, "schema_url").strip()
        base_url = self._str_arg(arguments, "base_url").strip()
        auth_header = self._str_arg(arguments, "auth_header").strip()
        checks = arguments.get("checks") or []
        try:
            max_examples = int(arguments.get("max_examples") or 30)
        except (TypeError, ValueError):
            max_examples = 30

        if not schema_url:
            return (
                False,
                0.0,
                {"success": False, "error": "'schema_url' is required."},
                None,
            )

        import shlex

        cmd_parts = [
            "python3 -m schemathesis run",
            shlex.quote(schema_url),
        ]
        if base_url:
            cmd_parts.extend(["--base-url", shlex.quote(base_url)])
        if auth_header:
            cmd_parts.extend(["--header", shlex.quote(f"Authorization: {auth_header}")])
        if checks:
            cmd_parts.extend(["--checks", shlex.quote(",".join(checks))])
        cmd_parts.append(f"--hypothesis-max-examples {int(max_examples)}")
        cmd_parts.append("--request-timeout 15")
        cmd_parts.append("--output-truncate false")
        cmd_parts.append("--code-sample-style python")
        active_target = self.state.active_target or "unknown"
        workspace_dir = shlex.quote(f"/workspace/{active_target}")
        output_file = shlex.quote(
            f"/workspace/{active_target}/output/schemathesis_results.txt"
        )
        joined_cmd = " ".join(cmd_parts)
        full_cmd = f"cd {workspace_dir} && {joined_cmd} 2>&1 | tee {output_file}"

        try:
            exec_result = await self.engine.execute_tool(
                "execute",
                {"command": full_cmd, "timeout": 300},
            )
            stdout = (
                exec_result.get("stdout", "") or exec_result.get("result", "") or ""
            )

            exec_error = exec_result.get("error") or exec_result.get("stderr") or ""
            engine_ok = bool(exec_result.get("success", True))
            success = engine_ok and (bool(stdout.strip()) or not bool(exec_error))

            violations = stdout.count("FAILED") + stdout.count("not_a_server_error")
            passed = stdout.count("PASSED")

            res_dict = {
                "success": success,
                "summary": f"Schemathesis completed: {passed} passed, {violations} potential violations.",
                "violations": violations,
                "output_file": output_file,
                "raw_output": stdout[:3000],
            }
            if not success:
                res_dict["error"] = (
                    exec_error[:500] if exec_error else "No output produced"
                )
            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            logger.error("schemathesis_fuzz error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=res_dict,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, self._last_output_file

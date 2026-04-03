from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
import time
from typing import Any, Callable

from ..caido_client import CaidoClient
from ..config import get_config, get_workspace_root
from ..mcp import mcp_call_tool, mcp_list_tools, mcp_search_tools_payload
from .executors_catalog import (
    _AIRECON_TOOL_NAMES,
    _MAX_COMMAND_LENGTH,
    _RESULT_TRUNCATION_THRESHOLD,
    _TOOL_FLAG_CONFLICTS,
)
from .models import ToolExecution

logger = logging.getLogger("airecon.agent")


class _DispatchExecutorMixin:
    async def _execute_run_parallel_agents_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from .subagent import ParallelAgentRunner
        self._last_output_file = None
        start_time = time.time()

        targets = arguments.get("targets", [])
        prompt = arguments.get("prompt", "")

        try:
            runner = ParallelAgentRunner(
                engine=self.engine)
            results = await runner.run_parallel(targets, prompt)

            res_dict = {
                "success": True,
                "results": {
                    t: len(
                        s.vulnerabilities) for t,
                    s in results.items()}}

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("Subagent runner error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time

        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1

        return success, duration, res_dict, None

    def _normalize_args_for_dedup(
            self, tool_name: str, arguments: dict[str, Any]) -> tuple[str, str]:
        args_copy = dict(arguments)
        if tool_name == "execute" and "command" in args_copy:
            cmd = args_copy["command"]

            cmd = re.sub(r'(\s+-(oA|oN|oX|oG|oJ|o)\s+[^\s]+)', '', cmd)
            cmd = re.sub(r'(\s+--output\s*=?\s*[^\s]+)', '', cmd)
            cmd = re.sub(r'(\s*>\s*[^\s]+(\s+2>&1)?)', '', cmd)

            cmd = re.sub(r'(\s+-[bc]\s+output/cookies\.txt)', '', cmd)
            cmd = re.sub(r'(\s+--cookie(?:-jar)?\s+[^\s]+)', '', cmd)

            cmd = re.sub(r'_[0-9]{8}_[0-9]{6}\.', '.', cmd)
            args_copy["command"] = cmd.strip()

        return tool_name, json.dumps(args_copy, sort_keys=True, default=str)

    async def _execute_tool_and_record(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        on_output: Callable[[str], None] | None = None,
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None

        if not isinstance(arguments, dict):
            logger.warning(
                "Tool '%s' received non-dict arguments (type=%s) — rejecting",
                tool_name, type(arguments).__name__,
            )
            return False, 0.0, {
                "success": False,
                "error": (
                    f"Tool call rejected: arguments must be a JSON object (dict), "
                    f"got {type(arguments).__name__}. "
                    f"Example: {{\"name\": \"{tool_name}\", \"arguments\": {{\"key\": \"value\"}}}}"
                ),
            }, None

        args_key = self._normalize_args_for_dedup(tool_name, arguments)
        count = self._executed_tool_counts.get(args_key, 0)
        limit = get_config().agent_repeat_tool_call_limit

        if self._is_recon_phase_repeat_blocked(tool_name, arguments, count):
            binary = self._extract_command_binary(arguments.get("command", ""))
            return False, 0.0, {
                "success": False,
                "error": (
                    f"Duplicate recon execution blocked for '{binary}'. "
                    "Use previous results and pivot to a new recon vector."
                ),
            }, None

        if count >= limit:
            return False, 0.0, {
                "success": False,
                "error": f"Duplicate tool execution prevented (already ran {count}x).",
            }, None

        if tool_name.startswith("mcp_"):
            start_time = time.time()
            server_name = tool_name[4:]
            action = str(arguments.get("action", "")).strip().lower()
            if action == "list_tools":
                success, result = await mcp_list_tools(server_name)
            elif action == "search_tools":
                query = str(arguments.get("query", "")).strip()
                raw_limit = arguments.get("limit", 10)
                try:
                    limit = int(raw_limit)
                except (TypeError, ValueError):
                    limit = 10

                success, listed = await mcp_list_tools(server_name)
                if not success:
                    result = listed
                else:
                    result = mcp_search_tools_payload(listed if isinstance(listed, dict) else {}, query, limit)
                    success = "error" not in result
            elif action == "call_tool":
                tool = str(arguments.get("tool", "")).strip()
                raw_args = arguments.get("arguments", {})

                # Compatibility fallback: some models nest call payload as
                # {"action":"call_tool","arguments":{"tool":"x","arguments":{...}}}
                if not tool and isinstance(raw_args, dict):
                    tool = str(raw_args.get("tool", "")).strip()
                    nested_args = raw_args.get("arguments", {})
                    if isinstance(nested_args, dict):
                        raw_args = nested_args

                if not tool:
                    success, result = False, {
                        "error": "MCP call_tool requires a 'tool' field"
                    }
                elif not isinstance(raw_args, dict):
                    success, result = False, {
                        "error": "MCP 'arguments' must be a JSON object"
                    }
                else:
                    success, result = await mcp_call_tool(server_name, tool, raw_args)
            else:
                success, result = False, {
                    "error": "Invalid MCP action. Use 'list_tools', 'search_tools', or 'call_tool'."
                }

            duration = time.time() - start_time
            self._append_tool_history(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                duration=duration,
                status="success" if success else "error",
            )
            self._executed_tool_counts[args_key] = count + 1
            return success, duration, result, None

        if tool_name == "advanced_fuzz":
            return await self._execute_advanced_fuzz_tool(tool_name, arguments)

        if tool_name == "quick_fuzz":
            return await self._execute_quick_fuzz_tool(tool_name, arguments)

        if tool_name == "deep_fuzz":
            return await self._execute_deep_fuzz_tool(tool_name, arguments)

        if tool_name == "generate_wordlist":
            return await self._execute_generate_wordlist_tool(tool_name, arguments)

        if tool_name == "run_parallel_agents":
            return await self._execute_run_parallel_agents_tool(tool_name, arguments)

        if tool_name == "caido_list_requests":
            return await self._execute_caido_list_requests_tool(tool_name, arguments)

        if tool_name == "caido_send_request":
            return await self._execute_caido_send_request_tool(tool_name, arguments)

        if tool_name == "caido_automate":
            return await self._execute_caido_automate_tool(tool_name, arguments)

        if tool_name == "caido_get_findings":
            return await self._execute_caido_get_findings_tool(tool_name, arguments)

        if tool_name == "caido_set_scope":
            return await self._execute_caido_set_scope_tool(tool_name, arguments)

        if tool_name == "caido_intercept":
            return await self._execute_caido_intercept_tool(tool_name, arguments)

        if tool_name == "caido_sitemap":
            return await self._execute_caido_sitemap_tool(tool_name, arguments)

        if tool_name == "spawn_agent":
            return await self._execute_spawn_agent_tool(tool_name, arguments)

        if tool_name == "code_analysis":
            return await self._execute_code_analysis_tool(tool_name, arguments)

        if tool_name == "http_observe":
            return await self._execute_http_observe_tool(tool_name, arguments)

        if tool_name == "record_hypothesis":
            return await self._exec_record_hypothesis(tool_name, arguments)

        if tool_name == "schemathesis_fuzz":
            return await self._execute_schemathesis_tool(tool_name, arguments)

        if tool_name == "request_user_input":
            return await self._execute_request_user_input(tool_name, arguments)

        if tool_name == "execute":
            cmd = arguments.get("command", "")
            if not cmd or not cmd.strip():
                return False, 0.0, {
                    "success": False,
                    "error": (
                        "Tool call error: 'command' argument is required and cannot be empty. "
                        "Example: {\"name\": \"execute\", \"arguments\": {\"command\": \"ls -la /workspace\"}}"
                    ),
                }, None
            if len(cmd) > _MAX_COMMAND_LENGTH:
                return False, 0.0, {
                    "success": False,
                    "error": (
                        f"Command rejected: length {len(cmd)} exceeds "
                        f"maximum {_MAX_COMMAND_LENGTH} characters."
                    ),
                }, None

            cmd_stripped = cmd.strip()
            _first_token = cmd_stripped.split()[0] if cmd_stripped.split() else ""
            _cmd_lower = cmd_stripped.lower()

            # Caido API/setup may run via execute ONLY for initial token acquisition.
            # Rule: If caido-setup is called AND no token exists yet, allow it (bootstrap).
            # If token already exists or explicit auth calls are present (127.0.0.1:48080/graphql, etc.),
            # reject to prevent repeated/confusing setup attempts.
            _is_caido_setup = "caido-setup" in _cmd_lower
            _has_graphql_url = (
                "127.0.0.1:48080/graphql" in _cmd_lower
                or "localhost:48080/graphql" in _cmd_lower
            )
            _has_loginasguest = "loginasguest" in _cmd_lower

            if _has_graphql_url or _has_loginasguest:
                # Block explicit GraphQL/auth calls via execute (sandbox cannot reach host)
                return False, 0.0, {
                    "success": False,
                    "error": (
                        "Command rejected: GraphQL/auth API must not run via execute. "
                        "Use native Caido tools directly: caido_intercept (action=status), "
                        "caido_list_requests, caido_set_scope, caido_send_request, caido_automate, caido_get_findings. "
                        "Reason: execute runs inside Docker sandbox and cannot reach host Caido (127.0.0.1 inside != host)."
                    ),
                }, None

            if _is_caido_setup:
                existing_token = CaidoClient._token
                if existing_token:
                    return False, 0.0, {
                        "success": False,
                        "error": (
                            "Command rejected: caido-setup bootstrap not needed because Caido token already exists. "
                            "Use native Caido tools directly: caido_intercept (action=status), "
                            "caido_list_requests, caido_set_scope, caido_send_request, caido_automate, caido_get_findings."
                        ),
                    }, None
                logger.info("Allowing caido-setup via execute for initial token bootstrap")

            if _first_token in _AIRECON_TOOL_NAMES and _first_token != "execute":
                return False, 0.0, {
                    "success": False,
                    "error": (
                        f"Command rejected: '{_first_token}' is an AIRecon tool, "
                        "not a shell binary. Do NOT call AIRecon tools via execute — "
                        f"use the '{_first_token}' tool directly with its own arguments. "
                        f"Example: {{\"name\": \"{_first_token}\", \"arguments\": {{...}}}}"
                    ),
                }, None

            _func_call_match = re.search(
                r"\b(" + "|".join(re.escape(t) for t in _AIRECON_TOOL_NAMES) + r")\s*\(",
                cmd_stripped,
            ) if _AIRECON_TOOL_NAMES else None
            if _func_call_match:
                _bad_tool = _func_call_match.group(1)
                return False, 0.0, {
                    "success": False,
                    "error": (
                        f"Command rejected: '{_bad_tool}(...)' is not valid bash syntax. "
                        f"'{_bad_tool}' is an AIRecon tool — call it as a separate tool "
                        f"with its own arguments, not as a shell function inside execute. "
                        f"Example: {{\"name\": \"{_bad_tool}\", \"arguments\": {{...}}}}"
                    ),
                }, None

            if _first_token in _TOOL_FLAG_CONFLICTS:
                _conflict_flags, _correct_tool = _TOOL_FLAG_CONFLICTS[_first_token]

                try:
                    _cmd_tokens = set(shlex.split(cmd_stripped))
                except ValueError:
                    _cmd_tokens = set(cmd_stripped.split())
                _found = [f for f in _conflict_flags if f in _cmd_tokens]
                if _found:
                    return False, 0.0, {
                        "success": False,
                        "error": (
                            f"Command rejected: '{_first_token}' was used with flags that "
                            f"belong to '{_correct_tool}': {_found}. "
                            f"Replace '{_first_token}' with '{_correct_tool}' and retry. "
                            f"Example: {cmd_stripped.replace(_first_token, _correct_tool, 1)}"
                        ),
                    }, None
            if self.state.active_target and cmd and not cmd.strip(
            ).startswith("cd "):
                workspace_dir = f"/workspace/{self.state.active_target}"
                host_workspace = get_workspace_root() / self.state.active_target
                try:
                    host_workspace.mkdir(parents=True, exist_ok=True)
                except Exception as _e:
                    logger.debug("Could not create workspace dir: %s", _e)
                for subdir in ["output", "command",
                               "tools", "vulnerabilities"]:
                    try:
                        (host_workspace / subdir).mkdir(parents=True, exist_ok=True)
                    except Exception as _e:
                        logger.debug("Could not create subdir %s: %s", subdir, _e)

                arguments["command"] = f"cd {workspace_dir} && {cmd}"
                logger.info("Enforced workspace context: %s", arguments["command"])

        start_time = time.time()
        output_file: str | None = None
        try:

            if hasattr(self, "state") and getattr(self.state, "_stop_requested", False):
                logger.info("Tool execution cancelled before start: %s", tool_name)
                return False, 0.0, {
                    "success": False,
                    "error": "Tool execution cancelled: agent is stopping.",
                    "cancelled": True,
                }, None

            result = await self.engine.execute_tool(
                tool_name, arguments, on_output=on_output
            )
            success = result.get("success", False)
            try:

                output_file = self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except asyncio.CancelledError:

            logger.info("Tool execution cancelled by agent: %s", tool_name)
            return False, 0.0, {
                "success": False,
                "error": "Tool execution cancelled: agent is stopping.",
                "cancelled": True,
            }, None
        except KeyboardInterrupt:

            logger.warning("Tool execution interrupted by user: %s", tool_name)
            return False, 0.0, {
                "success": False,
                "error": "Tool execution interrupted by user.",
                "interrupted": True,
            }, None
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Tool exec error: %s", e)

        if tool_name == "execute" and hasattr(self, "state"):
            cmd = arguments.get("command", "").lower()
            stdout = result.get("stdout", "") or ""
            stderr = result.get("stderr", "") or ""
            output = (stdout + stderr).lower()

            # Caido token extraction: if caido-setup ran successfully, try to extract token
            if "caido-setup" in cmd:
                full_output = stdout + stderr
                try:
                    if CaidoClient.extract_and_set_token_from_execute_output(full_output):
                        logger.info("caido-setup token extracted and cached for future use")
                        if "next_action" not in result:
                            result["next_action"] = (
                                "Caido token extracted successfully. "
                                "Caido is now active and ready for use via native tools: "
                                "caido_intercept, caido_list_requests, etc."
                            )
                except Exception as _e:
                    logger.debug("Token extraction from caido-setup output failed: %s", _e)

            _dead_markers = (
                "name_not_resolved", "err_name_not_resolved", "nodename nor servname",
                "no such host", "could not resolve host", "getaddrinfo failed",
                "temporary failure in name resolution",
                "failed to resolve", "unable to resolve",
                "nxdomain",
                "connection refused", "connection reset", "address unreachable",
                "failed to connect", "no address associated",
            )
            if any(m in output for m in _dead_markers):

                _host_match = re.search(
                    r"(?:https?://|ssh://)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)"
                    r"|(?:^|\s)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z]{2,})(?::\d+)?(?=/|\s|$))",
                    cmd,
                )
                _host = (
                    (_host_match.group(1) or _host_match.group(2) or "")
                ).split(":")[0] if _host_match else None

                if _host:
                    added = self.state.add_dead_host(_host)
                    if added:
                        logger.info(
                            "Dead host detected from execute output: %s",
                            _host,
                        )

                        result["dead_host_detected"] = True
                        result["host"] = _host
                        if "next_action" not in result:
                            result["next_action"] = (
                                f"SKIP: {_host} is unreachable (DNS/connection error). "
                                "Remove from target list and proceed to next subdomain."
                            )

        _is_exec_failure = (
            not success
            and hasattr(self, "state")
            and tool_name in ("execute", "browser_action", "web_search", "list_files")
            and "Duplicate tool execution" not in (result.get("error") or "")
            and "Tool call rejected" not in (result.get("error") or "")
            and "Command rejected" not in (result.get("error") or "")
        )
        if _is_exec_failure and hasattr(self.state, "add_failure"):
            error_detail = result.get("error", "") or result.get("stderr", "") or "Unknown error"
            target = arguments.get("target") or arguments.get("url", "")
            failure_id = self.state.add_failure(
                name=tool_name,
                error_detail=error_detail,
                target=target,
                failure_category="tool",
            )
            logger.debug("Failure recorded with ID: %s for tool %s", failure_id, tool_name)

            if "next_action" not in result and hasattr(self.state, "get_failure_summary"):
                failure_summary = self.state.get_failure_summary()
                if failure_summary.get("most_common"):
                    result["next_action"] = (
                        f"Pattern detected: {failure_summary['most_common']} errors are most common. "
                        f"Review recent failures and adapt strategy."
                    )

        if not success:
            err_msg = str(result.get("error") or result.get("stderr") or "")
            if "unexpected EOF while looking for matching `''" in err_msg:
                hint = (
                    "\n\n[SYSTEM HINT]: Bash syntax error! You cannot escape a single quote inside a single-quoted string "
                    "(e.g., 'don\\'t' is invalid). To use a single quote inside a single-quoted string, close the quote, "
                    "insert an escaped quote, and reopen it: 'don'\\''t'. Alternatively, wrap your entire command/regex in double "
                    "quotes if it contains single quotes."
                )
                if "error" in result and result["error"]:
                    result["error"] = str(result["error"]) + hint
                if "stderr" in result and result["stderr"]:
                    result["stderr"] = str(result["stderr"]) + hint

            elif "int() argument" in err_msg or "invalid literal for int" in err_msg:
                result["error"] = (
                    err_msg
                    + "\n[SYSTEM HINT]: A numeric argument was given a non-numeric value. "
                    "Check that integer fields (e.g. port, limit, count) are actual numbers, not strings."
                )

            elif "required" in err_msg.lower() and "argument" in err_msg.lower():
                result["error"] = (
                    err_msg
                    + f"\n[SYSTEM HINT]: The tool '{tool_name}' is missing a required argument. "
                    "Re-read the tool definition and include all required fields."
                )

            elif "NoneType" in err_msg or "'NoneType' object has no attribute" in err_msg:
                result["error"] = (
                    err_msg
                    + f"\n[SYSTEM HINT]: A None value was passed where a string/dict was expected for tool '{tool_name}'. "
                    "Check that all arguments are non-null and the correct type."
                )

        duration = time.time() - start_time

        history_result = result
        if success and output_file and len(str(result)) > _RESULT_TRUNCATION_THRESHOLD:
            history_result = {
                "success": True,
                "result": f"<Result truncated. Full output in {output_file}>",
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

        if success:
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(
                args_key, 0) + 1
        return success, duration, result, output_file

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse


from ..browser import browser_action
from ..config import get_config, get_workspace_root
from .executors_catalog import (
    _RESULT_TRUNCATION_THRESHOLD,
)

logger = logging.getLogger("airecon.agent")


class _BrowserExecutorMixin:
    async def _execute_local_browser_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None

        args_key = self._normalize_args_for_dedup(tool_name, arguments)

        allow_repeat = True

        if not allow_repeat:
            count = self._executed_tool_counts.get(
                args_key, 0)
            limit = get_config().agent_repeat_tool_call_limit
            if count >= limit:
                return False, 0.0, {
                    "success": False,
                    "error": f"Duplicate tool execution prevented (already ran {count}x)."
                }, None

        _browser_timeout = float(get_config().browser_action_timeout)
        start_time = time.time()
        try:
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(browser_action, **arguments),
                    timeout=_browser_timeout,
                )
            except asyncio.TimeoutError:

                asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: browser_action(action="close"),
                )
                return False, _browser_timeout, {
                    "success": False,
                    "error": f"Browser action timed out after {_browser_timeout:.0f}s. Browser close requested.",
                }, None

            if arguments.get("action") == "launch" and hasattr(self, "_session"):
                cookies = getattr(self._session, "auth_cookies", [])
                if cookies:
                    try:
                        await asyncio.to_thread(
                            browser_action,
                            action="inject_cookies",
                            cookies=cookies
                        )
                        if "url" in arguments:

                            await asyncio.to_thread(
                                browser_action,
                                action="goto",
                                url=arguments["url"]
                            )
                    except Exception as e:
                        logger.warning("Failed to auto-inject session cookies: %s", e)

            success = not (isinstance(result, dict) and "error" in result)
            if not success and isinstance(result, dict) and "error" in result:
                result = {"success": False, "error": result["error"]}
            elif "success" not in result:
                result = {"success": success, "result": result}

            if isinstance(result, dict) and result.get("domain_dead"):
                host = result.get("host", "")
                if host and hasattr(self, "state"):
                    added = self.state.add_dead_host(host)
                    if added:
                        logger.info("Dead host auto-registered from browser_action: %s", host)

                if "next_action" not in result:
                    result["next_action"] = (
                        f"SKIP: {host} is unreachable. Remove from target list and proceed to next subdomain."
                    )

            if success and self.state.active_target:
                action = arguments.get("action")
                if action in ("view_source", "get_console_logs",
                              "get_network_logs"):
                    try:
                        inner = result.get("result", {})
                        if not isinstance(inner, dict):
                            inner = {}
                        page_url = inner.get("url", "")
                        netloc = urlparse(page_url).netloc.replace(
                            ":", "_") if page_url else "unknown"
                        domain = netloc or "unknown"
                        host_output = (
                            get_workspace_root()
                            / self.state.active_target
                            / "output"
                        )
                        host_output.mkdir(parents=True, exist_ok=True)

                        if action == "view_source":

                            source_full = inner.get(
                                "full_page_source") or inner.get("page_source", "")
                            source_file = host_output / f"source_{domain}.txt"
                            with open(source_file, "w", encoding="utf-8") as f:
                                f.write(f"URL: {page_url}\n{'=' * 60}\n{source_full}")
                            saved_path = f"output/source_{domain}.txt"

                            js_src = re.findall(
                                r'src=["\']([^"\']*\.js[^"\']*)["\']', source_full)
                            js_abs = re.findall(
                                r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?', source_full)
                            all_js = list(dict.fromkeys(js_src + js_abs))
                            js_note = ""
                            if all_js:
                                js_file = host_output / "js_files.txt"
                                with open(js_file, "a", encoding="utf-8") as f:
                                    f.write(
                                        f"\n{'=' * 60}\nSOURCE: {page_url}\n{'=' * 60}\n"
                                    )
                                    for js_url in all_js:
                                        f.write(js_url + "\n")
                                js_note = f" {len(all_js)} JS files extracted to output/js_files.txt."
                            inner = dict(inner)

                            inner.pop("full_page_source", None)
                            inner["auto_saved"] = saved_path
                            inner["note"] = (
                                f"[Auto-saved full page source ({len(source_full)} chars) to {saved_path}.{js_note}"
                                " Analyze JS files for API endpoints, secrets, and vulnerabilities.]"
                            )
                            result = {"success": True, "result": inner}
                            self._last_output_file = saved_path

                        elif action == "get_console_logs":
                            logs = inner.get("console_logs", [])
                            console_file = host_output / \
                                f"console_{domain}.txt"
                            with open(console_file, "w", encoding="utf-8") as f:
                                f.write(
                                    f"URL: {page_url}\nLogs captured: {len(logs)}\n{'=' * 60}\n"
                                )
                                for log in logs:
                                    f.write(
                                        f"[{log.get('type', 'log')}] {log.get('text', '')}\n")
                            saved_path = f"output/console_{domain}.txt"
                            inner = dict(inner)
                            inner["auto_saved"] = saved_path
                            inner["note"] = (
                                f"[Auto-saved {len(logs)} console logs to {saved_path}."
                                " Check for errors, debug info, and leaked sensitive data.]"
                            )
                            result = {"success": True, "result": inner}
                            self._last_output_file = saved_path

                        elif action == "get_network_logs":
                            reqs = inner.get("network_requests", [])
                            net_file = host_output / f"network_{domain}.txt"
                            with open(net_file, "w", encoding="utf-8") as f:
                                f.write(
                                    f"URL: {page_url}\nTotal entries: {len(reqs)}\n{'=' * 60}\n\n"
                                )
                                for entry in reqs:
                                    etype = entry.get("type", "?")
                                    url = entry.get("url", "")
                                    if etype == "request":
                                        method = entry.get("method", "GET")
                                        resource_type = entry.get("resource_type", "")
                                        f.write(
                                            f">> {method} [{resource_type}] {url}\n"
                                        )
                                        if entry.get("post_data"):
                                            f.write(f"   BODY: {entry['post_data']}\n")
                                    elif etype == "response":
                                        status = entry.get("status", "")
                                        content_type = entry.get("content_type", "")
                                        f.write(
                                            f"<< {status} {url}  [{content_type}]\n"
                                        )
                                        if entry.get("body"):
                                            f.write(f"   RESPONSE: {entry['body']}\n")
                                    f.write("\n")
                            saved_path = f"output/network_{domain}.txt"
                            summary = inner.get("network_summary", {})
                            api_calls = summary.get("api_calls", [])
                            inner = dict(inner)

                            inner.pop("network_requests", None)
                            inner["auto_saved"] = saved_path
                            inner["note"] = (
                                f"[Auto-saved {len(reqs)} network entries to {saved_path}."
                                f" {len(api_calls)} XHR/Fetch API calls detected."
                                " Review for API endpoints, auth tokens, and sensitive data in responses.]"
                            )
                            result = {"success": True, "result": inner}
                            self._last_output_file = saved_path

                    except Exception as _e:
                        logger.warning("Failed to auto-save browser result: %s", _e)

            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Browser tool exec error: %s", e)

        duration = time.time() - start_time

        history_result = result
        if success and self._last_output_file and len(
                str(result)) > _RESULT_TRUNCATION_THRESHOLD:
            history_result = {
                "success": True,
                "result": f"<Result truncated. Full output in {self._last_output_file}>",
                "truncated": True,
            }

        self._append_tool_history(
            tool_name=tool_name,
            arguments=arguments,
            result=history_result,
            duration=duration,
            status="success" if success else "error",
        )

        if success:
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(
                args_key, 0) + 1
        return success, duration, result, self._last_output_file

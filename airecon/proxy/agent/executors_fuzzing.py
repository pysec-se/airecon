from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..config import get_workspace_root
from ..fuzzer import FUZZ_PAYLOADS as _FUZZ_PAYLOAD_KEYS
from .models import ToolExecution

logger = logging.getLogger("airecon.agent")


class _FuzzingExecutorMixin:
    async def _execute_advanced_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import Fuzzer

        self._last_output_file = None
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("parameters", [])
        method = arguments.get("method", "GET")
        _valid_vuln_types = set(_FUZZ_PAYLOAD_KEYS.keys())
        _raw_vuln_types = arguments.get("vuln_types")
        if _raw_vuln_types and isinstance(_raw_vuln_types, list):
            vuln_types = [
                v
                for v in _raw_vuln_types
                if isinstance(v, str) and v in _valid_vuln_types
            ] or list(_valid_vuln_types)
        else:
            vuln_types = list(_valid_vuln_types)

        def _as_bool(value: Any, default: bool = True) -> bool:
            if value is None:
                return default
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return bool(value)
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "y", "on"}
            return default

        def _as_str_list(value: Any) -> list[str] | None:
            if not isinstance(value, list):
                return None
            cleaned = [str(v).strip() for v in value if str(v).strip()]
            return cleaned or None

        enable_phase2 = _as_bool(arguments.get("phase2"), default=True)
        ssrf_params = _as_str_list(arguments.get("ssrf_params"))
        graphql_endpoints = _as_str_list(arguments.get("graphql_endpoints"))
        race_params = _as_str_list(arguments.get("race_params"))
        auth_login_url_raw = arguments.get("auth_login_url")
        auth_login_url = (
            auth_login_url_raw.strip()
            if isinstance(auth_login_url_raw, str) and auth_login_url_raw.strip()
            else None
        )
        auth_username = arguments.get("auth_username")
        auth_password = arguments.get("auth_password")
        auth_extra_fields_raw = arguments.get("auth_extra_fields")
        auth_extra_fields: dict[str, str] | None = None
        if isinstance(auth_extra_fields_raw, dict):
            auth_extra_fields = {
                str(k): str(v)
                for k, v in auth_extra_fields_raw.items()
                if str(k).strip()
            }

        try:
            async with Fuzzer(
                target=target,
                method=method,
                headers=self._build_fuzz_headers(),
                auth_login_url=auth_login_url,
            ) as fuzzer:
                if isinstance(auth_username, str) and isinstance(auth_password, str):
                    fuzzer.set_auth_credentials(
                        auth_username,
                        auth_password,
                        auth_extra_fields,
                        login_url=auth_login_url,
                    )
                await fuzzer.fuzz_parameters(params, vuln_types)
                phase2_findings: list[Any] = []
                if enable_phase2:
                    phase2_findings = await fuzzer.run_phase2_advanced_tests(
                        ssrf_params=ssrf_params,
                        graphql_endpoints=graphql_endpoints,
                        race_params=race_params,
                    )
                results = list(fuzzer.results)

            if not results:
                res_dict = {
                    "success": True,
                    "result": "No vulnerabilities found with confidence > 0.60.",
                    "phase2_enabled": enable_phase2,
                    "phase2_findings": len(phase2_findings) if enable_phase2 else 0,
                }
            else:
                findings_list = []
                for r in results:
                    findings_list.append(
                        f"Param: {r.parameter} | Vuln: {r.vuln_type} | "
                        f"Severity: {r.severity} | Conf: {r.confidence:.2f} | "
                        f"Evidence: {r.evidence}"
                    )
                res_dict = {
                    "success": True,
                    "findings": findings_list,
                    "phase2_enabled": enable_phase2,
                    "phase2_findings": len(phase2_findings) if enable_phase2 else 0,
                }

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("Fuzzer error: %s", e)
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

    def _is_target_in_scope(self, target_url: str) -> bool:
        session_target: str = ""
        try:
            if self._session and self._session.target:
                session_target = self._session.target.strip()
        except Exception as e:
            logger.debug(
                "Expected failure reading session target for scope check: %s", e
            )

        if not session_target or not target_url:
            return True

        try:
            target_host = urlparse(target_url).hostname or ""

            if "://" in session_target:
                scope_host = urlparse(session_target).hostname or ""
            else:
                scope_host = session_target.split(":")[0].split("/")[0].lower()

            if not scope_host or not target_host:
                return True

            target_host = target_host.lower()
            scope_host = scope_host.lower()

            return target_host == scope_host or target_host.endswith("." + scope_host)
        except Exception:
            return True

    async def _execute_quick_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import quick_fuzz_url

        self._last_output_file = None
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("params") or None

        if not self._is_target_in_scope(target):
            session_target = getattr(
                getattr(self, "_session", None), "target", "unknown"
            )
            logger.warning(
                "quick_fuzz scope violation — target %r is outside session scope %r. Skipping.",
                target,
                session_target,
            )
            oos_result = {
                "success": False,
                "error": (
                    f"OUT-OF-SCOPE: {target!r} does not belong to the target scope "
                    f"({session_target!r}). Do NOT fuzz third-party domains "
                    f"(CDNs, analytics, font services, etc.). "
                    f"Only fuzz subdomains of {session_target!r}."
                ),
            }
            duration = time.time() - start_time
            self.state.tool_history.append(
                ToolExecution(
                    tool_name=tool_name,
                    arguments=arguments,
                    result=oos_result,
                    duration=duration,
                    status="error",
                )
            )
            self.state.tool_counts["total"] += 1
            return False, duration, oos_result, None

        try:
            results = await quick_fuzz_url(
                url=target,
                params=params,
                headers=self._build_fuzz_headers(),
            )

            if not results:
                res_dict = {
                    "success": True,
                    "result": "No vulnerabilities found with confidence > 0.60.",
                }
            else:
                findings_list = [
                    f"Param: {r.parameter} | Vuln: {r.vuln_type} | "
                    f"Severity: {r.severity} | Conf: {r.confidence:.2f} | "
                    f"Evidence: {r.evidence}"
                    for r in results
                ]

                stdout_lines = []
                for r in results:
                    sev = r.severity.upper()
                    stdout_lines.append(
                        f"[{sev}] {r.vuln_type.upper()} on param '{r.parameter}'"
                        f" at {r.target}"
                    )
                    stdout_lines.append(
                        f"Payload: {r.payload} | Conf: {r.confidence:.2f}"
                    )
                    stdout_lines.append(f"Evidence: {r.evidence}")
                res_dict = {
                    "success": True,
                    "stdout": "\n".join(stdout_lines),
                    "findings": findings_list,
                    "total": len(findings_list),
                }

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("quick_fuzz error: %s", e)
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

    async def _execute_deep_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("params") or None
        vuln_types = arguments.get("vuln_types") or None

        if not self._is_target_in_scope(target):
            session_target = getattr(
                getattr(self, "_session", None), "target", "unknown"
            )
            logger.warning(
                "deep_fuzz scope violation — target %r is outside session scope %r. Skipping.",
                target,
                session_target,
            )
            oos_result = {
                "success": False,
                "error": (
                    f"OUT-OF-SCOPE: {target!r} does not belong to the target scope "
                    f"({session_target!r}). Do NOT fuzz third-party domains. "
                    f"Only fuzz subdomains of {session_target!r}."
                ),
            }
            duration = time.time() - start_time
            self.state.tool_history.append(
                ToolExecution(
                    tool_name=tool_name,
                    arguments=arguments,
                    result=oos_result,
                    duration=duration,
                    status="error",
                )
            )
            self.state.tool_counts["total"] += 1
            return False, duration, oos_result, None

        def _as_bool(value: Any, default: bool = True) -> bool:
            if value is None:
                return default
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return bool(value)
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "y", "on"}
            return default

        def _as_str_list(value: Any) -> list[str] | None:
            if not isinstance(value, list):
                return None
            cleaned = [str(v).strip() for v in value if str(v).strip()]
            return cleaned or None

        enable_phase2 = _as_bool(arguments.get("phase2"), default=True)
        enable_phase3 = _as_bool(arguments.get("phase3"), default=True)
        ssrf_params = _as_str_list(arguments.get("ssrf_params"))
        graphql_endpoints = _as_str_list(arguments.get("graphql_endpoints"))
        race_params = _as_str_list(arguments.get("race_params"))
        store_params = _as_str_list(arguments.get("store_params"))
        trigger_paths = _as_str_list(arguments.get("trigger_paths"))
        auth_login_url_raw = arguments.get("auth_login_url")
        auth_login_url = (
            auth_login_url_raw.strip()
            if isinstance(auth_login_url_raw, str) and auth_login_url_raw.strip()
            else None
        )
        auth_username = arguments.get("auth_username")
        auth_password = arguments.get("auth_password")
        auth_extra_fields_raw = arguments.get("auth_extra_fields")
        auth_extra_fields: dict[str, str] | None = None
        if isinstance(auth_extra_fields_raw, dict):
            auth_extra_fields = {
                str(k): str(v)
                for k, v in auth_extra_fields_raw.items()
                if str(k).strip()
            }
        tester = None

        try:
            from ..fuzzer import InteractiveRealTimeTester

            tester = InteractiveRealTimeTester(
                target,
                threads=10,
                timeout=20,
                headers=self._build_fuzz_headers(),
                auth_login_url=auth_login_url,
            )
            if isinstance(auth_username, str) and isinstance(auth_password, str):
                tester.fuzzer.set_auth_credentials(
                    auth_username,
                    auth_password,
                    auth_extra_fields,
                    login_url=auth_login_url,
                )
            async for event in tester.stream_fuzz(params=params, vuln_types=vuln_types):
                pass
            phase2_findings: list[Any] = []
            phase3_findings: list[Any] = []
            if enable_phase2:
                phase2_findings = await tester.fuzzer.run_phase2_advanced_tests(
                    ssrf_params=ssrf_params,
                    graphql_endpoints=graphql_endpoints,
                    race_params=race_params,
                )
            if enable_phase3:
                phase3_findings = await tester.fuzzer.run_phase3_advanced_tests(
                    store_params=store_params or params,
                    trigger_paths=trigger_paths,
                )
            if phase2_findings or phase3_findings:
                tester._findings.extend(phase2_findings + phase3_findings)
            summary = tester.get_summary()
            summary["phase2_enabled"] = enable_phase2
            summary["phase3_enabled"] = enable_phase3
            summary["phase2_findings"] = len(phase2_findings)
            summary["phase3_findings"] = len(phase3_findings)

            findings_list = []
            for f in getattr(tester, "_findings", []):
                findings_list.append(
                    f"Param: {f.parameter} | Vuln: {f.vuln_type} | "
                    f"Severity: {f.severity} | Conf: {f.confidence:.2f} | "
                    f"Evidence: {f.evidence}"
                )

            res_dict = {
                "success": True,
                "summary": summary,
                "findings": findings_list,
            }

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("deep_fuzz error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False
        finally:
            if tester is not None:
                try:
                    await tester.fuzzer.close()
                except Exception as _close_err:
                    logger.debug("Could not close deep_fuzz tester: %s", _close_err)

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

    async def _execute_generate_wordlist_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import generate_fuzz_wordlist

        self._last_output_file = None
        start_time = time.time()

        raw_output_file = arguments.get("output_file", "wordlist.txt")
        output_file = Path(raw_output_file).name or "wordlist.txt"
        max_combinations = min(int(arguments.get("max_combinations", 300)), 1000)
        vuln_types = arguments.get("vuln_types") or None

        try:
            wordlist = generate_fuzz_wordlist(
                max_combinations=max_combinations,
                vuln_types=vuln_types,
            )

            target = self.state.active_target or "unknown"
            host_output = get_workspace_root() / target / "output"
            host_output.mkdir(parents=True, exist_ok=True)
            out_path = host_output / output_file
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("\n".join(wordlist))

            saved_path = f"output/{output_file}"
            res_dict = {
                "success": True,
                "result": f"Generated {len(wordlist)} entries saved to {saved_path}.",
                "saved_to": saved_path,
                "total_entries": len(wordlist),
            }
            self._last_output_file = saved_path

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("generate_wordlist error: %s", e)
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

    def _build_fuzz_headers(self) -> dict[str, str] | None:
        headers: dict[str, str] = {}
        session = getattr(self, "_session", None)
        if session is None:
            return None
        auth_cookies: list[dict[str, Any]] = getattr(session, "auth_cookies", []) or []
        if auth_cookies:
            cookie_str = "; ".join(
                f"{c.get('name', '')}={c.get('value', '')}"
                for c in auth_cookies
                if c.get("name")
            )
            if cookie_str:
                headers["Cookie"] = cookie_str
        auth_hdrs: dict[str, str] = getattr(session, "auth_headers", {}) or {}
        headers.update(auth_hdrs)
        return headers or None

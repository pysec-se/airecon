from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

from .models import ToolExecution

from ..reporting import create_vulnerability_report

logger = logging.getLogger("airecon.agent")


class _ReportingExecutorMixin:
    async def _execute_report_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        try:
            result = await asyncio.to_thread(
                create_vulnerability_report,
                **arguments,
                _active_target=self.state.active_target,
            )
            success = result.get("success", False)
            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)

            if success and self._session:
                report_title = str(arguments.get("title", "") or "").strip()
                flag = arguments.get("flag", "")

                def _token_set(text: str) -> set[str]:
                    return {
                        tok for tok in re.findall(r"[a-z0-9]{4,}", text.lower())
                        if tok not in {"vulnerability", "report", "issue", "finding"}
                    }

                def _scope_hints(data: dict[str, Any]) -> set[str]:
                    hints: set[str] = set()
                    for key in ("url", "endpoint", "affected_endpoint", "target", "parameter"):
                        raw = str(data.get(key, "") or "").strip().lower()
                        if not raw:
                            continue
                        hints.add(raw)
                        try:
                            parsed = urlparse(raw)
                            if parsed.netloc:
                                hints.add(parsed.netloc.lower())
                            if parsed.path:
                                hints.add(parsed.path.lower())
                        except Exception:
                            pass
                    return hints

                report_scope = _scope_hints(arguments)
                report_tokens = _token_set(report_title)
                matched = False
                for vuln in self._session.vulnerabilities:
                    v_title = str(vuln.get("title") or vuln.get("finding") or "").strip()
                    if not report_title or not v_title:
                        continue

                    v_lower = v_title.lower()
                    r_lower = report_title.lower()
                    strict_title_hit = (
                        v_lower in r_lower
                        or r_lower in v_lower
                    )
                    v_tokens = _token_set(v_title)
                    overlap_ratio = (
                        (len(report_tokens & v_tokens) / max(1, len(report_tokens)))
                        if report_tokens
                        else 0.0
                    )

                    vuln_scope = _scope_hints(vuln)
                    scope_hit = False
                    if report_scope and vuln_scope:
                        scope_hit = any(
                            rs in vs or vs in rs
                            for rs in report_scope
                            for vs in vuln_scope
                        )

                    title_confident = strict_title_hit or overlap_ratio >= 0.75
                    if title_confident and (scope_hit or strict_title_hit or overlap_ratio >= 0.90):
                        vuln["report_generated"] = True
                        if flag:
                            vuln["flag"] = flag
                        matched = True

                if success and report_title and not matched:
                    logger.info(
                        "Report created but not bound to existing vulnerability: title=%r",
                        report_title[:120],
                    )
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Reporting tool exec error: %s", e)

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1
        return success, duration, result, self._last_output_file

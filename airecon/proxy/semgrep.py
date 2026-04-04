from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("airecon.semgrep")

DEFAULT_RULE_SETS: list[str] = [
    "p/security-audit",
    "p/owasp-top-ten",
    "p/cwe-top-25",
]


def get_default_rules() -> list[str]:
    return list(DEFAULT_RULE_SETS)


def build_semgrep_command(
    target_path: str,
    rules: list[str] | None = None,
    languages: list[str] | None = None,
    max_findings: int = 100,
) -> str:
    max_findings = max(1, min(int(max_findings), 1000))
    rule_sets = rules or get_default_rules()
    rule_args = " ".join(f"--config {r}" for r in rule_sets)

    lang_arg = ""
    if languages:
        lang_arg = f"--lang {','.join(languages)}"

    return (
        f"semgrep {rule_args} {lang_arg} "
        f"--json --no-git-ignore --max-target-bytes 1000000 "
        f"--timeout 120 --max-memory 2048 "
        f"--metrics off --max-findings {int(max_findings)} "
        f"{target_path} 2>/dev/null"
    )


def parse_semgrep_results(raw_json: str) -> dict[str, Any]:
    if not raw_json.strip():
        return {"findings": [], "errors": [], "summary": "No results"}

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return {
            "findings": [],
            "errors": [f"Failed to parse Semgrep output: {e}"],
            "summary": "Parse error",
        }

    results: list[dict[str, Any]] = []
    for result in data.get("results", []):
        check_id = result.get("check_id", "unknown")
        message = result.get("extra", {}).get("message", "")
        severity = result.get("extra", {}).get("severity", "WARNING").upper()
        metadata = result.get("extra", {}).get("metadata", {})

        finding = {
            "rule_id": check_id,
            "message": message,
            "severity": severity,
            "file": result.get("path", ""),
            "start_line": result.get("start", {}).get("line", 0),
            "end_line": result.get("end", {}).get("line", 0),
            "code_snippet": result.get("extra", {}).get("lines", ""),
            "cwe": metadata.get("cwe", []),
            "owasp": metadata.get("owasp", []),
            "confidence": metadata.get("confidence", "MEDIUM"),
            "references": metadata.get("references", []),
        }
        results.append(finding)

    errors = [
        {"type": e.get("type", ""), "message": e.get("message", "")}
        for e in data.get("errors", [])
    ]

    by_severity: dict[str, int] = {}
    for f in results:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    severity_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items()))
    summary = (
        f"Found {len(results)} issues ({severity_str})"
        if results
        else "No issues found"
    )

    return {
        "findings": results,
        "errors": errors,
        "summary": summary,
        "total": len(results),
    }


async def run_code_analysis(
    engine: Any,
    target_path: str,
    rules: list[str] | None = None,
    languages: list[str] | None = None,
) -> dict[str, Any]:
    install_check = await engine.execute_tool(
        "execute",
        {"command": "which semgrep || pip install semgrep 2>&1 | tail -1"},
    )
    if not install_check.get("success", False):
        logger.warning("Semgrep installation may have failed, attempting scan anyway")

    scan_cmd = build_semgrep_command(target_path, rules=rules, languages=languages)
    result = await engine.execute_tool("execute", {"command": scan_cmd})

    if not result.get("success", False):
        error_msg = result.get("error", result.get("stderr", "Unknown error"))
        return {
            "findings": [],
            "errors": [f"Semgrep execution failed: {error_msg}"],
            "summary": "Scan failed",
            "total": 0,
        }

    stdout = result.get("result", result.get("stdout", ""))
    if isinstance(stdout, dict):
        stdout = json.dumps(stdout)

    if not stdout or not stdout.strip():
        return {
            "findings": [],
            "errors": [],
            "summary": "No output from Semgrep (target may have no scannable files)",
            "total": 0,
        }

    return parse_semgrep_results(stdout)

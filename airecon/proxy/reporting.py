from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import get_workspace_root

_CVE_RE = re.compile(r'^CVE-(19[89]|20\d{2})-\d{4,7}$', re.IGNORECASE)

logger = logging.getLogger("airecon.proxy.reporting")

try:
    from cvss import CVSS3
except ImportError:
    CVSS3 = None

def calculate_cvss_and_severity(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> tuple[float, str, str]:
    if CVSS3 is None:
        return 0.0, "unknown", "CVSS library not installed"

    try:
        vector = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/"
            f"PR:{privileges_required}/UI:{user_interaction}/S:{scope}/"
            f"C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        c = CVSS3(vector)
        scores = c.scores()
        severities = c.severities()

        base_score = scores[0]
        base_severity = severities[0]

        severity = base_severity.lower()
        return base_score, severity, vector

    except Exception:
        logger.exception("Failed to calculate CVSS")
        return 0.0, "unknown", ""

def _validate_required_fields(**kwargs: str | None) -> list[str]:
    validation_errors: list[str] = []

    required_fields = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "target": "Target cannot be empty",
        "poc_description": "PoC description cannot be empty",
        "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
    }

    for field_name, error_msg in required_fields.items():
        value = kwargs.get(field_name)
        if not value or not str(value).strip():
            validation_errors.append(error_msg)

    return validation_errors

def _validate_cvss_parameters(**kwargs: str) -> list[str]:
    validation_errors: list[str] = []

    cvss_validations = {
        "attack_vector": ["N", "A", "L", "P"],
        "attack_complexity": ["L", "H"],
        "privileges_required": ["N", "L", "H"],
        "user_interaction": ["N", "R"],
        "scope": ["U", "C"],
        "confidentiality": ["N", "L", "H"],
        "integrity": ["N", "L", "H"],
        "availability": ["N", "L", "H"],
    }

    for param_name, valid_values in cvss_validations.items():
        value = kwargs.get(param_name)
        if value not in valid_values:
            validation_errors.append(
                f"Invalid {param_name}: {value}. Must be one of: {valid_values}"
            )

    return validation_errors

def _sanitize_target_name(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._-")
    return cleaned

def _extract_target_token(raw_target: str) -> str:
    raw = (raw_target or "").strip()
    if not raw:
        return ""

    if raw.startswith("@"):
        raw = raw[1:]
    if raw.startswith("[file:") and raw.endswith("]"):
        raw = raw[6:-1]

    parsed = urlparse(raw if "://" in raw else "")
    if parsed.netloc:
        return parsed.netloc

    if "/" in raw and not raw.startswith(("/", ".", "@")):
        host_candidate = raw.split("/", 1)[0]
        host_only = host_candidate.split(":", 1)[0]
        if "." in host_only and re.fullmatch(r"[a-zA-Z0-9.-]+", host_only):
            return host_only

    if raw.startswith("/workspace/"):
        parts = [p for p in raw.split("/") if p]
        if len(parts) >= 2:
            return parts[1]

    if "/" in raw or raw.startswith("."):
        path_like = Path(raw)

        if path_like.suffix:
            return path_like.stem or path_like.name
        return path_like.name or path_like.stem

    return raw

def _is_filesystem_like_target(raw_target: str) -> bool:
    raw = (raw_target or "").strip()
    if not raw:
        return False
    if "://" in raw:
        return False
    if "/" in raw and not raw.startswith(("/", ".", "@")):
        host_candidate = raw.split("/", 1)[0]
        host_only = host_candidate.split(":", 1)[0]
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host_only):
            return False
        if "." in host_only and re.fullmatch(r"[a-zA-Z0-9.-]+", host_only):
            return False
        return True
    return (
        raw.startswith("@/")
        or raw.startswith("/workspace/")
        or raw.startswith("/")
        or raw.startswith("[file:")
        or raw.startswith("./")
        or raw.startswith("../")
    )

def _resolve_report_workspace_target(target: str, active_target: str | None) -> str:
    target_token = _extract_target_token(target)
    target_clean = _sanitize_target_name(target_token)

    active_clean = ""
    if active_target:
        active_token = _extract_target_token(str(active_target))
        active_clean = _sanitize_target_name(active_token)

    if active_clean:

        if _is_filesystem_like_target(target) or not target_clean:
            return active_clean

        if target_clean != active_clean and (
            target_clean.endswith("." + active_clean)
            or active_clean.endswith("." + target_clean)
        ):
            return active_clean

    return target_clean or active_clean or "unknown_target"

def create_vulnerability_report(
    title: str,
    description: str,
    target: str,
    poc_description: str,
    poc_script_code: str,

    impact: str = "",
    technical_analysis: str = "",
    remediation_steps: str = "",

    attack_vector: str | None = None,
    attack_complexity: str | None = None,
    privileges_required: str | None = None,
    user_interaction: str | None = None,
    scope: str | None = None,
    confidentiality: str | None = None,
    integrity: str | None = None,
    availability: str | None = None,

    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    suggested_fix: str | None = None,
    flag: str | None = None,

    _workspace_root: str | None = None,
    _active_target: str | None = None,
) -> dict[str, Any]:

    validation_errors = _validate_required_fields(
        title=title,
        description=description,
        target=target,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
    )

    raw_cvss_params = {
        "attack_vector": attack_vector,
        "attack_complexity": attack_complexity,
        "privileges_required": privileges_required,
        "user_interaction": user_interaction,
        "scope": scope,
        "confidentiality": confidentiality,
        "integrity": integrity,
        "availability": availability,
    }
    _provided_cvss = sum(1 for v in raw_cvss_params.values() if v is not None and str(v).strip())
    has_cvss = _provided_cvss == len(raw_cvss_params)

    if 0 < _provided_cvss < len(raw_cvss_params):
        return {
            "success": False,
            "message": "Validation failed",
            "errors": [
                "Partial CVSS metrics provided. Supply all 8 CVSS base metrics or none.",
            ],
        }

    cvss_params = {
        k: (str(v).strip().upper() if v is not None else None)
        for k, v in raw_cvss_params.items()
    }

    if has_cvss:
        validation_errors.extend(
            _validate_cvss_parameters(
                **cvss_params))  # type: ignore[arg-type]

    if validation_errors:
        return {"success": False, "message": "Validation failed",
                "errors": validation_errors}

    if cve and cve.strip():
        if not _CVE_RE.match(cve.strip()):
            return {
                "success": False,
                "message": f"Invalid CVE format: '{cve}'. Must match CVE-YYYY-NNNN+ (e.g., CVE-2024-1234). Use web_search to verify CVE IDs.",
            }

    if has_cvss:
        cvss_score, severity, cvss_vector = calculate_cvss_and_severity(
            **cvss_params)  # type: ignore[arg-type]
    else:
        cvss_score, severity, cvss_vector = 0.0, "n/a", ""

    target_clean = _resolve_report_workspace_target(
        target=target,
        active_target=_active_target,
    )

    if not _workspace_root:
        _workspace_root = str(get_workspace_root())

    vuln_dir = os.path.join(_workspace_root, target_clean, "vulnerabilities")
    try:
        os.makedirs(vuln_dir, exist_ok=True)
    except Exception as e:
        return {"success": False, "message": f"Failed to create directory: {e}"}

    slug = re.sub(r'[^a-zA-Z0-9]+', '_', title).strip('_').lower()
    if not slug:
        slug = "report"
    slug = slug[:50]
    filename = f"{slug}.md"
    filepath = os.path.join(vuln_dir, filename)
    report_id = slug

    md_content = f"# {title}\n\n"
    md_content += f"**ID**: {report_id}\n"

    if has_cvss:
        md_content += f"**Severity**: {severity.upper()} (CVSS: {cvss_score})\n"
        md_content += f"**Vector**: `{cvss_vector}`\n"

    md_content += f"**Target**: {target}\n"
    md_content += f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

    if endpoint:
        md_content += f"**Endpoint**: {endpoint}\n"
    if method:
        md_content += f"**Method**: {method}\n"
    if flag:
        md_content += f"**Flag**: `{flag}`\n"

    md_content += f"\n## Overview\n{description}\n"

    if has_cvss:
        md_content += "\n## Severity and CVSS\n"
        md_content += f"- **Base Score**: {cvss_score} ({severity.upper()})\n"
        md_content += f"- **Vector**: `{cvss_vector}`\n"

    if technical_analysis and technical_analysis.strip():
        md_content += f"\n## Technical Details\n{technical_analysis}\n"

    md_content += f"\n## Proof of Concept\n{poc_description}\n"
    md_content += f"\n```\n{poc_script_code}\n```\n"

    if impact and impact.strip():
        md_content += f"\n## Impact\n{impact}\n"

    if remediation_steps and remediation_steps.strip():
        md_content += f"\n## Remediation\n{remediation_steps}\n"

    if suggested_fix and suggested_fix.strip():
        md_content += f"\n## Suggested Fix\n```\n{suggested_fix.strip()}\n```\n"

    if cve:
        md_content += f"\n## Reference\n**CVE**: {cve}\n"

    try:
        with open(filepath, "x", encoding="utf-8") as f:
            f.write(md_content)

        result: dict[str, Any] = {
            "success": True,
            "message": f"Vulnerability report saved to {filepath}",
            "report_id": report_id,
            "report_path": filepath,
        }
        if has_cvss:
            result["severity"] = severity
            result["cvss_score"] = cvss_score
        if flag:
            result["flag"] = flag
        return result
    except FileExistsError:
        return {
            "success": False,
            "message": f"Report '{filename}' already exists. Title collision detected.",
            "duplicate_of": report_id,
            "duplicate_title": title,
            "confidence": 1.0,
            "reason": "Exact title match with existing report.",
        }
    except Exception as e:
        return {"success": False, "message": f"Failed to write report file: {e}"}

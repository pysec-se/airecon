"""Session persistence — save/load findings per session across runs.

Sessions are identified by a unique ID (unix_timestamp_randomhex), not by target name.
Each `airecon start` creates a new session. Use `airecon start --session <id>` to resume.

Storage: ~/.airecon/sessions/<session_id>.json
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .output_parser import ParsedOutput

logger = logging.getLogger("airecon.agent.session")

SESSIONS_DIR = Path.home() / ".airecon" / "sessions"

# ---------------------------------------------------------------------------
# Injection point extraction
# ---------------------------------------------------------------------------

# UUID v4 pattern for path segment detection
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Analytics/tracking parameters that are never injection points.
# Including them as IDOR/INJECT creates false positives that waste agent time.
_TRACKING_PARAMS: frozenset[str] = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_reader", "utm_name",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "twclid",
    "mc_cid", "mc_eid",
    "_ga", "_gl", "_hsenc", "_hsmi",
    "ref", "referrer", "source", "medium", "campaign",
})

# Numeric values that look like IDs but are actually common false positives.
# Exact-match set for O(1) lookup before the regex heuristic fires.
_NUMERIC_FP_VALUES: frozenset[str] = frozenset({
    # Common HTTP ports
    "80", "443", "8080", "8443", "8000", "8888", "3000", "4000", "5000",
    "9000", "9090", "3306", "5432", "6379", "27017",
    # HTTP status codes (100-599)
    *[str(s) for s in range(100, 600)],
    # Calendar years (reasonable range)
    *[str(y) for y in range(1990, 2035)],
})

# Canonical param→attack-type mapping, loaded from fuzzer_data.json.
# Fallback is empty dict — _guess_injection_type still works via heuristics.
def _load_param_type_map() -> dict[str, str]:
    """Build flat {param_lower: TYPE} dict from fuzzer_data.json PARAM_TYPE_MAP."""
    try:
        data_file = Path(__file__).parent.parent / "data" / "fuzzer_data.json"
        data = json.loads(data_file.read_text(encoding="utf-8"))
        result: dict[str, str] = {}
        for attack_type, params in data.get("PARAM_TYPE_MAP", {}).items():
            for param in params:
                result[param.lower()] = attack_type
        return result
    except Exception as e:
        logger.debug("Could not load PARAM_TYPE_MAP from fuzzer_data.json: %s", e)
        return {}


_PARAM_TYPE_MAP: dict[str, str] = _load_param_type_map()


def _guess_injection_type(param: str, value: str) -> str:
    """Infer the most likely injection type from parameter name and sample value.

    Lookup order:
    1. Canonical map from fuzzer_data.json PARAM_TYPE_MAP
    2. camelCase normalisation (userId → user_id)
    3. Regex suffix patterns (_id suffix → IDOR)
    4. Numeric/UUID value heuristic
    """
    p = param.lower().rstrip("[]")
    if p in _PARAM_TYPE_MAP:
        return _PARAM_TYPE_MAP[p]
    # Normalise camelCase: userId → user_id
    p_norm = re.sub(r"([a-z])([A-Z])", r"\1_\2", param).lower().rstrip("[]")
    if p_norm in _PARAM_TYPE_MAP:
        return _PARAM_TYPE_MAP[p_norm]
    # Suffix/prefix heuristics
    if re.search(r"_id$|^id_|id$", p):
        return "IDOR"
    # Numeric value heuristic — only flag as IDOR when value looks like a real
    # resource ID (4-10 digits) AND is NOT a known false positive (port numbers,
    # HTTP status codes, calendar years).
    if value and re.match(r"^\d{4,10}$", value) and value not in _NUMERIC_FP_VALUES:
        return "IDOR"
    return "INJECT"


def _extract_injection_points(url: str) -> list[dict[str, Any]]:
    """Extract testable injection point candidates from a URL.

    Detects:
    - Query string parameters (?id=1&user=admin)
    - Numeric / UUID path segments (/users/123, /items/uuid)

    Returns a list of dicts with keys: url, parameter, method, value_sample,
    type_hint.
    """
    points: list[dict[str, Any]] = []
    try:
        p = urlparse(url)
        # Only process http/https URLs — skip javascript:, data:, ftp:, etc.
        if p.scheme not in ("http", "https"):
            return points
        # Normalize base so dedup keys are consistent regardless of case or
        # trailing slash variations (e.g. /api/users/ == /api/users).
        base = urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            p.path.rstrip("/") or "/",
            "", "", "",
        ))

        # Query string parameters — skip pure analytics/tracking params that
        # are never injection points and only inflate the injection_points list.
        for param, value in parse_qsl(p.query, keep_blank_values=True):
            if param.lower() in _TRACKING_PARAMS:
                continue
            points.append({
                "url": base,
                "parameter": param,
                "method": "GET",
                "value_sample": value[:30] if value else "",
                "type_hint": _guess_injection_type(param, value),
            })

        # Path segments that look like IDs (numeric or UUID).
        # Use the full URL so the LLM knows the complete endpoint context
        # (e.g. /api/users/123/orders — the ID belongs to 'users', and
        # /orders shows what sub-resource is being accessed).
        path_parts = [x for x in p.path.strip("/").split("/") if x]
        for i, seg in enumerate(path_parts):
            if re.match(r"^\d{1,10}$", seg) or _UUID_RE.match(seg):
                # Label: parent-resource/ID so the LLM knows which resource owns this ID
                parent = path_parts[i - 1] if i > 0 else ""
                param_label = f"path/{parent}/{seg}" if parent else f"path/{seg}"
                points.append({
                    "url": base,  # full URL preserves sub-resource context
                    "parameter": param_label,
                    "method": "GET",
                    "value_sample": seg,
                    "type_hint": "IDOR",
                })
    except Exception as _e:
        logger.debug("_extract_injection_points path traversal error: %s", _e)
    return points


def injection_point_key(url: str, parameter: str, method: str = "GET") -> str:
    """Build a stable string key for an injection point triple."""
    return f"{url}||{parameter}||{method.upper()}"


def mark_injection_point_tested(session: "SessionData", url: str, parameter: str, method: str = "GET") -> None:
    """Mark an injection point as tested so the agent won't re-test it."""
    key = injection_point_key(url, parameter, method)
    if key not in session.tested_injection_points:
        session.tested_injection_points.append(key)


def get_untested_injection_points(session: "SessionData") -> list[dict[str, Any]]:
    """Return injection points that have NOT been tested yet this session."""
    tested_set = set(session.tested_injection_points)
    return [
        pt for pt in session.injection_points
        if injection_point_key(
            pt.get("url", ""), pt.get("parameter", ""), pt.get("method", "GET")
        ) not in tested_set
    ]


def _merge_injection_points(
    session_points: list[dict[str, Any]],
    new_points: list[dict[str, Any]],
) -> None:
    """Append new injection points to session list, skipping exact duplicates.

    Dedup key: (url, parameter, method) — mutates session_points in-place.
    """
    existing = {
        (p["url"], p["parameter"], p["method"])
        for p in session_points
    }
    for pt in new_points:
        key = (pt["url"], pt["parameter"], pt["method"])
        if key not in existing:
            session_points.append(pt)
            existing.add(key)


def generate_session_id() -> str:
    """Generate a unique session ID: <unix_timestamp>_<8_random_hex>.

    Example: 1740842400_a3b4c5d6
    """
    return f"{int(time.time())}_{uuid.uuid4().hex[:8]}"


def _normalize_url(url: str) -> str:
    """Normalize a URL for deduplication.

    - Lowercase scheme and host
    - Sort query parameters alphabetically
    - Strip URL fragment (#...)
    - Strip trailing slash from path (except root "/")

    Returns the original string unchanged if parsing fails.
    """
    try:
        p = urlparse(url)
        query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
        return urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            p.path.rstrip("/"),
            p.params,
            query,
            "",  # strip fragment
        ))
    except Exception:
        return url


def _calculate_similarity(v1: str, v2: str) -> float:
    """Calculate similarity between two vulnerability strings using simple approach."""
    v1_lower = v1.lower()
    v2_lower = v2.lower()

    # Two empty strings are technically identical but represent nothing — do not
    # treat as duplicates, as this would silently drop any second report with
    # an empty finding field.
    if not v1_lower or not v2_lower:
        return 0.0

    if v1_lower == v2_lower:
        return 1.0

    # Extract parameter context to avoid false dedup of diff params
    param_re = re.compile(
        r"(?:[?&]([a-z0-9_\[\]\-]+)=|parameter\s+['\"]?([a-z0-9_\[\]\-]+)['\"]?)")
    m1 = param_re.search(v1_lower)
    m2 = param_re.search(v2_lower)

    if m1 and m2:
        p1 = m1.group(1) or m1.group(2)
        p2 = m2.group(1) or m2.group(2)
        if p1 and p2 and p1 != p2:
            return 0.0  # Different targeted parameters = NOT duplicate

    # Check for common words
    words1 = set(v1_lower.split())
    words2 = set(v2_lower.split())

    if not words1 or not words2:
        return 0.0

    intersection = words1 & words2
    union = words1 | words2

    return len(intersection) / len(union)


def _is_duplicate_vulnerability(
        new_vuln: dict, existing_vulns: list[dict]) -> bool:
    """Check if a vulnerability is a duplicate of an existing one.

    Uses vuln_similarity_threshold from config (default: 0.7).
    """
    try:
        from ..config import get_config
        threshold = get_config().vuln_similarity_threshold
    except Exception:
        from ..config import DEFAULT_CONFIG
        threshold = DEFAULT_CONFIG["vuln_similarity_threshold"]

    new_finding = new_vuln.get("finding", "")
    new_target = new_vuln.get("target", "")

    for existing in existing_vulns:
        existing_finding = existing.get("finding", "")
        existing_target = existing.get("target", "")

        # Check finding similarity — _calculate_similarity already returns 0.0
        # when the two findings mention different URL parameters, preventing
        # false deduplication of findings on different parameters.
        finding_sim = _calculate_similarity(new_finding, existing_finding)

        # Check target similarity (if both have targets)
        target_sim = 1.0 if new_target == existing_target else 0.0

        # Combined similarity
        combined_sim = (finding_sim * 0.8) + (target_sim * 0.2)

        if combined_sim >= threshold:
            return True

    return False


@dataclass
class SessionData:
    """Persistent per-session state, identified by a unique session_id."""

    # Session identity
    session_id: str = ""
    target: str = ""

    # Findings
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    technologies: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    completed_phases: list[str] = field(default_factory=list)
    current_phase: str = "RECON"
    tools_run: list[str] = field(default_factory=list)
    scan_count: int = 0
    created_at: str = ""
    updated_at: str = ""

    # Injection points discovered during ANALYSIS phase.
    # Each entry: {url, parameter, method, value_sample, type_hint}
    # Populated automatically from URLs by update_from_parsed_output().
    # The EXPLOIT phase uses this list to target specific parameters.
    injection_points: list[dict[str, Any]] = field(default_factory=list)

    # Browser auth state (persisted so re-runs skip re-login)
    auth_cookies: list[dict[str, Any]] = field(default_factory=list)
    auth_tokens: dict[str, str] = field(default_factory=dict)
    auth_type: str = ""  # "form", "totp", "oauth", "cookie"

    # Tracks which injection points have already been tested this session.
    # Key format: "<url>||<parameter>||<method>" — exact dedup to prevent
    # re-testing the same (url, param, method) triple across iterations.
    # Populated by loop.py after execute/quick_fuzz/advanced_fuzz tool calls.
    tested_injection_points: list[str] = field(default_factory=list)
    # Transient flag: True after prior-session findings have been merged this run.
    # Stored in JSON so it survives a session reload and prevents duplicate merges.
    _prior_merged: bool = field(default=False)

    # Dedup set for correlation engine suggestions: stores fingerprints of
    # chains/patterns already injected into context this session so the
    # correlation engine doesn't repeat the same hints every 10 iterations.
    # Format: "<type>:<key>" e.g. "port:80", "technology:wordpress",
    # "expert_test:idor_hotspot", "attack_chain:XSS → CSRF"
    suggested_correlations: list[str] = field(default_factory=list)

    # Endpoints that have been actively tested this session.
    # Format: "METHOD url" e.g. "GET https://example.com/api/users"
    # Capped at 500 entries (LRU — oldest dropped first).
    # Persisted to disk so the LLM never re-tests the same endpoint after
    # a crash or extreme context truncation.
    tested_endpoints: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.session_id:
            self.session_id = generate_session_id()
        if not self.created_at:
            self.created_at = datetime.now().isoformat()


_MAX_TESTED_ENDPOINTS = 500


def record_tested_endpoint(session: SessionData, url: str, method: str = "GET") -> None:
    """Record a URL as tested so it survives context truncation and crashes.

    Normalises to "METHOD URL" format and deduplicates.  When the list
    exceeds the cap, the oldest entries are dropped (LRU).
    """
    if not url or not url.strip():
        return
    key = f"{method.upper()} {url.strip()}"
    if key not in session.tested_endpoints:
        session.tested_endpoints.append(key)
        if len(session.tested_endpoints) > _MAX_TESTED_ENDPOINTS:
            # Drop oldest entries to stay within cap
            session.tested_endpoints = session.tested_endpoints[-_MAX_TESTED_ENDPOINTS:]


def load_session(session_id: str) -> SessionData | None:
    """Load a session by its unique ID.

    Returns None if the session file does not exist.
    """
    filepath = SESSIONS_DIR / f"{session_id}.json"
    if not filepath.exists():
        return None

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        session = SessionData(
            session_id=data.get("session_id", session_id),
            target=data.get("target", ""),
            subdomains=data.get("subdomains", []),
            live_hosts=data.get("live_hosts", []),
            open_ports=data.get("open_ports", {}),
            urls=data.get("urls", []),
            technologies=data.get("technologies", {}),
            vulnerabilities=data.get("vulnerabilities", []),
            attack_chains=data.get("attack_chains", []),
            completed_phases=data.get("completed_phases", []),
            current_phase=data.get("current_phase", "RECON"),
            tools_run=data.get("tools_run", []),
            scan_count=data.get("scan_count", 0),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            injection_points=data.get("injection_points", []),
            auth_cookies=data.get("auth_cookies", []),
            auth_tokens=data.get("auth_tokens", {}),
            auth_type=data.get("auth_type", ""),
            tested_injection_points=data.get("tested_injection_points", []),
            suggested_correlations=data.get("suggested_correlations", []),
            tested_endpoints=data.get("tested_endpoints", []),
            _prior_merged=data.get("_prior_merged", False),
        )
        logger.info(
            f"Loaded session {session_id} (target={session.target}): "
            f"{len(session.subdomains)} subs, {len(session.live_hosts)} live, "
            f"{len(session.vulnerabilities)} vulns"
        )
        return session
    except Exception as e:
        logger.warning(f"Failed to load session {session_id}: {e}")
        return None


def save_session(session: SessionData) -> None:
    """Save session data to disk using session_id as filename."""
    try:
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        filepath = SESSIONS_DIR / f"{session.session_id}.json"
        with open(filepath, "w") as f:
            json.dump(asdict(session), f, indent=2, default=str)
        logger.info(
            f"Saved session {session.session_id} (target={session.target})"
        )
    except Exception as e:
        logger.error(f"Failed to save session {session.session_id}: {e}")


def list_sessions() -> list[dict]:
    """Return a list of all saved sessions, sorted by most recently updated first.

    Each entry contains summary information (not the full data).
    """
    sessions: list[dict] = []
    if not SESSIONS_DIR.exists():
        return sessions

    for path in SESSIONS_DIR.glob("*.json"):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            sessions.append({
                "session_id": data.get("session_id", path.stem),
                "target": data.get("target", ""),
                "created_at": data.get("created_at", ""),
                "scan_count": data.get("scan_count", 0),
                "subdomains": len(data.get("subdomains", [])),
                "live_hosts": len(data.get("live_hosts", [])),
                "vulnerabilities": len(data.get("vulnerabilities", [])),
            })
        except Exception as _e:
            logger.debug("Could not load session metadata: %s", _e)

    sessions.sort(key=lambda s: s["created_at"], reverse=True)
    return sessions


def find_prior_session(target: str) -> SessionData | None:
    """Find the most recent completed session for the given target.

    Returns None if no prior session exists or the target has never been scanned.
    Only considers sessions that made meaningful progress (scan_count >= 3 or
    at least one completed phase) to avoid pre-populating from aborted runs.
    """
    if not SESSIONS_DIR.exists():
        return None

    target_norm = target.strip().lower()
    candidates: list[tuple[str, str]] = []  # (updated_at, session_id)

    for path in SESSIONS_DIR.glob("*.json"):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if data.get("target", "").strip().lower() != target_norm:
                continue
            # Only consider sessions with meaningful progress
            has_progress = (
                data.get("scan_count", 0) >= 3
                or bool(data.get("completed_phases"))
            )
            if not has_progress:
                continue
            ts = data.get("updated_at") or data.get("created_at", "")
            candidates.append((ts, data.get("session_id", path.stem)))
        except Exception as _e:
            logger.debug("Could not inspect session file %s: %s", path, _e)

    if not candidates:
        return None

    # Most recently updated session
    candidates.sort(reverse=True)
    _, best_id = candidates[0]
    return load_session(best_id)


def merge_prior_findings(new_session: SessionData, prior: SessionData) -> None:
    """Merge findings from a prior session into a new session for the same target.

    Only merges factual reconnaissance data (subdomains, ports, URLs, technologies,
    injection points, attack_chains). Does NOT merge vulnerabilities (may be patched),
    phase state (always restart from RECON), or auth state (tokens may be expired).

    This gives the new session a head-start without polluting it with stale vuln data.
    """
    if prior.target.strip().lower() != new_session.target.strip().lower():
        logger.warning(
            "merge_prior_findings: target mismatch (%r vs %r) — skipping",
            prior.target, new_session.target,
        )
        return

    merged_count = 0

    # Subdomains — deduplicated
    existing_subs = set(new_session.subdomains)
    for sub in prior.subdomains:
        if sub not in existing_subs:
            new_session.subdomains.append(sub)
            existing_subs.add(sub)
            merged_count += 1

    # Live hosts — deduplicated
    existing_hosts = set(new_session.live_hosts)
    for host in prior.live_hosts:
        if host not in existing_hosts:
            new_session.live_hosts.append(host)
            existing_hosts.add(host)

    # Open ports — merge dict (host → sorted unique port list)
    for host, ports in prior.open_ports.items():
        if host not in new_session.open_ports:
            new_session.open_ports[host] = list(ports)
        else:
            merged = sorted(set(new_session.open_ports[host]) | set(ports))
            new_session.open_ports[host] = merged

    # URLs — deduplicated (cap at 500 to avoid flooding context)
    existing_urls = set(new_session.urls)
    for url in prior.urls:
        if url not in existing_urls and len(new_session.urls) < 500:
            new_session.urls.append(url)
            existing_urls.add(url)
            merged_count += 1

    # Technologies — merge dict (newer value wins on conflict)
    for name, version in prior.technologies.items():
        if name not in new_session.technologies:
            new_session.technologies[name] = version

    # Injection points — deduplicate by (url, parameter, method) key
    existing_ips = {
        (ip.get("url", ""), ip.get("parameter", ""), ip.get("method", ""))
        for ip in new_session.injection_points
    }
    for ip in prior.injection_points:
        key = (ip.get("url", ""), ip.get("parameter", ""), ip.get("method", ""))
        if key not in existing_ips:
            new_session.injection_points.append(ip)
            existing_ips.add(key)
            merged_count += 1

    # Attack chains — merge by name
    existing_chains = {c.get("name", "") for c in new_session.attack_chains}
    for chain in prior.attack_chains:
        if chain.get("name", "") not in existing_chains:
            new_session.attack_chains.append(chain)

    logger.info(
        "Merged prior session %s into new session %s "
        "(%d items: %d subs, %d urls, %d injection_points)",
        prior.session_id, new_session.session_id,
        merged_count,
        len(new_session.subdomains), len(new_session.urls),
        len(new_session.injection_points),
    )


def update_from_parsed_output(
    session: SessionData,
    parsed: ParsedOutput,
    command: str = "",
) -> None:
    """Update session data based on WHAT THE DATA LOOKS LIKE, not which tool produced it.

    Classification logic:
    - Items that look like subdomains (e.g. "sub.example.com") → session.subdomains
    - Items that look like URLs (start with http) → session.urls or session.live_hosts
    - Items that look like host:port → session.open_ports
    - Items that look like port/proto lines → session.open_ports
    - Items with severity tags [CRITICAL] [HIGH] etc → session.vulnerabilities
    - Everything else: logged but not stored (no false assumptions)
    """
    session.scan_count += 1

    # Track which tools have been run (use actual binary name)
    tool_key = parsed.tool
    if tool_key and tool_key not in session.tools_run:
        session.tools_run.append(tool_key)

    # Merge technologies from tool output (whatweb, httpx -tech-detect)
    if parsed.technologies:
        for name, version in parsed.technologies.items():
            if name and name not in session.technologies:
                session.technologies[name] = version
            elif name and version and not session.technologies.get(name):
                # Upgrade an empty-version entry when a version is now
                # available
                session.technologies[name] = version

    if not parsed.items:
        return

    # Classify each item by its content pattern
    _SUBDOMAIN_RE = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$"
    )
    _URL_RE = re.compile(r"^https?://")
    _ANY_URL_RE = re.compile(r"https?://\S+")
    _HOST_PORT_RE = re.compile(r"^([a-zA-Z0-9.\-]+):(\d+)")
    # Match nmap port lines in multiple formats:
    #   "80/tcp   open  http"           (plain nmap -sV)
    #   "| 80/tcp  open  http"          (nmap script block with pipe prefix)
    #   "  443/tcp filtered https"      (leading whitespace variants)
    _PORT_PROTO_RE = re.compile(r"(?:^|[|\s])(\d+)/(tcp|udp)\s+(open|filtered)")
    _SEVERITY_RE = re.compile(
        r"^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]",
        re.IGNORECASE)
    # httpx outputs URL followed by [STATUS] bracket — handle multiple common formats:
    #   https://host.com [200]                     (httpx -sc)
    #   https://host.com [200] [title] [tech]      (httpx default)
    #   https://host.com [200 OK]                  (httpx extended)
    #   https://host.com [200,text/html,...]       (httpx -json piped)
    _HTTP_STATUS_RE = re.compile(r"(https?://\S+?)\s+\[(\d{3})[^\]]*\]")
    # DNS-only label prefixes that are not HTTP-probeable hosts (e.g. _dmarc, _domainkey)
    _DNS_ONLY_PREFIX_RE = re.compile(r"^_")
    # Private/loopback IP ranges — not valid external scan targets
    _PRIVATE_IP_RE = re.compile(
        r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1|fd)"
    )

    for item in parsed.items:
        item_stripped = item.strip()
        if not item_stripped:
            continue

        # 1. Severity-tagged finding → vulnerability
        if _SEVERITY_RE.match(item_stripped):
            new_vuln = {
                "finding": item_stripped,
                "source": tool_key,
                "timestamp": datetime.now().isoformat(),
            }
            # Check for duplicates before adding
            if not _is_duplicate_vulnerability(
                    new_vuln, session.vulnerabilities):
                session.vulnerabilities.append(new_vuln)
            continue

        # 2. URL with HTTP status code (httpx-style output) → live_hosts.
        # Matches: https://host [200], https://host [200 OK], https://host [200] [nginx]
        status_match = _HTTP_STATUS_RE.search(item_stripped)
        if status_match:
            url = _normalize_url(status_match.group(1).rstrip(".,;:)]}>\"'"))
            if url and url not in session.live_hosts:
                session.live_hosts.append(url)
            # Also add to urls if not already there
            if url and url not in session.urls:
                session.urls.append(url)
            continue

        # 3. URL (plain or embedded in prefixed line) → urls collection
        # + auto-extract injection points.
        url_token: str | None = None
        if _URL_RE.match(item_stripped):
            url_token = item_stripped.split()[0]
        else:
            embedded = _ANY_URL_RE.search(item_stripped)
            if embedded:
                url_token = embedded.group(0)

        if url_token:
            url = _normalize_url(url_token.rstrip(".,;:)]}>\"'"))
            if url not in session.urls:
                session.urls.append(url)
            # Extract any testable parameters from the URL
            new_pts = _extract_injection_points(url)
            if new_pts:
                _merge_injection_points(session.injection_points, new_pts)
            continue

        # 4. host:port format → open_ports
        hp_match = _HOST_PORT_RE.match(item_stripped)
        if hp_match:
            host, port_str = hp_match.group(1), hp_match.group(2)
            if port_str.isdigit():
                port = int(port_str)
                session.open_ports.setdefault(host, [])
                if port not in session.open_ports[host]:
                    session.open_ports[host].append(port)
            continue

        # 5. port/proto state service (nmap-style) → open_ports under target
        # Use search() (not match()) to handle pipe-prefixed nmap script output.
        pp_match = _PORT_PROTO_RE.search(item_stripped)
        if pp_match:
            port_str = pp_match.group(1)
            if port_str.isdigit():
                port = int(port_str)
                session.open_ports.setdefault(session.target, [])
                if port not in session.open_ports[session.target]:
                    session.open_ports[session.target].append(port)
            continue

        # 6. Looks like a subdomain → subdomains
        # Must have at least one dot, no spaces, no special chars.
        # Exclude DNS-only labels (e.g. _dmarc.target.com) — these cannot be
        # HTTP-probed. Exclude private/loopback IPs to avoid dead scan targets.
        clean = item_stripped.split()[0]  # first token only
        if (
            _SUBDOMAIN_RE.match(clean)
            and len(clean) > 4
            and not _DNS_ONLY_PREFIX_RE.match(clean)
            and not _PRIVATE_IP_RE.match(clean)
        ):
            if clean not in session.subdomains:
                session.subdomains.append(clean)
            continue

        # 7. Anything else: we DON'T store it to avoid false assumptions.
        # It stays in the parsed output for the LLM to see but doesn't
        # pollute structured session data.


def session_to_context(session: SessionData) -> str:
    """Format session data as a context string for injection into conversation."""
    target_label = session.target or "unknown target"
    parts = [
        f"[SYSTEM: PREVIOUS SESSION DATA — Session {session.session_id} for {target_label}]"
    ]
    parts.append(f"Session created: {session.created_at}")
    parts.append(
        f"Tools previously run: {', '.join(session.tools_run) if session.tools_run else 'none'}"
    )
    parts.append(f"Total scans: {session.scan_count}")

    if session.subdomains:
        count = len(session.subdomains)
        preview = ", ".join(session.subdomains[:10])
        parts.append(
            f"Subdomains found: {count} — {preview}"
            + (f" ... +{count - 10} more" if count > 10 else "")
        )

    if session.live_hosts:
        count = len(session.live_hosts)
        preview = ", ".join(session.live_hosts[:10])
        parts.append(
            f"Live hosts: {count} — {preview}"
            + (f" ... +{count - 10} more" if count > 10 else "")
        )

    if session.open_ports:
        total_ports = sum(len(p) for p in session.open_ports.values())
        port_preview = []
        for host, ports in list(session.open_ports.items())[:5]:
            port_preview.append(
                f"{host}: {','.join(str(p) for p in sorted(ports)[:10])}"
            )
        parts.append(
            f"Open ports: {total_ports} total — " +
            "; ".join(port_preview))

    if session.urls:
        parts.append(f"URLs collected: {len(session.urls)}")

    if session.injection_points:
        count = len(session.injection_points)
        untested = get_untested_injection_points(session)
        tested_count = count - len(untested)

        # Show UNTESTED injection points first — these are highest priority.
        # Fall back to all IPs if everything is already tested.
        show_list = untested if untested else session.injection_points

        # Group by type_hint for clarity
        by_type: dict[str, list[dict[str, Any]]] = {}
        for pt in show_list:
            t = pt.get("type_hint", "INJECT")
            by_type.setdefault(t, []).append(pt)

        preview_lines: list[str] = []
        shown = 0
        for type_hint, pts in by_type.items():
            for pt in pts[:3]:
                param = pt.get("parameter", "?")
                url_short = pt.get("url", "")
                path = urlparse(url_short).path or url_short
                preview_lines.append(f"  [{type_hint}] {param} @ {path}")
                shown += 1
            if shown >= 9:
                break

        suffix = f" ... +{len(show_list) - shown} more" if len(show_list) > shown else ""
        untested_note = (
            f"⚠ {len(untested)} UNTESTED — prioritize these!" if untested
            else f"✓ all {tested_count} tested"
        )
        parts.append(
            f"Injection points: {count} total ({untested_note}):\n"
            + "\n".join(preview_lines) + suffix
        )

    if session.technologies:
        count = len(session.technologies)
        # Format as "Name/version" where version is known, else just "Name"
        tech_parts = [
            f"{name}/{ver}" if ver else name
            for name, ver in list(session.technologies.items())[:15]
        ]
        parts.append(
            f"Technologies fingerprinted: {count} — {', '.join(tech_parts)}"
            + (f" ... +{count - 15} more" if count > 15 else "")
        )

    if session.vulnerabilities:
        parts.append(f"Vulnerabilities found: {len(session.vulnerabilities)}")
        for v in session.vulnerabilities[:5]:
            flag_info = f" (FLAG: {v.get('flag')})" if v.get("flag") else ""
            parts.append(f"  - {v.get('finding', '?')}{flag_info}")

    if session.attack_chains:
        parts.append(f"Attack chains identified: {len(session.attack_chains)}")
        for chain in session.attack_chains[:3]:
            parts.append(f"  - Chain: {' -> '.join(chain.get('steps', []))}")

    if session.completed_phases:
        parts.append(f"Completed phases: {', '.join(session.completed_phases)}")

    if session.auth_cookies or session.auth_tokens:
        auth_info = f"Auth state: {session.auth_type or 'unknown'} — "
        if session.auth_cookies:
            auth_info += f"{len(session.auth_cookies)} cookies captured"
        if session.auth_tokens:
            auth_info += f", tokens: {', '.join(session.auth_tokens.keys())}"
        parts.append(
            auth_info +
            " (use inject_cookies action to restore session)")

    parts.append(
        "Use this data to RESUME work — do NOT re-run scans that already have results above."
    )
    return "\n".join(parts)

from __future__ import annotations


import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.payload_memory")


@dataclass
class PayloadRecord:
    payload: str
    vuln_type: str
    target: str
    param: str
    success: bool
    confidence: float
    status_code: int
    waf_detected: str = ""
    tech_stack: list[str] = field(default_factory=list)
    response_time_ms: float = 0.0
    error: str = ""
    timestamp: float = 0.0
    attempts: int = 1

    @property
    def payload_hash(self) -> str:
        return hashlib.sha1(
            f"{self.payload}|{self.vuln_type}|{self.target}|{self.param}".encode(),
            usedforsecurity=False,
        ).hexdigest()[:16]


class PayloadMemoryEngine:
    def __init__(
        self,
        max_records: int = 10000,
        prune_target: int = 5000,
        ttl_seconds: float = 86400 * 7,
    ):
        self.max_records = max_records
        self.prune_target = prune_target
        self.ttl_seconds = ttl_seconds
        self.records: dict[str, PayloadRecord] = {}

    def record_attempt(
        self,
        payload: str,
        vuln_type: str,
        target: str,
        param: str,
        success: bool,
        confidence: float,
        status_code: int,
        waf_detected: str = "",
        tech_stack: list[str] | None = None,
        response_time_ms: float = 0.0,
        error: str = "",
    ) -> None:
        record = PayloadRecord(
            payload=payload,
            vuln_type=vuln_type,
            target=target,
            param=param,
            success=success,
            confidence=confidence,
            status_code=status_code,
            waf_detected=waf_detected,
            tech_stack=tech_stack or [],
            response_time_ms=response_time_ms,
            error=error,
            timestamp=time.time(),
        )
        key = record.payload_hash
        if key in self.records:
            existing = self.records[key]
            existing.attempts += 1
            alpha = 0.3
            existing.confidence = (alpha * confidence) + (
                (1 - alpha) * existing.confidence
            )
            existing.success = success
            existing.status_code = status_code
            existing.timestamp = time.time()
            if waf_detected:
                existing.waf_detected = waf_detected
            if tech_stack:
                existing.tech_stack = list(set(existing.tech_stack + tech_stack))
        else:
            self.records[key] = record
        if len(self.records) > self.max_records:
            self._prune()

    def should_skip_payload(
        self,
        payload: str,
        vuln_type: str,
        target: str,
        param: str,
        min_attempts: int = 2,
    ) -> tuple[bool, str]:
        key = hashlib.sha1(
            f"{payload}|{vuln_type}|{target}|{param}".encode(),
            usedforsecurity=False,
        ).hexdigest()[:16]
        record = self.records.get(key)
        if not record:
            return False, ""
        if record.attempts < min_attempts:
            return False, ""
        if record.success:
            return False, ""
        return (
            True,
            f"Failed {record.attempts} times previously (last: {record.status_code})",
        )

    def get_successful_payloads(
        self,
        vuln_type: str,
        target: str = "",
        waf: str = "",
        tech: str = "",
        top_n: int = 10,
    ) -> list[tuple[str, float]]:
        candidates: list[tuple[str, float, int]] = []
        for record in self.records.values():
            if record.vuln_type != vuln_type or not record.success:
                continue
            score = record.confidence
            if waf and record.waf_detected.lower() == waf.lower():
                score *= 1.3
            if tech and tech.lower() in [t.lower() for t in record.tech_stack]:
                score *= 1.2
            if target and record.target == target:
                score *= 1.1
            candidates.append((record.payload, score, record.attempts))
        candidates.sort(key=lambda x: (x[1], x[2]), reverse=True)
        return [(p, round(s, 3)) for p, s, _ in candidates[:top_n]]

    def save(self, path: str | Path) -> None:
        data = {
            "version": "1.0.0",
            "saved_at": time.time(),
            "records": [asdict(r) for r in self.records.values()],
        }
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load(self, path: str | Path) -> int:
        path = Path(path)
        if not path.exists():
            return 0
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            loaded = 0
            for rdata in data.get("records", []):
                if rdata.get("timestamp", 0) < time.time() - self.ttl_seconds:
                    continue
                record = PayloadRecord(**rdata)
                self.records[record.payload_hash] = record
                loaded += 1
            return loaded
        except Exception as exc:
            logger.warning("Failed to load payload memory: %s", exc)
            return 0

    def _prune(self) -> None:
        sorted_records = sorted(
            self.records.values(),
            key=lambda r: (r.success, r.timestamp, r.attempts),
            reverse=True,
        )
        keep = sorted_records[: self.prune_target]
        self.records = {r.payload_hash: r for r in keep}

    def get_stats(self) -> dict[str, Any]:
        if not self.records:
            return {"total_records": 0}
        total = len(self.records)
        success = sum(1 for r in self.records.values() if r.success)
        return {
            "total_records": total,
            "successful_payloads": success,
            "failed_payloads": total - success,
            "overall_success_rate": round(success / total, 3) if total > 0 else 0,
            "unique_targets": len(set(r.target for r in self.records.values())),
        }

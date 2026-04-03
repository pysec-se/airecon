import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.memory")

MEMORY_DIR = Path.home() / ".airecon" / "memory"
MEMORY_DB = MEMORY_DIR / "airecon.db"

def get_memory_db() -> sqlite3.Connection:
    if not MEMORY_DIR.exists():
        MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("Created memory directory: %s", MEMORY_DIR)

    db_exists = MEMORY_DB.exists()

    conn = sqlite3.connect(str(MEMORY_DB))
    conn.row_factory = sqlite3.Row

    if not db_exists:
        logger.info("Created new memory database: %s", MEMORY_DB)
        _init_schema(conn)

    else:
        _init_schema(conn)

    return conn

def _init_schema(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            target TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            phase TEXT DEFAULT 'RECON',
            subdomains_count INTEGER DEFAULT 0,
            live_hosts_count INTEGER DEFAULT 0,
            vulnerabilities_count INTEGER DEFAULT 0,
            attack_chains_count INTEGER DEFAULT 0,
            token_total INTEGER DEFAULT 0,
            model_used TEXT,
            status TEXT DEFAULT 'completed'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            target TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT DEFAULT 'Medium',
            url TEXT,
            parameter TEXT,
            description TEXT,
            evidence TEXT,
            cwe_id TEXT,
            cvss_score REAL,
            remediation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_type TEXT NOT NULL,  -- 'recon' or 'exploit'
            target_tech TEXT,
            technique_name TEXT NOT NULL,  -- Specific technique name
            description TEXT NOT NULL,
            success_rate REAL DEFAULT 0.0,  -- Must be >= 0.70 to be saved
            times_used INTEGER DEFAULT 1,
            times_successful INTEGER DEFAULT 1,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            payload_template TEXT,
            commands_used TEXT,  -- JSON array of actual commands
            prerequisites TEXT,  -- JSON array of required conditions
            detection_evasion TEXT,  -- Notes on avoiding detection
            effectiveness_score REAL DEFAULT 0.0,  -- 0-100 scale
            notes TEXT,
            source_session TEXT,
            validated INTEGER DEFAULT 0  -- 1 = validated by human, 0 = auto-learned
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_patterns_success_rate ON patterns(success_rate DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_patterns_effectiveness ON patterns(effectiveness_score DESC)")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_domain TEXT NOT NULL UNIQUE,
            subdomains TEXT,  -- JSON array
            open_ports TEXT,  -- JSON object {port: service}
            technologies TEXT,  -- JSON object {tech: version}
            waf_detected TEXT,
            auth_methods TEXT,  -- JSON array
            interesting_endpoints TEXT,  -- JSON array
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            scan_count INTEGER DEFAULT 1
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS knowledge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            confidence REAL DEFAULT 1.0,
            source_session TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT  -- JSON array
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_patterns_type ON patterns(pattern_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(target_domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge(category)")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tool_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT NOT NULL,
            target TEXT,
            success_count INTEGER DEFAULT 0,
            failure_count INTEGER DEFAULT 0,
            avg_duration_sec REAL DEFAULT 0.0,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            typical_output_size INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_performance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT NOT NULL,
            task_type TEXT,
            avg_response_time_sec REAL DEFAULT 0.0,
            success_rate REAL DEFAULT 1.0,
            total_requests INTEGER DEFAULT 0,
            context_size_used INTEGER DEFAULT 0,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_usage_name ON tool_usage(tool_name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_model_performance_name ON model_performance(model_name)")

    conn.commit()
    logger.info("Memory database initialized at %s", MEMORY_DB)

class MemoryManager:
    def __init__(self):
        self.conn = None

    def connect(self) -> None:
        self.conn = get_memory_db()
        logger.debug("Memory manager connected")

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None

    def save_session(self, session_data: dict[str, Any]) -> None:
        if not self.conn:
            return

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO sessions
            (session_id, target, updated_at, phase, subdomains_count,
             live_hosts_count, vulnerabilities_count, attack_chains_count,
             token_total, model_used)
            VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_data.get("session_id"),
            session_data.get("target"),
            session_data.get("current_phase", "RECON"),
            len(session_data.get("subdomains", [])),
            len(session_data.get("live_hosts", [])),
            len(session_data.get("vulnerabilities", [])),
            len(session_data.get("attack_chains", [])),
            session_data.get("token_total", 0),
            session_data.get("model_used"),
        ))
        self.conn.commit()

    def get_past_sessions(self, target: str | None = None, limit: int = 10) -> list[dict]:
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        if target:
            cursor.execute("""
                SELECT * FROM sessions
                WHERE target LIKE ?
                ORDER BY updated_at DESC
                LIMIT ?
            """, (f"%{target}%", limit))
        else:
            cursor.execute("""
                SELECT * FROM sessions
                ORDER BY updated_at DESC
                LIMIT ?
            """, (limit,))

        return [dict(row) for row in cursor.fetchall()]

    def save_finding(self, finding: dict[str, Any]) -> None:
        if not self.conn:
            return

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO findings
            (session_id, target, finding_type, severity, url, parameter,
             description, evidence, cwe_id, cvss_score, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.get("session_id"),
            finding.get("target"),
            finding.get("type", "vulnerability"),
            finding.get("severity", "Medium"),
            finding.get("url"),
            finding.get("parameter"),
            finding.get("description", ""),
            json.dumps(finding.get("evidence", [])),
            finding.get("cwe_id"),
            finding.get("cvss_score"),
            finding.get("remediation", ""),
        ))
        self.conn.commit()

    def get_similar_findings(self, target: str, finding_type: str | None = None, limit: int = 20) -> list[dict]:
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        if finding_type:
            cursor.execute("""
                SELECT * FROM findings
                WHERE (target = ? OR target LIKE ?) AND finding_type = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (target, f"%.{target}", finding_type, limit))
        else:
            cursor.execute("""
                SELECT * FROM findings
                WHERE target = ? OR target LIKE ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (target, f"%.{target}", limit))

        findings = []
        for row in cursor.fetchall():
            finding = dict(row)

            if finding.get("evidence"):
                try:
                    finding["evidence"] = json.loads(finding["evidence"])
                except Exception:
                    pass
            findings.append(finding)

        return findings

    def save_pattern(self, pattern: dict[str, Any]) -> None:
        if not self.conn:
            return

        success_rate = float(pattern.get('success_rate', 0.0))
        if success_rate < 0.70:
            logger.debug(
                "Pattern rejected: success_rate %.2f < 0.70 threshold | %s",
                success_rate, pattern.get('technique_name', 'unknown')
            )
            return

        times_used = int(pattern.get('times_used', 0))
        if times_used < 3:
            logger.debug(
                "Pattern rejected: times_used %d < 3 minimum | %s",
                times_used, pattern.get('technique_name', 'unknown')
            )
            return

        technique_name = pattern.get('technique_name', '').strip()
        if not technique_name or len(technique_name) < 5:
            logger.debug("Pattern rejected: technique_name too short/generic")
            return

        BASIC_PATTERNS = [
            'nmap -sV', 'nmap -sC', 'nmap -p-', 'nmap -F',
            'gobuster dir', 'gobuster dns', 'dirb', 'dirsearch',
            'sqlmap -u', 'nikto', 'whatweb', 'wafw00f',
            'subfinder', 'amass', 'assetfinder', 'httpx',
            'ffuf -w', 'nuclei -t',
        ]
        commands = pattern.get('commands_used', [])
        if isinstance(commands, str):
            try:
                commands = json.loads(commands)
            except Exception:
                commands = [commands]

        is_basic = any(
            basic.lower() in str(cmd).lower()
            for cmd in commands
            for basic in BASIC_PATTERNS
        )
        if is_basic and not pattern.get('advanced_technique', False):
            logger.debug(
                "Pattern rejected: basic tool usage (not advanced technique) | %s",
                technique_name
            )
            return

        description = pattern.get('description', '').strip()
        payload = pattern.get('payload_template', '').strip()
        if not description and not payload and not commands:
            logger.debug("Pattern rejected: no actionable content")
            return

        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT id, times_used, times_successful FROM patterns
            WHERE technique_name = ? AND (target_tech = ? OR target_tech IS ?)
        """, (technique_name, pattern.get('tech'), pattern.get('tech')))

        existing = cursor.fetchone()
        if existing:

            new_times_used = existing["times_used"] + times_used
            new_times_successful = existing["times_successful"] + int(times_used * success_rate)
            new_success_rate = new_times_successful / max(new_times_used, 1)

            cursor.execute("""
                UPDATE patterns SET
                    success_rate = ?, times_used = ?, times_successful = ?,
                    last_used = CURRENT_TIMESTAMP,
                    effectiveness_score = ?,
                    notes = COALESCE(?, notes),
                    source_session = ?
                WHERE id = ?
            """, (
                new_success_rate,
                new_times_used,
                new_times_successful,
                pattern.get('effectiveness_score', new_success_rate * 100),
                pattern.get('notes'),
                pattern.get('source_session'),
                existing["id"]
            ))
        else:

            cursor.execute("""
                INSERT INTO patterns (
                    pattern_type, target_tech, technique_name, description,
                    success_rate, times_used, times_successful,
                    payload_template, commands_used, prerequisites,
                    detection_evasion, effectiveness_score, notes, source_session
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern.get('type', 'recon'),
                pattern.get('tech'),
                technique_name,
                description,
                success_rate,
                times_used,
                int(times_used * success_rate),
                payload,
                json.dumps(commands) if commands else None,
                json.dumps(pattern.get('prerequisites', [])),
                pattern.get('detection_evasion'),
                pattern.get('effectiveness_score', success_rate * 100),
                pattern.get('notes'),
                pattern.get('source_session'),
            ))

        self.conn.commit()
        logger.info(
            "✓ High-quality pattern saved: %s (success=%.0f%%, used=%dx)",
            technique_name, success_rate * 100, times_used
        )

    def get_patterns(self, target_tech: str | None = None, limit: int = 10, min_success_rate: float = 0.70) -> list[dict]:
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        if target_tech:
            cursor.execute("""
                SELECT * FROM patterns
                WHERE (target_tech = ? OR target_tech IS NULL)
                  AND success_rate >= ?
                  AND times_used >= 3
                ORDER BY effectiveness_score DESC, success_rate DESC
                LIMIT ?
            """, (target_tech, min_success_rate, limit))
        else:
            cursor.execute("""
                SELECT * FROM patterns
                WHERE success_rate >= ?
                  AND times_used >= 3
                ORDER BY effectiveness_score DESC, success_rate DESC
                LIMIT ?
            """, (min_success_rate, limit))

        patterns = []
        for row in cursor.fetchall():
            pattern = dict(row)

            if pattern.get("commands_used"):
                try:
                    pattern["commands_used"] = json.loads(pattern["commands_used"])
                except Exception:
                    pattern["commands_used"] = []
            if pattern.get("prerequisites"):
                try:
                    pattern["prerequisites"] = json.loads(pattern["prerequisites"])
                except Exception:
                    pattern["prerequisites"] = []
            patterns.append(pattern)

        logger.debug(
            "Retrieved %d high-quality patterns (min_success=%.0f%%)",
            len(patterns), min_success_rate * 100
        )
        return patterns

    def save_target_intel(self, intel: dict[str, Any]) -> None:
        if not self.conn:
            return

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO targets
            (target_domain, subdomains, open_ports, technologies, waf_detected,
             auth_methods, interesting_endpoints, last_seen, scan_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP,
                    COALESCE((SELECT scan_count FROM targets WHERE target_domain = ?), 0) + 1)
        """, (
            intel.get("target"),
            json.dumps(intel.get("subdomains", [])),
            json.dumps(intel.get("ports", {})),
            json.dumps(intel.get("technologies", {})),
            intel.get("waf"),
            json.dumps(intel.get("auth_methods", [])),
            json.dumps(intel.get("interesting_endpoints", [])),
            intel.get("target"),
        ))
        self.conn.commit()

    def get_target_intel(self, target: str) -> dict | None:
        if not self.conn:
            return None

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM targets WHERE target_domain = ?
        """, (target,))

        row = cursor.fetchone()
        if not row:
            return None

        intel = dict(row)

        for field in ["subdomains", "open_ports", "technologies", "auth_methods", "interesting_endpoints"]:
            if intel.get(field):
                try:
                    intel[field] = json.loads(intel[field])
                except Exception:
                    intel[field] = []

        return intel

    def save_knowledge(self, knowledge: dict[str, Any]) -> None:
        if not self.conn:
            return

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO knowledge
            (category, title, content, confidence, source_session, tags)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            knowledge.get("category"),
            knowledge.get("title"),
            knowledge.get("content"),
            knowledge.get("confidence", 1.0),
            knowledge.get("source_session"),
            json.dumps(knowledge.get("tags", [])),
        ))
        self.conn.commit()

    def get_knowledge(self, category: str | None = None, limit: int = 50) -> list[dict]:
        if not self.conn:
            return []

        cursor = self.conn.cursor()
        if category:
            cursor.execute("""
                SELECT * FROM knowledge
                WHERE category = ?
                ORDER BY confidence DESC, created_at DESC
                LIMIT ?
            """, (category, limit))
        else:
            cursor.execute("""
                SELECT * FROM knowledge
                ORDER BY confidence DESC, created_at DESC
                LIMIT ?
            """, (limit,))

        knowledge_entries = []
        for row in cursor.fetchall():
            entry = dict(row)
            if entry.get("tags"):
                try:
                    entry["tags"] = json.loads(entry["tags"])
                except Exception:
                    entry["tags"] = []
            knowledge_entries.append(entry)

        return knowledge_entries

    def get_context_for_small_model(
        self,
        target: str,
        current_phase: str,
        max_tokens: int = 2000,
    ) -> str:
        context_parts = []
        tokens_used = 0

        intel = self.get_target_intel(target)
        if intel:
            context_parts.append("## TARGET INTELLIGENCE")
            if intel.get("subdomains"):
                subs = ', '.join(intel['subdomains'][:20])
                context_parts.append(f"Subdomains: {subs}")
                tokens_used += len(subs) // 4
            if intel.get("open_ports"):
                ports = intel["open_ports"]
                ports_str = ', '.join(f'{p}:{s}' for p, s in list(ports.items())[:10])
                context_parts.append(f"Open Ports: {ports_str}")
                tokens_used += len(ports_str) // 4
            if intel.get("technologies"):
                tech = intel["technologies"]
                tech_str = ', '.join(f'{t}:{v}' for t, v in list(tech.items())[:10])
                context_parts.append(f"Technologies: {tech_str}")
                tokens_used += len(tech_str) // 4

        findings = self.get_similar_findings(target, limit=10)
        if findings and tokens_used < max_tokens * 0.7:
            context_parts.append("\n## PAST FINDINGS")
            for f in findings[:5]:
                line = f"- [{f['severity']}] {f['finding_type']}: {f['description'][:100]}"
                context_parts.append(line)
                tokens_used += len(line) // 4

        patterns = self.get_patterns(limit=5)
        if patterns and tokens_used < max_tokens * 0.8:
            context_parts.append("\n## ATTACK PATTERNS (Ranked by Success Rate)")
            for p in patterns[:3]:
                line = f"- {p['description'][:100]} (success: {p['success_rate']:.0%}, used: {p['times_used']}x)"
                context_parts.append(line)
                tokens_used += len(line) // 4

        if current_phase == "EXPLOIT" and tokens_used < max_tokens * 0.9:
            knowledge = self.get_knowledge("exploitation", limit=5)
            if knowledge:
                context_parts.append("\n## EXPLOITATION TIPS")
                for k in knowledge[:3]:
                    line = f"- {k['content'][:150]}"
                    context_parts.append(line)
                    tokens_used += len(line) // 4

        if tokens_used < max_tokens * 0.5:
            baseline = self.get_knowledge(limit=10)
            if baseline:
                context_parts.append("\n## SECURITY KNOWLEDGE BASE")
                for k in baseline[:5]:
                    line = f"- [{k['category']}] {k['title']}: {k['content'][:100]}"
                    context_parts.append(line)
                    tokens_used += len(line) // 4

        return "\n".join(context_parts)

    def get_similar_targets(self, target: str, limit: int = 5) -> list[dict]:
        if not self.conn:
            return []

        intel = self.get_target_intel(target)
        if not intel or not intel.get("technologies"):
            return []

        current_techs = set(intel["technologies"].keys())

        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM targets WHERE target_domain != ?", (target,))

        similar = []
        for row in cursor.fetchall():
            try:
                techs = json.loads(row["technologies"]) if row["technologies"] else {}
                overlap = current_techs.intersection(set(techs.keys()))
                if overlap:
                    target_data = dict(row)
                    target_data["tech_overlap"] = list(overlap)
                    target_data["similarity_score"] = len(overlap) / max(len(current_techs), 1)
                    similar.append(target_data)
            except Exception:
                continue

        similar.sort(key=lambda x: x.get("similarity_score", 0), reverse=True)
        return similar[:limit]

    def get_tool_statistics(self, tool_name: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        if not self.conn:
            return {}

        cursor = self.conn.cursor()
        if tool_name:
            cursor.execute("""
                SELECT * FROM tool_usage WHERE tool_name = ?
            """, (tool_name,))
            row = cursor.fetchone()
            return dict(row) if row else {}
        else:
            cursor.execute("""
                SELECT tool_name, success_count, failure_count, avg_duration_sec
                FROM tool_usage ORDER BY last_used DESC LIMIT 20
            """)
            return [dict(row) for row in cursor.fetchall()]

    def record_tool_usage(
        self,
        tool_name: str,
        target: str,
        success: bool,
        duration_sec: float,
        output_size: int,
    ) -> None:
        if not self.conn:
            return

        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT id, success_count, failure_count, avg_duration_sec FROM tool_usage
            WHERE tool_name = ? AND (target = ? OR target IS NULL)
        """, (tool_name, target))

        existing = cursor.fetchone()
        if existing:

            new_success = existing["success_count"] + (1 if success else 0)
            new_failure = existing["failure_count"] + (0 if success else 1)
            total = new_success + new_failure
            new_avg = ((existing["avg_duration_sec"] * (total - 1)) + duration_sec) / total

            cursor.execute("""
                UPDATE tool_usage SET
                    success_count = ?, failure_count = ?, avg_duration_sec = ?,
                    typical_output_size = ?, last_used = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (new_success, new_failure, new_avg, output_size, existing["id"]))
        else:
            cursor.execute("""
                INSERT INTO tool_usage
                (tool_name, target, success_count, failure_count, avg_duration_sec, typical_output_size)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (tool_name, target, 1 if success else 0, 0 if success else 1, duration_sec, output_size))

        self.conn.commit()

    def get_model_recommendation(self, task_type: str) -> str:

        def _config_default_model() -> str:
            try:
                from airecon.proxy.config import get_config
                cfg = get_config()
                model = (cfg.ollama_model if cfg else "") or ""
                logger.debug("Config loaded: ollama_model=%s", model or None)
                if model:
                    return model
                logger.debug("Config or ollama_model is None/empty")
            except Exception as e:
                logger.debug("Config read failed: %s", e)
            return ""

        if not self.conn:
            model = _config_default_model()
            if model:
                logger.debug("Returning user config model: %s", model)
                return model
            logger.warning("No model configured — check ~/.airecon/config.yaml")
            return ""

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT model_name, success_rate, avg_response_time_sec, total_requests
            FROM model_performance
            WHERE task_type = ? OR task_type IS NULL
            ORDER BY success_rate DESC, avg_response_time_sec ASC
            LIMIT 1
        """, (task_type,))

        row = cursor.fetchone()
        if row and row["total_requests"] >= 5:
            return row["model_name"]

        model = _config_default_model()
        if model:
            logger.debug("Returning user config model (fallback path): %s", model)
            return model

        logger.warning("No model configured — check ~/.airecon/config.yaml")
        return ""

_memory_manager: MemoryManager | None = None

def get_memory_manager() -> MemoryManager:
    global _memory_manager
    if _memory_manager is None:
        _memory_manager = MemoryManager()
        _memory_manager.connect()
    return _memory_manager

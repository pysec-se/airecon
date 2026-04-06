from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import logging
import time

logger = logging.getLogger("airecon.agent.session_persistence")


class SessionPersistenceEngine:
    def __init__(self, workspace_root: str | Path | None = None):
        self.workspace_root = Path(workspace_root) if workspace_root else None

    def _get_session_dir(self, target: str) -> Path:
        if not self.workspace_root:
            raise ValueError("workspace_root not set")
        safe_name = target.replace("://", "_").replace("/", "_").replace(":", "_")
        session_dir = self.workspace_root / safe_name
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir

    def save_session_state(self, target: str, state: dict[str, Any]) -> Path:
        session_dir = self._get_session_dir(target)
        state_file = session_dir / "session_state.json"
        data = {
            "version": "1.0.0",
            "saved_at": time.time(),
            "target": target,
            "state": state,
        }
        state_file.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("Session state saved for %s", target)
        return state_file

    def load_session_state(self, target: str) -> dict[str, Any] | None:
        try:
            session_dir = self._get_session_dir(target)
            state_file = session_dir / "session_state.json"
            if not state_file.exists():
                return None
            data = json.loads(state_file.read_text(encoding="utf-8"))
            if data.get("version") != "1.0.0":
                return None
            logger.info("Session state loaded for %s", target)
            return data.get("state", {})
        except Exception as e:
            logger.debug("Failed to load session state for %s: %s", target, e)
            return None

    def save_payload_memory(self, target: str, records: list[dict[str, Any]]) -> Path:
        session_dir = self._get_session_dir(target)
        payload_file = session_dir / "payload_memory.json"
        data = {
            "version": "1.0.0",
            "saved_at": time.time(),
            "target": target,
            "records": records,
        }
        payload_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return payload_file

    def load_payload_memory(self, target: str) -> list[dict[str, Any]]:
        try:
            session_dir = self._get_session_dir(target)
            payload_file = session_dir / "payload_memory.json"
            if not payload_file.exists():
                return []
            data = json.loads(payload_file.read_text(encoding="utf-8"))
            return data.get("records", [])
        except Exception as e:
            logger.debug("Failed to load payload memory for %s: %s", target, e)
            return []

    def save_adaptive_state(self, target: str, state: dict[str, Any]) -> Path:
        session_dir = self._get_session_dir(target)
        adaptive_file = session_dir / "adaptive_state.json"
        data = {
            "version": "1.0.0",
            "saved_at": time.time(),
            "target": target,
            "state": state,
        }
        adaptive_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return adaptive_file

    def load_adaptive_state(self, target: str) -> dict[str, Any] | None:
        try:
            session_dir = self._get_session_dir(target)
            adaptive_file = session_dir / "adaptive_state.json"
            if not adaptive_file.exists():
                return None
            data = json.loads(adaptive_file.read_text(encoding="utf-8"))
            return data.get("state")
        except Exception as e:
            logger.debug("Failed to load adaptive state for %s: %s", target, e)
            return None

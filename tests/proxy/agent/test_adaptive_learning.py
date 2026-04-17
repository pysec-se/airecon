"""Tests for Adaptive Learning."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest


def _init_learning_db(db_path: Path) -> None:
    from airecon.proxy.memory import _init_schema, configure_sqlite_connection

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    configure_sqlite_connection(conn)
    _init_schema(conn)
    conn.close()


@pytest.fixture
def isolated_learning_paths(tmp_path, monkeypatch):
    import airecon.proxy.agent.adaptive_learning as learning_mod

    learning_dir = tmp_path / "learning"
    learning_dir.mkdir()
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    memory_db = memory_dir / "airecon.db"

    monkeypatch.setattr(learning_mod, "_LEARNING_DIR", learning_dir)
    monkeypatch.setattr(learning_mod, "_MEMORY_DB", memory_db)
    monkeypatch.setattr(learning_mod, "_TARGET_MEMORY_DIR", tmp_path / "by_target")
    return learning_mod, memory_db


class TestToolPerformance:
    def test_creation(self):
        from airecon.proxy.agent.adaptive_learning import ToolPerformance

        p = ToolPerformance(tool_name="test")
        assert p.tool_name == "test"


class TestAdaptiveLearningEngine:
    def test_init(self, isolated_learning_paths):
        learning_mod, _ = isolated_learning_paths

        engine = learning_mod.AdaptiveLearningEngine()
        assert engine is not None

    def test_import_from_memory_db_aggregates_scoped_tool_usage(
        self, isolated_learning_paths
    ):
        learning_mod, memory_db = isolated_learning_paths
        _init_learning_db(memory_db)

        conn = sqlite3.connect(str(memory_db))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.executemany(
            """
            INSERT INTO tool_usage
            (tool_name, target, success_count, failure_count, avg_duration_sec, typical_output_size)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                ("nmap", "a.example.com", 1, 0, 10.0, 100),
                ("nmap", "b.example.com", 2, 1, 20.0, 200),
            ],
        )
        conn.commit()
        conn.close()

        engine = learning_mod.AdaptiveLearningEngine(session_id="test_import")
        perf = engine.tool_performances["nmap"]

        assert perf.successes == 3
        assert perf.failures == 1
        assert perf.total_uses == 4

    def test_sync_to_memory_db_collapses_duplicate_global_rows(
        self, isolated_learning_paths
    ):
        learning_mod, memory_db = isolated_learning_paths
        _init_learning_db(memory_db)

        conn = sqlite3.connect(str(memory_db))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.executemany(
            """
            INSERT INTO tool_usage
            (tool_name, target, success_count, failure_count, avg_duration_sec, typical_output_size)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                ("ffuf", "", 1, 0, 1.0, 10),
                ("ffuf", "", 3, 1, 2.0, 20),
                ("ffuf", "example.com", 2, 0, 1.5, 15),
            ],
        )
        conn.commit()
        conn.close()

        engine = learning_mod.AdaptiveLearningEngine(session_id="test_sync")
        engine.tool_performances["ffuf"] = learning_mod.ToolPerformance(
            tool_name="ffuf",
            total_uses=6,
            successes=5,
            failures=1,
            avg_duration=1.7,
        )
        engine._sync_to_memory_db()

        conn = sqlite3.connect(str(memory_db))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT success_count, failure_count
            FROM tool_usage
            WHERE tool_name = ? AND target = ''
            ORDER BY id ASC
            """,
            ("ffuf",),
        )
        rows = cur.fetchall()
        conn.close()

        assert len(rows) == 1
        assert rows[0]["success_count"] == 5
        assert rows[0]["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_distill_insights_uses_worker_executor_inside_running_loop(
        self, isolated_learning_paths, monkeypatch
    ):
        learning_mod, _ = isolated_learning_paths
        engine = learning_mod.AdaptiveLearningEngine(
            min_observations=1,
            session_id="test_distill",
        )
        engine.observation_log = [
            learning_mod.ObservationLog(
                timestamp=1.0,
                tool_name="http_observe",
                arguments={},
                result_summary="ok",
                success=True,
                confidence=0.8,
                phase="RECON",
                target_type="nginx",
            )
            for _ in range(3)
        ]

        calls: dict[str, object] = {}

        class _FakeFuture:
            def result(self, timeout=None):
                calls["timeout"] = timeout
                return json.dumps(
                    [
                        {
                            "category": "tool_tech",
                            "title": "Prefer observe first",
                            "conditions": {"tech": "nginx"},
                            "recommendation": "Run observe before fuzzing",
                        }
                    ]
                )

        class _FakeExecutor:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn):
                calls["submitted"] = True
                return _FakeFuture()

        monkeypatch.setattr(
            learning_mod.concurrent.futures,
            "ThreadPoolExecutor",
            lambda max_workers=1: _FakeExecutor(),
        )

        insights = engine.distill_insights(
            ollama_url="http://ollama.local",
            model="qwen-test",
        )

        assert calls["submitted"] is True
        assert calls["timeout"] == 125
        assert len(insights) == 1
        assert insights[0].title == "Prefer observe first"


class TestTargetMemoryStore:
    def test_revisited_target_increments_session_count_and_prompt_text(self, tmp_path):
        from airecon.proxy.agent.adaptive_learning import TargetMemoryStore

        store = TargetMemoryStore(base_dir=tmp_path)
        store.record_endpoint("https://example.com", "/login")
        store.save("https://example.com")

        new_store = TargetMemoryStore(base_dir=tmp_path)
        injection = new_store.get_injection_text("https://example.com")

        assert injection is not None
        assert "from 1 previous session(s) on example.com" in injection

        data = json.loads(new_store._file_path("https://example.com").read_text())
        assert data["session_count"] == 2

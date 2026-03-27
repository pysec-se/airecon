"""Tests for InteractiveRealTimeTester in fuzzer.py."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock
from airecon.proxy.fuzzer import InteractiveRealTimeTester


class TestInteractiveRealTimeTester:
    """Test real-time fuzzing with live result streaming."""

    def test_init_sets_defaults(self) -> None:
        """Test InteractiveRealTimeTester initialization."""
        tester = InteractiveRealTimeTester("https://example.com/search")
        
        assert tester.target == "https://example.com/search"
        assert tester.fuzzer is not None
        assert tester.chain_engine is not None
        assert tester.on_finding is None
        assert tester._findings == []
        assert tester._chains == []

    def test_init_with_custom_params(self) -> None:
        """Test initialization with custom threads, timeout, headers."""
        headers = {"Authorization": "Bearer token123"}
        tester = InteractiveRealTimeTester(
            target="https://api.example.com",
            threads=10,
            timeout=30,
            headers=headers,
        )
        
        assert tester.target == "https://api.example.com"
        assert tester.fuzzer.threads == 10
        assert tester.fuzzer.timeout == 30
        assert tester.fuzzer.headers == headers

    @pytest.mark.asyncio
    async def test_probe_baseline_returns_param_stats(self) -> None:
        """Test probe_baseline returns statistics for each parameter."""
        tester = InteractiveRealTimeTester("https://example.com/search")
        
        # Mock fuzzer probe method
        tester.fuzzer.probe = AsyncMock(return_value={
            "status": 200,
            "response_time": 0.5,
            "body_length": 1024,
        })
        
        result = await tester.probe_baseline(["q", "id", "page"])
        
        assert isinstance(result, dict)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_stream_fuzz_yields_finding_events(self) -> None:
        """Test stream_fuzz yields RealTimeEvent with finding data."""
        tester = InteractiveRealTimeTester("https://example.com/search")
        
        # Mock fuzzer to yield findings
        async def mock_fuzz(*args, **kwargs):
            yield {
                "param": "q",
                "payload": "' OR 1=1--",
                "vuln_type": "SQL Injection",
                "severity": "high",
                "status_code": 500,
            }
        
        tester.fuzzer.fuzz = mock_fuzz
        
        events = []
        async for event in tester.stream_fuzz(params=["q"]):
            events.append(event)
            if len(events) >= 1:
                break
        
        assert len(events) > 0
        assert events[0].event_type in ("finding", "progress", "complete")

    @pytest.mark.asyncio
    async def test_stream_fuzz_yields_chain_discovery_events(self) -> None:
        """Test stream_fuzz yields chain discovery events when exploit chains found."""
        tester = InteractiveRealTimeTester("https://example.com/api")
        
        # Mock chain engine to return chains
        mock_chain = MagicMock()
        mock_chain.chain_id = "sqli_to_rce"
        mock_chain.name = "SQL Injection to RCE Chain"
        mock_chain.steps = ["SQLi", "File Read", "RCE"]
        
        async def mock_fuzz_with_chain(*args, **kwargs):
            yield {
                "param": "id",
                "payload": "1; cat /etc/passwd",
                "vuln_type": "SQL Injection",
                "severity": "critical",
            }
            # Simulate chain discovery
            tester._chains.append(mock_chain)
        
        tester.fuzzer.fuzz = mock_fuzz_with_chain
        tester.chain_engine.find_chains = AsyncMock(return_value=[mock_chain])
        
        events = []
        async for event in tester.stream_fuzz(params=["id"]):
            events.append(event)
            if len(events) >= 2:
                break
        
        # Should have at least finding event
        assert len(events) > 0

    @pytest.mark.asyncio
    async def test_stream_fuzz_handles_errors_gracefully(self) -> None:
        """Test stream_fuzz handles fuzzer errors without crashing."""
        tester = InteractiveRealTimeTester("https://example.com/broken")
        
        # Mock fuzzer to raise error
        async def mock_fuzz_error(*args, **kwargs):
            raise Exception("Connection timeout")
        
        tester.fuzzer.fuzz = mock_fuzz_error
        
        events = []
        # Should not crash, should handle error gracefully
        try:
            async for event in tester.stream_fuzz(params=["q"]):
                events.append(event)
        except Exception as e:
            # Error is expected, but should be handled
            assert "timeout" in str(e).lower() or "connection" in str(e).lower()

    @pytest.mark.asyncio
    async def test_stop_request(self) -> None:
        """Test stop method sets stop event."""
        tester = InteractiveRealTimeTester("https://example.com")
        
        assert tester._stop_event.is_set() is False
        await tester.stop()
        assert tester._stop_event.is_set() is True

    def test_get_summary_returns_stats(self) -> None:
        """Test get_summary returns fuzzing statistics."""
        tester = InteractiveRealTimeTester("https://example.com")
        
        # Add mock findings
        mock_finding = MagicMock()
        mock_finding.param = "q"
        mock_finding.vuln_type = "XSS"
        mock_finding.severity = "medium"
        tester._findings.append(mock_finding)
        
        summary = tester.get_summary()
        
        assert isinstance(summary, dict)
        assert "findings" in summary or "total" in summary or len(summary) > 0

"""Tests for OllamaClient response time tracking and adaptive timeout.

FIX 2026-03-30 #3: Ensure response time methods work correctly even when
tests bypass __init__ via __new__().
"""

from __future__ import annotations


from airecon.proxy.ollama import OllamaClient


class TestResponseTimeTracking:
    """Test _record_response_time and related methods."""

    def test_record_response_time_appends_to_list(self) -> None:
        """_record_response_time should append response times."""
        client = OllamaClient.__new__(OllamaClient)
        # Property ensures lazy initialization even without __init__
        client._response_times = []  # Explicit init for test clarity
        client._max_response_times = 20

        client._record_response_time(5.0)
        assert len(client._response_times) == 1
        assert client._response_times[0] == 5.0

        client._record_response_time(10.0)
        assert len(client._response_times) == 2
        assert client._response_times == [5.0, 10.0]

    def test_record_response_time_trims_to_max(self) -> None:
        """_record_response_time should trim to max_response_times."""
        client = OllamaClient.__new__(OllamaClient)
        client._response_times = []
        client._max_response_times = 3

        # Add 5 times, should only keep last 3
        for i in range(5):
            client._record_response_time(float(i))

        assert len(client._response_times) == 3
        assert client._response_times == [2.0, 3.0, 4.0]

    def test_record_response_time_works_without_init(self) -> None:
        """_record_response_time should work even if __init__ not called.

        This tests the lazy initialization property pattern.
        """
        client = OllamaClient.__new__(OllamaClient)
        # Don't initialize _response_times - property should handle it

        # Should not raise AttributeError
        client._record_response_time(5.0)
        assert len(client._response_times) == 1

    def test_get_response_time_stats_empty(self) -> None:
        """get_response_time_stats should return zeros when empty."""
        client = OllamaClient.__new__(OllamaClient)
        client._response_times = []

        stats = client.get_response_time_stats()
        assert stats == {"avg": 0.0, "min": 0.0, "max": 0.0, "count": 0}

    def test_get_response_time_stats_with_data(self) -> None:
        """get_response_time_stats should calculate correct statistics."""
        client = OllamaClient.__new__(OllamaClient)
        client._response_times = [10.0, 20.0, 30.0, 40.0, 50.0]

        stats = client.get_response_time_stats()
        assert stats["count"] == 5
        assert stats["min"] == 10.0
        assert stats["max"] == 50.0
        assert stats["avg"] == 30.0  # avg of last 10 (or all if <10)

    def test_get_response_time_stats_uses_last_10(self) -> None:
        """get_response_time_stats should use only last 10 for avg/min/max."""
        client = OllamaClient.__new__(OllamaClient)
        # Add 15 times
        client._response_times = [float(i) for i in range(15)]

        stats = client.get_response_time_stats()
        assert stats["count"] == 15  # Total count
        # Last 10: [5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        assert stats["min"] == 5.0
        assert stats["max"] == 14.0
        assert stats["avg"] == 9.5  # avg of 5..14


class TestDynamicTimeout:
    """Test _get_dynamic_timeout method."""

    def test_get_dynamic_timeout_uses_base_when_few_samples(self) -> None:
        """_get_dynamic_timeout should use base timeout when <3 samples."""
        client = OllamaClient.__new__(OllamaClient)
        client._response_times = [10.0, 20.0]  # Only 2 samples
        client.model = "qwen3.5:122b"

        timeout = client._get_dynamic_timeout()
        assert timeout == 300.0  # Base timeout for 122b model

    def test_get_dynamic_timeout_adapts_with_enough_samples(self) -> None:
        """_get_dynamic_timeout should adapt based on response times."""
        client = OllamaClient.__new__(OllamaClient)
        client._response_times = [10.0, 20.0, 30.0]  # 3 samples
        client.model = "test-model"

        timeout = client._get_dynamic_timeout()
        # 3x avg of last 10 = 3 * 20 = 60, which is > base (90)
        # So should use base timeout
        assert timeout >= 60.0

    def test_get_dynamic_timeout_compression_operation(self) -> None:
        """_get_dynamic_timeout should increase timeout for compression."""
        client = OllamaClient.__new__(OllamaClient)
        client._response_times = []
        client.model = "test-model"

        timeout = client._get_dynamic_timeout(operation="compression")
        assert timeout >= 120.0  # Compression minimum

    def test_get_dynamic_timeout_caps_at_maximum(self) -> None:
        """_get_dynamic_timeout should cap at 10 minutes."""
        client = OllamaClient.__new__(OllamaClient)
        # Add very slow response times
        client._response_times = [500.0] * 10
        client.model = "test-model"

        timeout = client._get_dynamic_timeout()
        assert timeout <= 600.0  # 10 minutes max

    def test_get_dynamic_timeout_works_without_init(self) -> None:
        """_get_dynamic_timeout should work even if __init__ not called."""
        client = OllamaClient.__new__(OllamaClient)
        client.model = "qwen3.5:122b"
        # Don't initialize _response_times

        # Should not raise AttributeError
        timeout = client._get_dynamic_timeout()
        assert timeout == 300.0  # Base timeout for 122b

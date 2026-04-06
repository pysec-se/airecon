"""Tests for Data Loader."""
from __future__ import annotations
from airecon.proxy.data_loader import (
    load_endpoint_patterns,
    load_fuzzer_data,
    load_tech_correlations,
    load_tools_meta,
)

class TestDataLoader:
    def test_load_tech_correlations(self):
        data = load_tech_correlations()
        assert isinstance(data, dict)
    def test_load_endpoint_patterns(self):
        data = load_endpoint_patterns()
        assert isinstance(data, dict)
    def test_load_fuzzer_data(self):
        data = load_fuzzer_data()
        assert isinstance(data, dict)
    def test_load_tools_meta(self):
        data = load_tools_meta()
        assert isinstance(data, dict)

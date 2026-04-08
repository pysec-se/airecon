"""Tests for Exploration Mixin."""

from __future__ import annotations

from types import SimpleNamespace


class TestExplorationMixin:
    def test_module_imports(self):
        from airecon.proxy.agent import loop_exploration
        assert loop_exploration is not None

    def test_untested_vuln_classes_use_ontology_not_tool_names(self):
        from airecon.proxy.agent.loop_exploration import _ExplorationMixin

        class Dummy(_ExplorationMixin):
            def __init__(self):
                self.state = SimpleNamespace(evidence_log=[], skills_used=[], iteration=0)
                self._session = SimpleNamespace(vulnerabilities=[])

            def _load_skills_index(self):
                return {}

            def _get_vuln_terms_from_system_prompt(self):
                return []

        agent = Dummy()
        untested = agent._get_untested_vuln_classes(set())

        assert "protocol_abuse" in untested
        assert "sqlmap" not in untested

    def test_tested_vuln_classes_are_normalized_to_ontology_labels(self):
        from airecon.proxy.agent.loop_exploration import _ExplorationMixin

        class Dummy(_ExplorationMixin):
            def __init__(self):
                self.state = SimpleNamespace(
                    evidence_log=[
                        {"tags": ["xss"], "summary": "Reflected xss in search response"}
                    ],
                    skills_used=[],
                    iteration=0,
                )
                self._session = SimpleNamespace(
                    vulnerabilities=[
                        {
                            "title": "JWT alg:none auth bypass in API",
                            "severity": "HIGH",
                        }
                    ]
                )

            def _load_skills_index(self):
                return {}

            def _get_vuln_terms_from_system_prompt(self):
                return []

        agent = Dummy()
        tested = agent._get_tested_vuln_classes()

        assert "client_side" in tested
        assert "authentication" in tested

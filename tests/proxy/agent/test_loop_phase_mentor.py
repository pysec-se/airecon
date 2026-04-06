"""Tests for Phase Mentor."""

class TestPhaseMentor:
    def test_module_imports(self):
        from airecon.proxy.agent import loop_phase_mentor
        assert loop_phase_mentor is not None

from types import SimpleNamespace

from core_topo_gen import cli


class DummyCore:
    def __init__(self, sessions):
        self._sessions = sessions

    def get_sessions(self):
        return list(self._sessions)


def test_core_state_str_normalizes_runtime_state():
    assert cli._core_state_str("RUNTIME_STATE") == "runtime_state"
    assert cli._core_state_str("SessionState.RUNTIME_STATE") == "runtime_state"
    assert cli._is_runtime_state("runtime_state") is True
    assert cli._is_runtime_state("RUNTIME_STATE") is True


def test_wait_for_core_runtime_accepts_runtime_state():
    sess = SimpleNamespace(id=1, state="RUNTIME_STATE")
    core = DummyCore([sess])
    ok, st = cli._wait_for_core_runtime(core, 1, timeout_s=0.2, poll_s=0.05)
    assert ok is True
    assert cli._is_runtime_state(st) is True

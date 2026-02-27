from types import SimpleNamespace

from core_topo_gen.builders.topology import _session_add_node


class SessionSupportsStart:
    def __init__(self):
        self.calls = []

    def add_node(self, node_id, **kwargs):
        self.calls.append((node_id, kwargs))
        return SimpleNamespace(id=node_id, kwargs=kwargs)


class SessionNoStart:
    def __init__(self):
        self.calls = []

    def add_node(self, node_id, **kwargs):
        # Simulate wrapper that rejects unknown kwarg 'start'
        if 'start' in kwargs:
            raise TypeError("unexpected keyword 'start'")
        self.calls.append((node_id, kwargs))
        return SimpleNamespace(id=node_id, kwargs=kwargs)


def test_session_add_node_passes_start_when_supported():
    s = SessionSupportsStart()
    n = _session_add_node(s, 1, node_type="DOCKER", name="n1", start=False)
    assert n.id == 1
    assert s.calls
    _node_id, kw = s.calls[0]
    assert kw.get('start') is False


def test_session_add_node_falls_back_when_start_not_supported():
    s = SessionNoStart()
    n = _session_add_node(s, 2, node_type="DOCKER", name="n2", start=False)
    assert n.id == 2
    assert s.calls
    _node_id, kw = s.calls[0]
    assert 'start' not in kw

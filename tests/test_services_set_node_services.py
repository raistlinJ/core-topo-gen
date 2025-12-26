from __future__ import annotations

from types import SimpleNamespace

from core_topo_gen.utils.services import set_node_services


class _WeirdServices:
    """Simulates a CORE wrapper where services.set(node_id, ...) is a silent no-op.

    Some CORE gRPC wrapper variants expect a node object, not an id. When passed an
    int they may not error but also won't apply the change.
    """

    def __init__(self) -> None:
        self._by_node_id: dict[int, list[str]] = {}

    def set(self, node_id_or_obj, services: tuple[str, ...]) -> None:
        if hasattr(node_id_or_obj, "id"):
            self._by_node_id[int(node_id_or_obj.id)] = list(services)
        else:
            # silent no-op for ids
            return

    def get(self, node_id_or_obj):
        node_id = int(getattr(node_id_or_obj, "id", node_id_or_obj))
        return tuple(self._by_node_id.get(node_id, []))


class _Session:
    def __init__(self) -> None:
        self.services = _WeirdServices()


def test_set_node_services_retries_with_node_obj_when_id_noops() -> None:
    session = _Session()
    node = SimpleNamespace(id=123)

    ok = set_node_services(session, 123, ["IPForward", "zebra", "RIP"], node_obj=node)
    assert ok is True
    assert set(session.services.get(123)) == {"IPForward", "zebra", "RIP"}

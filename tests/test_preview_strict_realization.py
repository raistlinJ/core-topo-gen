import pytest

from core_topo_gen.builders import topology as topo_mod
from core_topo_gen.types import RoutingInfo
from tests.test_router_mesh import DummyClient, FakeSession, _patch_safe_create_session


def test_preview_payload_failure_is_fatal_by_default(monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    # Mark this as a preview payload, but intentionally omit required pieces
    # so preview realization returns None.
    preview_plan = {
        "routers": [{"node_id": 1, "name": "r1"}],
        # 'hosts' missing on purpose
    }

    routing_items = [RoutingInfo(protocol="OSPFv2", factor=1.0, abs_count=1, r2s_mode="Exact", r2s_edges=1)]

    with pytest.raises(RuntimeError, match=r"Preview plan was provided but could not be realized exactly"):
        topo_mod.build_segmented_topology(
            DummyClient(),
            role_counts={"Workstation": 1},
            routing_density=0.0,
            routing_items=routing_items,
            base_host_pool=1,
            services=None,
            preview_plan=preview_plan,
        )


def test_preview_fallback_can_be_enabled(monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    monkeypatch.setenv("CORETG_ALLOW_PREVIEW_FALLBACK", "1")

    preview_plan = {
        "routers": [{"node_id": 1, "name": "r1"}],
        # 'hosts' missing on purpose
    }

    routing_items = [RoutingInfo(protocol="OSPFv2", factor=1.0, abs_count=1, r2s_mode="Exact", r2s_edges=1)]

    sess, routers, hosts, *_ = topo_mod.build_segmented_topology(
        DummyClient(),
        role_counts={"Workstation": 1},
        routing_density=0.0,
        routing_items=routing_items,
        base_host_pool=1,
        services=None,
        preview_plan=preview_plan,
    )

    assert sess is session
    assert len(routers) >= 1
    assert len(hosts) >= 1

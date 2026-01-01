from core_topo_gen.planning.router_host_plan import plan_r2s_grouping


class DummyHost:
    def __init__(self, node_id: int):
        self.node_id = node_id


def test_prune_switches_with_no_non_router_attachments():
    """If planning asks for more switches than there are hosts, empty switch buckets
    must be pruned so we don't create router-only switches (and router->switch links).
    """
    routers = 2
    # Two hosts total, mapped one-per-router.
    # Host node IDs in this helper test are arbitrary; only the mapping matters.
    host_router_map = {101: 1, 102: 2}
    hosts = [DummyHost(101), DummyHost(102)]

    out = plan_r2s_grouping(
        routers_planned=routers,
        host_router_map=host_router_map,
        host_nodes=hosts,
        routing_items=None,
        r2s_policy={"mode": "Exact", "target_per_router": 3},
        seed=1234,
        ip4_prefix="10.90.0.0/16",
    )

    switches_detail = out.get("switches_detail") or []
    # Should create only one switch per router (since each router has only 1 host).
    assert len(switches_detail) == routers
    assert all((detail.get("hosts") or []) for detail in switches_detail)

    policy = out.get("computed_r2s_policy") or {}
    unmet = policy.get("unmet_switch_targets") or {}
    assert unmet.get(1) == 2
    assert unmet.get(2) == 2

    # Ensure subnet lists remain aligned with actual switches created.
    assert len(out.get("router_switch_subnets") or []) == len(switches_detail)
    assert len(out.get("lan_subnets") or []) == len(switches_detail)

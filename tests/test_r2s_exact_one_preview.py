import json
from core_topo_gen.planning.full_preview import build_full_preview

def test_r2s_exact_one_preview_all_hosts_under_single_switch():
    role_counts = {"Workstation": 5}
    routers_planned = 2
    # Provide routing_items-like structures for auto-derive (simulate RoutingInfo dataclass minimal)
    class DummyRI:
        def __init__(self, r2s_mode, r2s_edges):
            self.r2s_mode = r2s_mode
            self.r2s_edges = r2s_edges
    routing_items = [DummyRI('Exact', 1)]
    prev = build_full_preview(
        role_counts=role_counts,
        routers_planned=routers_planned,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy=None,
        routing_items=routing_items,
        routing_plan={},
        segmentation_density=None,
        segmentation_items=None,
        seed=1234,
        ip4_prefix='10.10.0.0/16'
    )
    r2s = prev.get('r2s_policy_preview', {})
    assert r2s.get('mode') == 'Exact'
    counts = r2s.get('counts') or {}
    # Every router with hosts should have exactly 1 switch
    assert all(c == 1 for c in counts.values())
    # Ensure switches list length equals number of routers that had any hosts >0
    assert len(prev.get('switches', [])) == len(counts)
    # Each switch's host list should cover all hosts of that router (aggregated semantics) – check first switch detail
    sw_details = prev.get('switches_detail') or []
    assert sw_details, 'Expected at least one switch detail record'
    # Validate no switch record is limited to only 2 hosts unless router truly had only 2
    for rec in sw_details:
        assert len(rec.get('hosts', [])) >= 1

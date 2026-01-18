from core_topo_gen.planning.full_preview import build_full_preview


def test_full_preview_no_routers_star_topology():
    role_counts = {
        'Workstation': 4,
        'Server': 1,
    }
    preview = build_full_preview(
        role_counts=role_counts,
        routers_planned=0,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy=None,
        routing_items=None,
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=None,
        seed=123,
        ip4_prefix='10.50.0.0/16',
    )

    hosts = preview.get('hosts') or []
    routers = preview.get('routers') or []
    switches = preview.get('switches') or []
    switches_detail = preview.get('switches_detail') or []

    assert len(routers) == 0
    assert len(hosts) == sum(role_counts.values())

    # Expect a single-switch star topology when there are no routers.
    assert len(switches) == 1
    assert len(switches_detail) == 1

    detail = switches_detail[0]
    assert detail.get('router_id') is None

    host_ids = sorted(int(h.get('node_id')) for h in hosts)
    assert sorted(int(x) for x in (detail.get('hosts') or [])) == host_ids

    # Should include a LAN subnet so host IP assignment can be deterministic.
    lan = detail.get('lan_subnet')
    assert isinstance(lan, str) and '/' in lan

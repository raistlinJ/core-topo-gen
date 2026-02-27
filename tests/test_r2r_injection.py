from webapp import app_backend as backend


def _base_preview():
    return {
        'routers': [
            {'node_id': 10, 'name': 'r10', 'metadata': {}},
            {'node_id': 11, 'name': 'r11', 'metadata': {}},
        ],
        'layout_positions': {'routers': {'10': {'x': 100, 'y': 200}}},
    }


def test_wire_hitl_preview_routers_adds_r2r_preview_structures():
    full_preview = _base_preview()
    hitl_cfg = {
        'scenario_key': 'scenario-a',
        'interfaces': [
            {
                'name': 'eth0',
                'ordinal': 0,
                'interface_count': 1,
                'prefix_len': 24,
                'new_router_ip4': '10.99.0.2',
                'existing_router_ip4': '10.99.0.1',
                'link_network_cidr': '10.99.0.0/24',
                'preview_router': {
                    'node_id': 200,
                    'name': 'hitl-r200',
                    'metadata': {'hitl_preview': True, 'ordinal': 0, 'interface_count': 1},
                },
            }
        ],
    }

    backend._wire_hitl_preview_routers(full_preview, hitl_cfg)

    edges = full_preview.get('r2r_edges_preview') or []
    links = full_preview.get('r2r_links_preview') or []
    degree = full_preview.get('r2r_degree_preview') or {}

    assert len(edges) == 1
    assert len(links) == 1
    assert links[0].get('hitl_preview') is True
    assert links[0].get('subnet') == '10.99.0.0/24'
    assert degree.get(200) == 1

    iface = hitl_cfg['interfaces'][0]
    preview_router = iface['preview_router']
    peer_id = iface.get('peer_router_node_id')
    assert isinstance(peer_id, int)
    assert preview_router['metadata'].get('hitl_peer_wired') is True
    assert preview_router['metadata'].get('peer_router_node_id') == peer_id
    assert preview_router.get('r2r_interfaces', {}).get(str(peer_id)) == '10.99.0.2/24'


def test_wire_hitl_preview_routers_is_idempotent_for_same_interface():
    full_preview = _base_preview()
    hitl_cfg = {
        'scenario_key': 'scenario-a',
        'interfaces': [
            {
                'name': 'eth0',
                'ordinal': 0,
                'interface_count': 1,
                'prefix_len': 24,
                'new_router_ip4': '10.99.0.2',
                'existing_router_ip4': '10.99.0.1',
                'link_network_cidr': '10.99.0.0/24',
                'preview_router': {
                    'node_id': 200,
                    'name': 'hitl-r200',
                    'metadata': {'hitl_preview': True, 'ordinal': 0, 'interface_count': 1},
                },
            }
        ],
    }

    backend._wire_hitl_preview_routers(full_preview, hitl_cfg)
    backend._wire_hitl_preview_routers(full_preview, hitl_cfg)

    assert len(full_preview.get('r2r_edges_preview') or []) == 1
    assert len(full_preview.get('r2r_links_preview') or []) == 1

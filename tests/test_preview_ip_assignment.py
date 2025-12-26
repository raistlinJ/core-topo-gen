from __future__ import annotations

import types
import ipaddress

from core_topo_gen.builders import topology as topo_mod
from tests.test_router_mesh import DummyClient, _patch_safe_create_session


class IfaceRecordingSession:
    def __init__(self) -> None:
        self.nodes: dict[int, object] = {}
        # store full link info so we can inspect iface IPs
        self.links: list[tuple[int, int, object | None, object | None]] = []
        self.services = types.SimpleNamespace(add=lambda *args, **kwargs: None)

    def add_node(self, node_id: int, _type=None, position=None, name=None):
        node = types.SimpleNamespace(id=node_id, name=name or f"n{node_id}", type=_type, position=position)
        self.nodes[node_id] = node
        return node

    def get_node(self, node_id: int):
        return self.nodes[node_id]

    def add_link(self, node1=None, node2=None, iface1=None, iface2=None, **kwargs):
        a = getattr(node1, "id", node1)
        b = getattr(node2, "id", node2)
        self.links.append((int(a), int(b), iface1, iface2))

    def add_service(self, node_id=None, service_name=None):
        return


def test_preview_router_switch_hosts_share_one_subnet_and_no_duplicate_ips(monkeypatch):
    session = IfaceRecordingSession()
    _patch_safe_create_session(monkeypatch, session)

    preview = {
        'routers': [{'node_id': 1, 'name': 'r1', 'ip4': '10.0.0.1/24'}],
        'hosts': [
            {'node_id': 2, 'name': 'h1', 'role': 'Workstation', 'ip4': '10.0.1.2/24'},
            {'node_id': 3, 'name': 'h2', 'role': 'Workstation', 'ip4': '10.0.1.3/24'},
        ],
        'host_router_map': {'2': 1, '3': 1},
        'switches_detail': [
            {
                'switch_id': 10,
                'router_id': 1,
                'hosts': [2, 3],
                # Intentionally mismatched; builder should force a single shared subnet (lan_subnet).
                'rsw_subnet': '10.10.0.0/24',
                'lan_subnet': '10.10.1.0/24',
                'router_ip': '10.10.0.1/24',
                'switch_ip': '10.10.0.2/24',
                'host_if_ips': {},
            },
        ],
        'r2r_edges_preview': [],
    }

    result = topo_mod._try_build_segmented_topology_from_preview(
        DummyClient(),
        services=None,
        routing_items=[],
        ip4_prefix='10.0.0.0/24',
        ip_mode='private',
        ip_region='all',
        layout_density='standard',
        preview_plan=preview,
    )
    assert result is not None

    # Collect all non-empty IPs on ifaces.
    ips: list[str] = []
    for _a, _b, if1, if2 in session.links:
        for iface in (if1, if2):
            ip = getattr(iface, 'ip4', None) if iface is not None else None
            if ip:
                ips.append(str(ip))

    # No duplicates.
    assert len(ips) == len(set(ips))

    # Router-switch iface and host ifaces should share the same subnet (lan_subnet).
    shared = ipaddress.ip_network('10.10.1.0/24')
    router_ips = []
    host_ips = []
    for a, b, if1, if2 in session.links:
        # host nodes are 2 and 3 and their IPs are on iface1
        if a in (2, 3) and if1 is not None and getattr(if1, 'ip4', None):
            host_ips.append(ipaddress.ip_address(str(if1.ip4)))
        # router node is 1 and its IP is on iface1 for router->switch link
        if a == 1 and if1 is not None and getattr(if1, 'ip4', None):
            router_ips.append(ipaddress.ip_address(str(if1.ip4)))

    assert router_ips, 'expected router interface ip on router->switch link'
    assert host_ips, 'expected host interface ips'
    assert all(ip in shared for ip in router_ips + host_ips)

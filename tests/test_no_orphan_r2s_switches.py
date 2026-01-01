import random, types
from core_topo_gen.builders import topology as topo_mod
from core_topo_gen.types import RoutingInfo

# Reuse lightweight fake session approach (subset) similar to other tests
class FakeNode:
    def __init__(self, node_id: int, name: str = ""):
        self.id = node_id
        self.name = name or f"n{node_id}"
        self.position = types.SimpleNamespace(x=0, y=0)
        self.services = []
        # model is set by builder; default empty
        self.model = ""

class FakeServices:
    def __init__(self):
        self._map = {}
    def add(self, node_id_or_obj, service_name):
        nid = getattr(node_id_or_obj, 'id', node_id_or_obj)
        self._map.setdefault(nid, set()).add(service_name)

class FakeSession:
    def __init__(self):
        self.nodes = {}
        self.links = []
        self.services = FakeServices()
    def add_node(self, node_id, _type=None, position=None, name=None):
        n = FakeNode(node_id, name or f"n{node_id}")
        self.nodes[node_id] = n
        return n
    def add_link(self, node1=None, node2=None, iface1=None, iface2=None):
        if not node1 or not node2:
            return
        a = getattr(node1, 'id', node1); b = getattr(node2, 'id', node2)
        if a == b:
            return
        key = tuple(sorted((a,b)))
        if key not in self.links:
            self.links.append(key)
    def add_service(self, node_id=None, service_name=None):
        if node_id is not None:
            self.services.add(node_id, service_name)
    def delete_link(self, node1_id=None, node2_id=None, iface1_id=None, iface2_id=None):
        key = tuple(sorted((node1_id, node2_id)))
        self.links = [lk for lk in self.links if lk != key]
    def delete_node(self, node_id):  # builder may call this
        self.nodes.pop(node_id, None)
        self.links = [lk for lk in self.links if node_id not in lk]

class DummyClient: pass


def _patch(monkeypatch, sess):
    monkeypatch.setattr(topo_mod, 'safe_create_session', lambda core: sess)


def test_no_empty_r2s_switches(monkeypatch):
    # Use Exact R2S with target large enough to trigger creation attempts
    ritems = [RoutingInfo(protocol='OSPFv2', factor=1.0, r2s_mode='Exact', r2s_edges=3)]
    role_counts = {'workstation': 18}  # plenty of hosts to distribute
    sess = FakeSession(); _patch(monkeypatch, sess)
    random.seed(2)
    _res = topo_mod.build_segmented_topology(DummyClient(), role_counts=role_counts, routing_density=0.5, routing_items=ritems, base_host_pool=sum(role_counts.values()), services=None)
    # Identify switches: model set to 'switch'
    switches = [nid for nid, node in sess.nodes.items() if getattr(node, 'model', '').lower() == 'switch']
    # A switch is empty if all its incident links connect only to routers/switches and no host models
    def is_router(nid):
        n = sess.nodes.get(nid); return 'router' in (getattr(n, 'model', '') or getattr(n,'name','')).lower()
    def is_host(nid):
        n = sess.nodes.get(nid); return getattr(n, 'model', '').lower() in ('pc','docker','host','default')
    empty_switches = []
    for sw in switches:
        incident = [lk for lk in sess.links if sw in lk]
        if not incident:
            empty_switches.append(sw); continue
        has_host = any(is_host(a if b==sw else b) for a,b in incident)
        only_r_or_sw = all((is_router(a if b==sw else b) or (getattr(sess.nodes.get(a if b==sw else b), 'model','').lower()=='switch')) for a,b in incident)
        if (not has_host) and only_r_or_sw:
            empty_switches.append(sw)
    assert not empty_switches, f"Orphan R2S switches still present: {empty_switches}"


def test_nonuniform_respects_host_bounds(monkeypatch):
    ritems = [RoutingInfo(protocol='OSPFv2', factor=0.0, abs_count=2, r2s_mode='NonUniform', r2s_edges=4, r2s_hosts_min=3, r2s_hosts_max=5)]
    role_counts = {'workstation': 24}
    sess = FakeSession(); _patch(monkeypatch, sess)
    random.seed(12345)
    topo_mod.build_segmented_topology(DummyClient(), role_counts=role_counts, routing_density=0.6, routing_items=ritems, base_host_pool=sum(role_counts.values()), services=None)

    host_models = {'pc', 'docker', 'host', 'default'}
    switch_host_counts = {}
    for nid, node in sess.nodes.items():
        name = getattr(node, 'name', '') or ''
        if not name.startswith('rsw-'):
            continue
        neighbors = [lk[0] if lk[1] == nid else lk[1] for lk in sess.links if nid in lk]
        hosts_attached = [sess.nodes.get(nb) for nb in neighbors if getattr(sess.nodes.get(nb), 'model', '').lower() in host_models]
        if hosts_attached:
            switch_host_counts[nid] = len(hosts_attached)

    assert switch_host_counts, "Expected at least one non-uniform R2S switch to be created"
    for count in switch_host_counts.values():
        assert 3 <= count <= 5, f"Switch host count {count} outside bounds"

    topo_stats = getattr(sess, 'topo_stats', {}) or {}
    policy = topo_stats.get('r2s_policy', {}) if isinstance(topo_stats, dict) else {}
    bounds = policy.get('host_group_bounds', {}) if isinstance(policy, dict) else {}
    if bounds:
        assert bounds.get('requested_min') == 3
        assert bounds.get('requested_max') == 5
        applied_min = bounds.get('applied_min')
        applied_max = bounds.get('applied_max')
        if applied_min is not None:
            assert applied_min >= 3
        if applied_max is not None:
            assert applied_max <= 5


def test_no_degree0_switch_when_link_noops(monkeypatch):
    # Simulate a CORE/session implementation where add_link() silently no-ops for switch-related links.
    # The builder should detect this (via session.links validation) and delete the created switch,
    # rather than leaving behind a degree-0 switch node.
    class NoopSwitchLinkSession(FakeSession):
        def add_link(self, node1=None, node2=None, iface1=None, iface2=None):
            if not node1 or not node2:
                return
            a_obj = node1 if hasattr(node1, 'id') else self.nodes.get(int(node1))
            b_obj = node2 if hasattr(node2, 'id') else self.nodes.get(int(node2))
            a_model = (getattr(a_obj, 'model', '') or '').lower() if a_obj is not None else ''
            b_model = (getattr(b_obj, 'model', '') or '').lower() if b_obj is not None else ''
            # Silent failure for any link involving a switch.
            if a_model == 'switch' or b_model == 'switch':
                return
            return super().add_link(node1=node1, node2=node2, iface1=iface1, iface2=iface2)

    ritems = [RoutingInfo(protocol='OSPFv2', factor=1.0, r2s_mode='Exact', r2s_edges=2)]
    role_counts = {'workstation': 12}
    sess = NoopSwitchLinkSession()
    _patch(monkeypatch, sess)
    random.seed(7)

    topo_mod.build_segmented_topology(
        DummyClient(),
        role_counts=role_counts,
        routing_density=0.5,
        routing_items=ritems,
        base_host_pool=sum(role_counts.values()),
        services=None,
    )

    # No switch nodes should remain if switch links cannot be created.
    switches = [nid for nid, node in sess.nodes.items() if getattr(node, 'model', '').lower() == 'switch']
    assert not switches, f"Switch nodes should not persist when switch links fail: {switches}"

    # Hosts should still have at least one link (direct to router), i.e., we didn't disconnect them.
    host_ids = [nid for nid, node in sess.nodes.items() if getattr(node, 'model', '').lower() in ('pc', 'docker', 'host', 'default')]
    assert host_ids, 'Expected hosts to be created'
    linked_host_ids = {nid for lk in sess.links for nid in lk if nid in host_ids}
    assert linked_host_ids == set(host_ids), f"Some hosts became disconnected: missing={sorted(set(host_ids) - linked_host_ids)}"


def test_preview_realization_skips_empty_switch_details(monkeypatch):
    # Preview payload with one empty switch detail (should be ignored) and one valid.
    preview_plan = {
        "routers": [{"node_id": 1, "name": "r1", "ip4": ""}],
        "hosts": [
            {"node_id": 2, "name": "h1", "role": "workstation", "ip4": ""},
            {"node_id": 3, "name": "h2", "role": "workstation", "ip4": ""},
        ],
        "host_router_map": {"2": 1, "3": 1},
        "switches_detail": [
            {
                "switch_id": 99,
                "router_id": 1,
                "hosts": [],
                "rsw_subnet": "10.55.1.0/24",
                "lan_subnet": "10.55.1.0/24",
                "router_ip": "10.55.1.1/24",
                "switch_ip": None,
                "host_if_ips": {},
            },
            {
                "switch_id": 100,
                "router_id": 1,
                "hosts": [2, 3],
                "rsw_subnet": "10.55.2.0/24",
                "lan_subnet": "10.55.2.0/24",
                "router_ip": "10.55.2.1/24",
                "switch_ip": None,
                "host_if_ips": {"2": "10.55.2.2/24", "3": "10.55.2.3/24"},
            },
        ],
    }

    sess = FakeSession()
    _patch(monkeypatch, sess)

    topo_mod.build_segmented_topology(
        DummyClient(),
        role_counts={"workstation": 2},
        routing_density=0.0,
        routing_items=[],
        base_host_pool=2,
        services=None,
        ip4_prefix="10.55.0.0/16",
        preview_plan=preview_plan,
    )

    assert 99 not in sess.nodes
    assert 100 in sess.nodes
    assert tuple(sorted((1, 99))) not in sess.links
    assert tuple(sorted((1, 100))) in sess.links

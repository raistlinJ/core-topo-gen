import sys, types, importlib

def _install_core_stubs():
    # Create package hierarchy core.api.grpc.wrappers
    if 'core' not in sys.modules:
        core_mod = types.ModuleType('core'); sys.modules['core'] = core_mod
    if 'core.api' not in sys.modules:
        api_mod = types.ModuleType('core.api'); sys.modules['core.api'] = api_mod
    if 'core.api.grpc' not in sys.modules:
        grpc_mod = types.ModuleType('core.api.grpc'); sys.modules['core.api.grpc'] = grpc_mod
    if 'core.api.grpc.wrappers' not in sys.modules:
        wrappers_mod = types.ModuleType('core.api.grpc.wrappers'); sys.modules['core.api.grpc.wrappers'] = wrappers_mod
        class NodeType:
            ROUTER='router'; SWITCH='switch'; DEFAULT='host'; HUB='hub'; EMANE='emane'
        class Position:
            def __init__(self, x=0, y=0): self.x=x; self.y=y
        class Interface:
            def __init__(self, id=0, name='', ip4='', ip4_mask=0, mac=''):
                self.id=id; self.name=name; self.ip4=ip4; self.ip4_mask=ip4_mask; self.mac=mac
        wrappers_mod.NodeType = NodeType
        wrappers_mod.Position = Position
        wrappers_mod.Interface = Interface
    if 'core.api.grpc.client' not in sys.modules:
        client_mod = types.ModuleType('core.api.grpc.client'); sys.modules['core.api.grpc.client'] = client_mod
        class CoreGrpcClient: pass
        client_mod.CoreGrpcClient = CoreGrpcClient

class DummyCore:
    def add_session(self):
        class S:
            def __init__(self):
                self.nodes={}; self.links=[]
            def add_node(self, nid, _type=None, position=None, name=None):
                n=types.SimpleNamespace(id=nid, name=name or f'n{nid}', services=[], position=position)
                self.nodes[nid]=n; return n
            def add_link(self, *args, **kwargs):
                if args and len(args)>=2:
                    a=args[0]; b=args[1]
                else:
                    a=kwargs.get('node1') or kwargs.get('node1_id')
                    b=kwargs.get('node2') or kwargs.get('node2_id')
                if hasattr(a,'id'): a=a.id
                if hasattr(b,'id'): b=b.id
                pair=tuple(sorted((a,b)))
                if pair not in self.links:
                    self.links.append(pair)
        return S()

def test_r2r_preview_injection_respected():
    _install_core_stubs()
    from core_topo_gen.builders import topology
    # Deterministic allocators
    topology.UniqueAllocator = lambda *a, **k: types.SimpleNamespace(next_mac=lambda: '00:00:00:00:00:00')  # type: ignore
    topology.make_subnet_allocator = lambda *a, **k: types.SimpleNamespace(next_random_subnet=lambda prefix: __import__('ipaddress').ip_network('10.10.%d.0/%d' % (prefix, prefix)))  # type: ignore
    role_counts={'Host':4}
    routing_density=1.0
    routing_items=[]
    base_host_pool=4
    full_preview={'routers':[{'node_id':1},{'node_id':2},{'node_id':3}], 'r2r_edges_preview':[(1,2),(2,3)]}
    approved_plan={'full_preview': full_preview}
    dummy_core=DummyCore()
    session, *_ = topology.build_segmented_topology(dummy_core, role_counts, routing_density, routing_items, base_host_pool, approved_plan=approved_plan)
    links=set(session.links)
    assert (1,2) in links and (2,3) in links
    assert (1,3) not in links, f"Unexpected enrichment edge present: {links}"

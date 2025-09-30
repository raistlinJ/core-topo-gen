"""Phased topology construction builder.

This module implements the phased approach (routers -> R2R -> hosts -> R2S -> services -> vulnerabilities)
consuming an AllocationPool. It is an opt-in path invoked when --approve-plan or --use-plan
is active. Initially mirrors logic from build_segmented_topology with decomposition.

NOTE: This is an initial scaffold; later phases (traffic, segmentation) will be integrated.
"""
from __future__ import annotations
from typing import Dict, List, Optional, Tuple, Any, Set
import ipaddress
import math
import random
import logging

from core.api.grpc import client
from core.api.grpc.wrappers import Position, Interface, NodeType

from core_topo_gen.types import ServiceInfo, RoutingInfo, NodeInfo
from core_topo_gen.utils.services import (
    set_node_services, ensure_service, has_service, remove_service,
)
from core_topo_gen.builders.topology import (
    UniqueAllocator, make_subnet_allocator, safe_create_session,
    mark_node_as_router, map_role_to_node_type, _type_desc, _router_node_type,
    _apply_docker_compose_meta, ROUTING_STACK_SERVICES, _make_safe_link_tracker,
)
from core_topo_gen.planning.pool import AllocationPool
from core_topo_gen.planning.constraints import validate_phase

logger = logging.getLogger(__name__)

# ---- Switch host grouping configuration (experimental) ----
SWITCH_HOSTS_MIN = 1        # allow a single host under a switch (avoids orphans)
SWITCH_HOSTS_MAX = 4        # cap to keep broadcast domains modest
SWITCH_HOST_SIZE_BIAS = 'small'  # 'small' favors smaller groups; 'uniform' equal probability

def _choose_switch_group_size(remaining: int, rnd: random.Random) -> int:
    lo = max(1, SWITCH_HOSTS_MIN)
    hi = min(SWITCH_HOSTS_MAX, remaining)
    if lo >= hi:
        return lo
    sizes = list(range(lo, hi + 1))
    if SWITCH_HOST_SIZE_BIAS == 'small':
        weights = [1.0 / (s ** 1.2) for s in sizes]
    else:
        weights = [1.0 for _ in sizes]
    total = sum(weights)
    pick = rnd.random() * total
    acc = 0.0
    for s, w in zip(sizes, weights):
        acc += w
        if pick <= acc:
            return s
    return sizes[0]

# ---------------- Phase Helpers ---------------- #

def _int_list_stats(values: List[int]):
    out = {"min": 0, "max": 0, "avg": 0.0, "std": 0.0, "gini": 0.0}
    if not values:
        return out
    import math as _math
    v = list(values)
    mn = min(v); mx = max(v); sm = sum(v); n = len(v)
    avg = sm / n if n else 0.0
    var = 0.0
    if n > 1:
        var = sum((x - avg) ** 2 for x in v) / (n - 1)
    std = _math.sqrt(var) if var > 0 else 0.0
    gini = 0.0
    if sm > 0 and n > 1:
        v_sorted = sorted(v)
        cum = 0
        for i, x in enumerate(v_sorted, start=1):
            cum += i * x
        gini = (2 * cum) / (n * sm) - (n + 1) / n
        if gini < 0:
            gini = 0.0
    out.update({"min": mn, "max": mx, "avg": round(avg, 4), "std": round(std, 4), "gini": round(gini, 4)})
    return out

# ---------------- Main Phased Builder ---------------- #

def build_segmented_topology_phased(
    core: client.CoreGrpcClient,
    pool: AllocationPool,
    routing_density: float,
    routing_items: List[RoutingInfo],
    services: Optional[List[ServiceInfo]] = None,
    ip4_prefix: str = "10.0.0.0/24",
    ip_mode: str = "private",
    ip_region: str = "all",
    layout_density: str = "normal",
    docker_slot_plan: Optional[Dict[str, Dict[str, str]]] = None,
    router_mesh_style: str = "full",
    r2s_ratio: Optional[float] = None,
) -> Tuple[Any, List[NodeInfo], List[NodeInfo], Dict[int, List[str]], Dict[str, Dict[str, str]]]:
    """Phased construction variant returning same tuple shape as legacy builder.

    Returns: session, routers, hosts, router_protocols, docker_by_name
    """
    logger.info("[phased] starting phased segmented topology build")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = make_subnet_allocator(ip_mode, ip4_prefix, ip_region)
    session = safe_create_session(core)
    existing_links, safe_add_link = _make_safe_link_tracker()

    total_hosts = pool.hosts_total
    router_count = pool.routers_planned
    if router_count <= 0 or total_hosts == 0:
        logger.info("[phased] No routers planned -> fallback to star not yet implemented in phased path (use legacy) ")
        raise RuntimeError("Phased builder currently expects at least one router; fallback earlier in CLI")

    # Layout parameters (reuse existing heuristic)
    if layout_density == "compact":
        cell_w, cell_h = 600, 450
        host_radius_mean = 140
        host_radius_jitter = 40
    elif layout_density == "spacious":
        cell_w, cell_h = 1000, 750
        host_radius_mean = 260
        host_radius_jitter = 80
    else:
        cell_w, cell_h = 900, 650
        host_radius_mean = 220
        host_radius_jitter = 60

    # Phase 1: Routers
    r_positions = _grid_positions(router_count, cell_w=cell_w, cell_h=cell_h, jitter=50)
    routers: List[NodeInfo] = []
    router_objs: List[Any] = []
    router_nodes: Dict[int, Any] = {}
    router_next_ifid: Dict[int, int] = {}
    router_iface_names: Dict[int, set[str]] = {}

    user_service_names: list[str] = []
    if services:
        seen_usvc = set()
        for svc in services:
            nm = getattr(svc, 'name', None) or getattr(svc, 'Name', None)
            if not nm:
                continue
            nm_str = str(nm).strip()
            if not nm_str or nm_str in ("IPForward", "zebra"):
                continue
            if nm_str not in seen_usvc:
                seen_usvc.add(nm_str)
                user_service_names.append(nm_str)

    for i in range(router_count):
        if not pool.consume_router():
            raise RuntimeError(f"Attempt to allocate router beyond plan index={i}")
        x, y = r_positions[i]
        node_id = i + 1
        rtype = _router_node_type()
        node = session.add_node(node_id, _type=rtype, position=Position(x=x, y=y), name=f"router-{i+1}")
        mark_node_as_router(node, session)
        router_iface_names[node.id] = set()
        merged_svc = ["IPForward", "zebra"] + user_service_names
        set_node_services(session, node.id, merged_svc, node_obj=node)
        routers.append(NodeInfo(node_id=node.id, ip4="", role="Router"))
        router_nodes[node.id] = node
        router_objs.append(node)
    topo_stats = {
        "routers_total_planned": router_count,
        "routers_allocated": pool.routers_allocated,
    }

    # Phase 2: R2R edges (support limited modes similar to legacy builder)
    existing_router_links: Set[Tuple[int, int]] = set()

    def add_router_link(a_obj, b_obj, prefix=30, label=""):
        key = (min(a_obj.id, b_obj.id), max(a_obj.id, b_obj.id))
        if key in existing_router_links:
            return False
        a_ifid = router_next_ifid.get(a_obj.id, 0)
        b_ifid = router_next_ifid.get(b_obj.id, 0)
        router_next_ifid[a_obj.id] = a_ifid + 1
        router_next_ifid[b_obj.id] = b_ifid + 1
        rr_net = subnet_alloc.next_random_subnet(prefix)
        rr_hosts = list(rr_net.hosts())
        if len(rr_hosts) < 2:
            return False
        a_ip = str(rr_hosts[0]); b_ip = str(rr_hosts[1])
        tag = label or "to"
        def _uniq(router_id: int, base: str) -> str:
            names = router_iface_names.setdefault(router_id, set())
            if base not in names:
                names.add(base)
                return base
            idx = 1
            while True:
                cand = f"{base}-{idx}"
                if cand not in names:
                    names.add(cand)
                    return cand
                idx += 1
        a_name = _uniq(a_obj.id, f"r{a_obj.id}-{tag}-r{b_obj.id}")
        b_name = _uniq(b_obj.id, f"r{b_obj.id}-{tag}-r{a_obj.id}")
        a_if = Interface(id=a_ifid, name=a_name, ip4=a_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
        b_if = Interface(id=b_ifid, name=b_name, ip4=b_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
        key_all = (min(a_obj.id, b_obj.id), max(a_obj.id, b_obj.id))
        if key_all not in existing_links:
            safe_add_link(session, a_obj, b_obj, iface1=a_if, iface2=b_if)
        existing_router_links.add(key)
        pool.r2r_edges_created += 1
        return True

    connectivity_mode = 'Random'
    target_degree: Optional[int] = None
    injected_r2r_edges: List[tuple[int, int]] = []
    if getattr(pool, 'full_preview', None):
        try:
            fp_edges = pool.full_preview.get('r2r_edges_preview') or []
            for edge in fp_edges:
                try:
                    a, b = edge
                except Exception:
                    continue
                if not (isinstance(a, int) and isinstance(b, int)):
                    continue
                if a == b:
                    continue
                a_obj = None; b_obj = None
                for r in router_objs:
                    if r.id == a: a_obj = r
                    elif r.id == b: b_obj = r
                if not a_obj or not b_obj:
                    continue
                if add_router_link(a_obj, b_obj, prefix=30, label="inj"):
                    injected_r2r_edges.append((a, b))
            if injected_r2r_edges:
                connectivity_mode = 'Injected'
                logger.info("[phased] injected %d R2R edges from full preview", len(injected_r2r_edges))
        except Exception as _inj_e:
            logger.warning("[phased] failed injecting preview R2R edges: %s", _inj_e)

    if connectivity_mode != 'Injected' and routing_items and router_count > 1:
        exact_values = [ri.r2r_edges for ri in routing_items if getattr(ri, 'r2r_mode', None) == 'Exact' and getattr(ri, 'r2r_edges', 0) > 0]
        modes_present = [ri.r2r_mode for ri in routing_items if getattr(ri, 'r2r_mode', None)]
        if exact_values:
            avg = sum(exact_values)/len(exact_values)
            target_degree = max(1, min(router_count - 1, int(round(avg))))
            connectivity_mode = 'Exact'
        elif 'Uniform' in modes_present:
            connectivity_mode = 'Uniform'
        elif 'Max' in modes_present:
            connectivity_mode = 'Max'
        elif 'Min' in modes_present:
            connectivity_mode = 'Min'
        elif 'NonUniform' in modes_present:
            connectivity_mode = 'NonUniform'
        else:
            connectivity_mode = 'Random'

    if router_count > 1 and connectivity_mode == 'Injected':
        pass  # edges already added deterministically
    elif router_count > 1:
        if connectivity_mode == 'Min':
            for i in range(router_count - 1):
                add_router_link(router_objs[i], router_objs[i+1], prefix=30, label="chain")
        elif connectivity_mode == 'Random':
            order = list(range(router_count))
            random.shuffle(order)
            in_tree = {order[0]}; remaining = set(order[1:])
            while remaining:
                a_idx = random.choice(list(in_tree))
                b_idx = random.choice(list(remaining))
                add_router_link(router_objs[a_idx], router_objs[b_idx], prefix=30, label="tree")
                in_tree.add(b_idx); remaining.remove(b_idx)
        elif connectivity_mode == 'Uniform':
            import math as _math
            if router_count == 2:
                add_router_link(router_objs[0], router_objs[1], prefix=30, label="u")
            else:
                td = min(router_count - 1, max(2, int(round(_math.log2(router_count))) + 1))
                td = min(td, max(2, (router_count // 2) + 1))
                target_degree = td
                for i in range(router_count):
                    add_router_link(router_objs[i], router_objs[(i+1) % router_count], prefix=30, label="u-ring")
                degrees_tmp: Dict[int, int] = {r.id: 0 for r in router_objs}
                for a_id, b_id in list(existing_router_links):
                    degrees_tmp[a_id] += 1; degrees_tmp[b_id] += 1
                attempts = 0
                max_attempts = router_count * router_count
                while attempts < max_attempts:
                    if all(d >= td for d in degrees_tmp.values()):
                        break
                    attempts += 1
                    low = sorted(degrees_tmp.items(), key=lambda kv: kv[1])
                    if not low:
                        break
                    a_id = low[0][0]
                    cand = [rid for rid, dval in low[1:] if dval < td and (min(rid, a_id), max(rid, a_id)) not in existing_router_links]
                    if not cand:
                        continue
                    b_id = random.choice(cand)
                    a_obj = router_nodes.get(a_id); b_obj = router_nodes.get(b_id)
                    if not a_obj or not b_obj:
                        continue
                    if add_router_link(a_obj, b_obj, prefix=30, label="u-bal"):
                        degrees_tmp[a_id] += 1; degrees_tmp[b_id] += 1
        elif connectivity_mode == 'NonUniform':
            order = list(range(router_count))
            random.shuffle(order)
            in_tree = {order[0]}; remaining = set(order[1:])
            while remaining:
                a_idx = random.choice(list(in_tree))
                b_idx = random.choice(list(remaining))
                add_router_link(router_objs[a_idx], router_objs[b_idx], prefix=30, label="base")
                in_tree.add(b_idx); remaining.remove(b_idx)
            degrees_tmp: Dict[int, int] = {r.id: 0 for r in router_objs}
            for a_id, b_id in existing_router_links:
                degrees_tmp[a_id] += 1; degrees_tmp[b_id] += 1
            max_possible = (router_count * (router_count - 1) // 2) - len(existing_router_links)
            extra_target = min(max_possible, max(0, random.randint(router_count//3, router_count)))
            attempts = 0; max_attempts = router_count * router_count
            router_id_list = [r.id for r in router_objs]
            while extra_target > 0 and attempts < max_attempts:
                attempts += 1
                sorted_ids = sorted(router_id_list, key=lambda rid: degrees_tmp[rid])
                low_candidates = sorted_ids[: max(1, min(3, len(sorted_ids)))]
                high_candidates = sorted_ids[-max(1, min(5, len(sorted_ids))):]
                a_id = random.choice(low_candidates); b_id = random.choice(high_candidates)
                if a_id == b_id:
                    continue
                a_obj = router_nodes.get(a_id); b_obj = router_nodes.get(b_id)
                if not a_obj or not b_obj:
                    continue
                if add_router_link(a_obj, b_obj, prefix=30, label="nu"):
                    degrees_tmp[a_id] += 1; degrees_tmp[b_id] += 1; extra_target -= 1
        elif connectivity_mode == 'Max':
            for i in range(router_count):
                for j in range(i+1, router_count):
                    add_router_link(router_objs[i], router_objs[j], prefix=30, label="mesh")
        elif connectivity_mode == 'Exact':
            # True k-regular attempt matching legacy builder fix (target_degree exact per router where feasible)
            def _build_regular_edges(n: int, k: int, max_tries: int = 2000) -> List[Tuple[int,int]]:
                if k < 0 or k >= n: return []
                if (n * k) % 2 != 0: return []
                if k == 0: return []
                import random as _r
                if k == 1:
                    idxs = list(range(n)); _r.shuffle(idxs); pairs=[]
                    while len(idxs) >= 2:
                        a=idxs.pop(); b=idxs.pop(); pairs.append((a,b))
                    return pairs
                for _ in range(max_tries):
                    stubs=[]
                    for i in range(n): stubs.extend([i]*k)
                    _r.shuffle(stubs)
                    edges:set[Tuple[int,int]] = set(); ok=True
                    while stubs:
                        if len(stubs) < 2: ok=False; break
                        a=stubs.pop(); b=stubs.pop()
                        if a==b: ok=False; break
                        e=(a,b) if a<b else (b,a)
                        if e in edges: ok=False; break
                        edges.add(e)
                    if ok:
                        degs={i:0 for i in range(n)}
                        for a,b in edges: degs[a]+=1; degs[b]+=1
                        if all(v==k for v in degs.values()): return list(edges)
                return []
            k = target_degree or 0
            if k <= 0:
                pass
            else:
                reg_edges = _build_regular_edges(router_count, k)
                construction_method = 'regular'
                if not reg_edges:
                    # Fallback chain + augment to reach at least k where possible
                    construction_method = 'fallback'
                    for i in range(router_count - 1):
                        add_router_link(router_objs[i], router_objs[i+1], prefix=30, label="chain")
                    if k > 1:
                        degrees_tmp: Dict[int, int] = {r.id: 0 for r in router_objs}
                        for a_id, b_id in existing_router_links:
                            degrees_tmp[a_id] += 1; degrees_tmp[b_id] += 1
                        attempts = 0; max_attempts = router_count * router_count
                        while attempts < max_attempts and min(degrees_tmp.values()) < k:
                            a_obj, b_obj = random.sample(router_objs, 2)
                            if a_obj.id == b_obj.id:
                                continue
                            if degrees_tmp[a_obj.id] >= k and degrees_tmp[b_obj.id] >= k:
                                attempts += 1; continue
                            if add_router_link(a_obj, b_obj, prefix=30, label="exactF"):
                                degrees_tmp[a_obj.id] += 1; degrees_tmp[b_obj.id] += 1
                            attempts += 1
                else:
                    for a_idx, b_idx in reg_edges:
                        add_router_link(router_objs[a_idx], router_objs[b_idx], prefix=30, label="exactR")
                try:
                    topo_stats.setdefault('router_edges_policy', {})
                    topo_stats['router_edges_policy']['construction_method'] = construction_method
                except Exception:
                    pass

    degrees = {r.id: 0 for r in router_objs}
    for a_id, b_id in existing_router_links:
        degrees[a_id] += 1; degrees[b_id] += 1
    ds = _int_list_stats(list(degrees.values()))
    topo_stats['router_edges_policy'] = {
        'mode': connectivity_mode,
        'target_degree': target_degree or 0,
        'degree_min': ds['min'], 'degree_max': ds['max'], 'degree_avg': ds['avg'], 'degree_std': ds['std'], 'degree_gini': ds['gini'],
        'construction_method': topo_stats.get('router_edges_policy', {}).get('construction_method') if topo_stats.get('router_edges_policy') else None
    }
    try:
        cm = topo_stats['router_edges_policy'].get('construction_method')
        if cm == 'fallback':
            topo_stats['router_edges_policy']['note'] = 'Fallback augmentation used; degrees may deviate within tolerance.'
        elif (target_degree or 0) == 1:
            topo_stats['router_edges_policy']['note'] = 'Perfect matching (degree=1) except possible single isolate if odd router count.'
    except Exception:
        pass
    try:
        if (target_degree or 0) == 1:
            topo_stats['router_edges_policy']['display_degree_min'] = 1 if ds['min'] in (0,1) else ds['min']
            topo_stats['router_edges_policy']['display_degree_max'] = 1 if ds['max'] in (0,1) else ds['max']
    except Exception:
        pass
    topo_stats['router_degrees'] = degrees

    # Phase 3: Hosts (bucket assignment round-robin by role like legacy)
    # Deterministic injection path: if a full preview with explicit hosts/switches/subnets
    # was attached to the pool, recreate those artifacts instead of randomized bucket logic.
    if getattr(pool, 'full_preview', None):
        try:
            fp = pool.full_preview
            fp_hosts = fp.get('hosts') or []
            fp_switches = fp.get('switches_detail') or []
            ptp_subnets = list(fp.get('ptp_subnets') or [])
            router_switch_subnets = {sd.get('rsw_subnet'): sd for sd in fp_switches if sd.get('rsw_subnet')}
            lan_subnet_map = {sd.get('lan_subnet'): sd for sd in fp_switches if sd.get('lan_subnet')}
            # Build quick host grouping lookup: host_id -> switch record
            host_to_switch = {}
            for sd in fp_switches:
                for h in sd.get('hosts', []):
                    host_to_switch[h] = sd
            # Create host nodes using preview ordering / ids
            hosts: List[NodeInfo] = []
            host_nodes_by_id: Dict[int, Any] = {}
            host_next_ifid: Dict[int, int] = {}
            # Determine non-switch hosts for ptp assignment
            nonswitch_hosts = [h for h in fp_hosts if h.get('node_id') not in host_to_switch]
            # Round-robin router assignment for nonswitch hosts (mirror preview logic)
            router_cycle = [r.id for r in router_objs]
            rc_len = len(router_cycle) or 1
            for idx, h in enumerate(fp_hosts):
                hid = int(h.get('node_id'))
                role = h.get('role') or 'Host'
                # Provide simple circular placement around first router to keep visual stable
                ridx = (hid - 1) % len(router_objs)
                rx, ry = r_positions[ridx]
                theta = (2 * math.pi * (idx + 1)) / max(2, len(fp_hosts))
                radius = 140 + (idx % 5) * 10
                x = int(rx + radius * math.cos(theta))
                y = int(ry + radius * math.sin(theta))
                node_type = map_role_to_node_type(role)
                name = h.get('name') or f"h{idx+1}-{role.lower()}"
                node = session.add_node(hid, _type=node_type, position=Position(x=x, y=y), name=name)
                host_nodes_by_id[node.id] = node
                host_next_ifid[node.id] = 1
                hosts.append(NodeInfo(node_id=node.id, ip4="", role=role))
            # PTP assign for nonswitch hosts
            ptp_iter = iter(ptp_subnets)
            for idx, h in enumerate(fp_hosts):
                hid = int(h.get('node_id'))
                if hid in host_to_switch:
                    continue
                router_id = router_cycle[idx % rc_len]
                r_obj = router_nodes.get(router_id)
                h_obj = host_nodes_by_id.get(hid)
                if not r_obj or not h_obj:
                    continue
                try:
                    sn_str = next(ptp_iter)
                    sn = ipaddress.ip_network(sn_str, strict=False)
                except Exception:
                    sn = subnet_alloc.next_random_subnet(30)
                hs = list(sn.hosts())
                if len(hs) < 2:
                    continue
                r_ip = str(hs[0]); h_ip = str(hs[1])
                r_ifid = router_next_ifid.get(router_id, 0); router_next_ifid[router_id] = r_ifid + 1
                h_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=sn.prefixlen, mac=mac_alloc.next_mac())
                r_if = Interface(id=r_ifid, name=f"r{router_id}-h{hid}", ip4=r_ip, ip4_mask=sn.prefixlen, mac=mac_alloc.next_mac())
                safe_add_link(session, h_obj, r_obj, iface1=h_if, iface2=r_if)
                # Record IP on hosts list entry
                for hn in hosts:
                    if hn.node_id == hid:
                        hn.ip4 = f"{h_ip}/{sn.prefixlen}"
                        break
            # Switch injection
            switch_count = 0
            for sd in fp_switches:
                try:
                    swid = int(sd.get('switch_id'))
                except Exception:
                    continue
                rid = sd.get('router_id')
                r_obj = router_nodes.get(rid)
                if not r_obj:
                    continue
                sw_name = f"{sd.get('name') or 'sw'}-{rid}-{switch_count+1}" if sd.get('name') else f"rsw-{rid}-{switch_count+1}"
                sw_node = session.add_node(swid, _type=NodeType.SWITCH, position=Position(x=0,y=0), name=sw_name)
                # Router-switch /30
                try:
                    rsn = ipaddress.ip_network(sd.get('rsw_subnet'), strict=False)
                except Exception:
                    rsn = subnet_alloc.next_random_subnet(30)
                rsh = list(rsn.hosts())
                if len(rsh) < 2:
                    continue
                r_ip = sd.get('router_ip') or str(rsh[0])
                sw_ip = sd.get('switch_ip') or str(rsh[1])
                r_ifid = router_next_ifid.get(rid, 0); router_next_ifid[rid] = r_ifid + 1
                sw_if = Interface(id=0, name=f"{sw_name}-r{rid}", ip4=sw_ip, ip4_mask=rsn.prefixlen, mac=mac_alloc.next_mac())
                r_if = Interface(id=r_ifid, name=f"r{rid}-{sw_name}", ip4=r_ip, ip4_mask=rsn.prefixlen, mac=mac_alloc.next_mac())
                safe_add_link(session, sw_node, r_obj, iface1=sw_if, iface2=r_if)
                # Host LAN /28
                try:
                    lan_net = ipaddress.ip_network(sd.get('lan_subnet'), strict=False)
                except Exception:
                    lan_net = subnet_alloc.next_random_subnet(28)
                lan_hosts = list(lan_net.hosts())
                sw_lan_ip = str(lan_hosts[0]) if lan_hosts else None
                h_if_ips = sd.get('host_if_ips') or {}
                h_pair = sd.get('hosts') or []
                for idx_h, hid in enumerate(h_pair):
                    h_obj = host_nodes_by_id.get(hid)
                    if not h_obj:
                        continue
                    hip_full = h_if_ips.get(hid) or (str(lan_hosts[idx_h+1]) + f"/{lan_net.prefixlen}" if len(lan_hosts) > idx_h+1 else None)
                    if not hip_full:
                        continue
                    hip, _, mask = hip_full.partition('/')
                    h_ifid = host_next_ifid.get(hid, 1)
                    host_next_ifid[hid] = h_ifid + 1
                    h_if = Interface(id=h_ifid, name=f"eth{h_ifid}", ip4=hip, ip4_mask=int(mask) if mask else lan_net.prefixlen, mac=mac_alloc.next_mac())
                    sw_if_h = Interface(id=idx_h+1, name=f"{sw_name}-h{hid}", ip4=sw_lan_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
                    safe_add_link(session, h_obj, sw_node, iface1=h_if, iface2=sw_if_h)
                    for hn in hosts:
                        if hn.node_id == hid:
                            hn.ip4 = hip_full
                            break
                switch_count += 1
            pool.hosts_allocated = len(hosts)
            pool.switches_allocated = switch_count
            topo_stats['switches_allocated'] = switch_count
            topo_stats['hosts_allocated'] = len(hosts)
            # Drift accounting vs preview
            try:
                preview_switch_ct = len(fp_switches)
                if switch_count != preview_switch_ct:
                    topo_stats.setdefault('preview_drift', []).append(f"switch_count preview={preview_switch_ct} actual={switch_count}")
                preview_host_ct = len(fp_hosts)
                if preview_host_ct != len(hosts):
                    topo_stats.setdefault('preview_drift', []).append(f"host_count preview={preview_host_ct} actual={len(hosts)}")
            except Exception:
                pass
            # Skip original random host creation path
            # Proceed directly to later phases (services, vulnerabilities)
        except Exception as _inj_e:
            logger.warning("[phased] full preview host/switch injection failed: %s -- falling back to randomized host build", _inj_e)
        else:
            # Jump to services/vulnerabilities phases using injected hosts
            pass
    else:
        # Original randomized host creation path
        expanded_roles: List[str] = []
        for role, count in pool.role_counts.items():
            expanded_roles.extend([role] * count)
        random.shuffle(expanded_roles)
        buckets: List[List[str]] = [[] for _ in range(router_count)]
        for idx, role in enumerate(expanded_roles):
            buckets[idx % router_count].append(role)

        hosts: List[NodeInfo] = []
        host_nodes_by_id: Dict[int, Any] = {}
        host_next_ifid: Dict[int, int] = {}
        node_id_counter = router_count + 1
        docker_by_name: Dict[str, Dict[str, str]] = {}
        created_docker = 0
        host_router_map: Dict[int, int] = {}
        host_direct_link: Dict[int, bool] = {}

        for ridx, roles in enumerate(buckets):
            rx, ry = r_positions[ridx]
            router_node = router_objs[ridx]
            if not roles:
                continue
            if len(roles) == 1:
                role = roles[0]
                theta = 0.0
                r = max(60, int(random.gauss(host_radius_mean, host_radius_jitter)))
                x = int(rx + r * math.cos(theta))
                y = int(ry + r * math.sin(theta))
                node_type = map_role_to_node_type(role)
                name = f"{role.lower()}-{ridx+1}-1"
                host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
                host_nodes_by_id[host.id] = host
                host_next_ifid[host.id] = 1
                lan_net = subnet_alloc.next_random_subnet(24)
                lan_hosts = list(lan_net.hosts())
                if len(lan_hosts) < 2:
                    continue
                r_ip = str(lan_hosts[0]); h_ip = str(lan_hosts[1])
                host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
                r_ifid = router_next_ifid.get(router_node.id, 0)
                router_next_ifid[router_node.id] = r_ifid + 1
                r_if = Interface(id=r_ifid, name=f"r{router_node.id}-h{host.id}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
                safe_add_link(session, host, router_node, iface1=host_if, iface2=r_if)
                hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
                node_id_counter += 1
                host_router_map[host.id] = router_node.id
                host_direct_link[host.id] = True
            else:
                for j, role in enumerate(roles):
                    theta = (2 * math.pi * j) / len(roles)
                    r = max(80, int(random.gauss(host_radius_mean + 10 * math.sqrt(len(roles)), host_radius_jitter)))
                    x = int(rx + r * math.cos(theta))
                    y = int(ry + r * math.sin(theta))
                    node_type = map_role_to_node_type(role)
                    name = f"{role.lower()}-{ridx+1}-{j+1}"
                    host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
                    host_nodes_by_id[host.id] = host
                    host_next_ifid[host.id] = 1
                    lan_net = subnet_alloc.next_random_subnet(30)
                    lan_hosts = list(lan_net.hosts())
                    if len(lan_hosts) < 2:
                        continue
                    r_ip = str(lan_hosts[0]); h_ip = str(lan_hosts[1])
                    host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
                    r_ifid = router_next_ifid.get(router_node.id, 0)
                    router_next_ifid[router_node.id] = r_ifid + 1
                    r_if = Interface(id=r_ifid, name=f"r{router_node.id}-h{host.id}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
                    safe_add_link(session, host, router_node, iface1=host_if, iface2=r_if)
                    hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
                    node_id_counter += 1
                    host_router_map[host.id] = router_node.id
                    host_direct_link[host.id] = True
        pool.hosts_allocated = len(hosts)

    # If we injected via full preview hosts variable will already exist; ensure it does.
    if 'hosts' not in locals():
        hosts = []
    expanded_roles: List[str] = []
    for role, count in pool.role_counts.items():
        expanded_roles.extend([role] * count)
    random.shuffle(expanded_roles)
    buckets: List[List[str]] = [[] for _ in range(router_count)]
    for idx, role in enumerate(expanded_roles):
        buckets[idx % router_count].append(role)

    hosts: List[NodeInfo] = []
    host_nodes_by_id: Dict[int, Any] = {}
    host_next_ifid: Dict[int, int] = {}
    node_id_counter = router_count + 1
    docker_by_name: Dict[str, Dict[str, str]] = {}
    created_docker = 0
    host_router_map: Dict[int, int] = {}
    host_direct_link: Dict[int, bool] = {}

    for ridx, roles in enumerate(buckets):
        rx, ry = r_positions[ridx]
        router_node = router_objs[ridx]
        if not roles:
            continue
        if len(roles) == 1:
            role = roles[0]
            theta = 0.0
            r = max(60, int(random.gauss(host_radius_mean, host_radius_jitter)))
            x = int(rx + r * math.cos(theta))
            y = int(ry + r * math.sin(theta))
            node_type = map_role_to_node_type(role)
            name = f"{role.lower()}-{ridx+1}-1"
            if node_type == NodeType.DEFAULT:
                # docker slot integration minimal placeholder
                pass
            host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
            host_nodes_by_id[host.id] = host
            host_next_ifid[host.id] = 1
            # allocate /24 lan
            lan_net = subnet_alloc.next_random_subnet(24)
            lan_hosts = list(lan_net.hosts())
            if len(lan_hosts) < 2:
                continue
            r_ip = str(lan_hosts[0]); h_ip = str(lan_hosts[1])
            host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
            r_ifid = router_next_ifid.get(router_node.id, 0)
            router_next_ifid[router_node.id] = r_ifid + 1
            r_if = Interface(id=r_ifid, name=f"r{router_node.id}-h{host.id}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
            safe_add_link(session, host, router_node, iface1=host_if, iface2=r_if)
            hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
            node_id_counter += 1
            host_router_map[host.id] = router_node.id
            host_direct_link[host.id] = True
        else:
            for j, role in enumerate(roles):
                theta = (2 * math.pi * j) / len(roles)
                r = max(80, int(random.gauss(host_radius_mean + 10 * math.sqrt(len(roles)), host_radius_jitter)))
                x = int(rx + r * math.cos(theta))
                y = int(ry + r * math.sin(theta))
                node_type = map_role_to_node_type(role)
                name = f"{role.lower()}-{ridx+1}-{j+1}"
                host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
                host_nodes_by_id[host.id] = host
                host_next_ifid[host.id] = 1
                # temporary direct link (/30) for deferred regrouping
                lan_net = subnet_alloc.next_random_subnet(30)
                lan_hosts = list(lan_net.hosts())
                if len(lan_hosts) < 2:
                    continue
                r_ip = str(lan_hosts[0]); h_ip = str(lan_hosts[1])
                host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
                r_ifid = router_next_ifid.get(router_node.id, 0)
                router_next_ifid[router_node.id] = r_ifid + 1
                r_if = Interface(id=r_ifid, name=f"r{router_node.id}-h{host.id}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
                safe_add_link(session, host, router_node, iface1=host_if, iface2=r_if)
                hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
                node_id_counter += 1
                host_router_map[host.id] = router_node.id
                host_direct_link[host.id] = True
    # pool.hosts_allocated already set in injected path or randomized path above

    # Phase 4: R2S regrouping (ratio-based). We pair hosts per router to form switches.
    if r2s_ratio is not None and router_count > 0:
        pool.r2s_ratio_used = r2s_ratio
        # Build per-router host lists
        hosts_by_router: Dict[int, List[int]] = {r.node_id: [] for r in routers}
        for h in hosts:
            # host names encode router index; use host_router_map already built
            # We didn't keep host_router_map external; derive by proximity: modulo bucket distribution
            # Re-derive bucket mapping
            pass  # minimal assumption: sequential assignment preserved; skip deriving for now
        # Simpler: reconstruct from naming pattern role-<router>-<idx>
        for h in hosts:
            try:
                nm = getattr(h, 'name', None) or ''
            except Exception:
                nm = ''
        # Instead, collect physical node objects for actual relink based on existing direct links to routers
        try:
            link_index: Dict[int, List[int]] = {r.node_id: [] for r in routers}  # router id -> host node ids
            for lk in list(getattr(session, 'links', []) or []):
                try:
                    n1 = getattr(lk, 'node1_id', None) or getattr(lk, 'node1', None)
                    n2 = getattr(lk, 'node2_id', None) or getattr(lk, 'node2', None)
                except Exception:
                    continue
                if n1 in router_nodes and n2 not in router_nodes:
                    link_index.setdefault(n1, []).append(n2)
                elif n2 in router_nodes and n1 not in router_nodes:
                    link_index.setdefault(n2, []).append(n1)
        except Exception:
            link_index = {}
        r2s_counts: Dict[int, int] = {r.node_id: 0 for r in routers}
        rehomed_hosts: List[int] = []
        node_id_counter_local = max([h.node_id for h in hosts] + [r.node_id for r in routers]) + 1
        for rid, host_ids in link_index.items():
            random.shuffle(host_ids)
            max_switches = min(int(r2s_ratio), max(1, len(host_ids)//max(1, SWITCH_HOSTS_MIN))) if r2s_ratio > 0 else 0
            seq = 0
            rnd_local = random.Random(5000 + rid)
            while max_switches > 0 and len(host_ids) >= SWITCH_HOSTS_MIN:
                group_size = _choose_switch_group_size(len(host_ids), rnd_local)
                if group_size > len(host_ids):
                    group_size = len(host_ids)
                selected_hosts = [host_ids.pop() for _ in range(group_size)]
                try:
                    sw_name = f"rsw-{rid}-{seq+1}"
                    sw_node = session.add_node(node_id_counter_local, _type=NodeType.SWITCH, position=Position(x=0,y=0), name=sw_name)
                except Exception:
                    break
                node_id_counter_local += 1; seq += 1
                seg_net = subnet_alloc.next_random_subnet(30)
                seg_hosts = list(seg_net.hosts())
                if len(seg_hosts) < 2:
                    continue
                r_ip = str(seg_hosts[0]); sw_ip = str(seg_hosts[1])
                r_ifid = router_next_ifid.get(rid, 0); router_next_ifid[rid] = r_ifid + 1
                r_if = Interface(id=r_ifid, name=f"r{rid}-rsw{seq}-if{r_ifid}", ip4=r_ip, ip4_mask=seg_net.prefixlen, mac=mac_alloc.next_mac())
                sw_if = Interface(id=0, name=f"rsw{seq}-r{rid}", ip4=sw_ip, ip4_mask=seg_net.prefixlen, mac=mac_alloc.next_mac())
                r_obj = router_nodes.get(rid)
                if r_obj:
                    safe_add_link(session, sw_node, r_obj, iface1=sw_if, iface2=r_if)
                # LAN size conditional: /30 for single-host else /28
                lan_net2 = subnet_alloc.next_random_subnet(30 if len(selected_hosts)==1 else 28)
                lan2_hosts = list(lan_net2.hosts())
                if len(lan2_hosts) < 2:
                    continue
                for idx_h, h_sel in enumerate(selected_hosts):
                    if idx_h + 1 >= len(lan2_hosts):
                        break
                    h_obj = session.get_node(h_sel) if hasattr(session, 'get_node') else None
                    if not h_obj:
                        continue
                    hip = str(lan2_hosts[idx_h+1])
                    h_if = Interface(id=1+idx_h, name=f"eth{1+idx_h}", ip4=hip, ip4_mask=lan_net2.prefixlen, mac=mac_alloc.next_mac())
                    sw_l_if = Interface(id=idx_h+1, name=f"rsw{seq}-h{h_sel}-if{idx_h+1}", ip4=str(lan2_hosts[0]), ip4_mask=lan_net2.prefixlen, mac=mac_alloc.next_mac())
                    safe_add_link(session, h_obj, sw_node, iface1=h_if, iface2=sw_l_if)
                r2s_counts[rid] += 1
                pool.switches_allocated += 1
                rehomed_hosts.extend(selected_hosts)
                max_switches -= 1
            # leftover hosts -> final switch
            if host_ids:
                selected_hosts = list(host_ids)
                host_ids.clear()
                try:
                    sw_name = f"rsw-{rid}-{seq+1}"
                    sw_node = session.add_node(node_id_counter_local, _type=NodeType.SWITCH, position=Position(x=0,y=0), name=sw_name)
                except Exception:
                    sw_node = None
                if sw_node:
                    node_id_counter_local += 1; seq += 1
                    seg_net = subnet_alloc.next_random_subnet(30)
                    seg_hosts = list(seg_net.hosts())
                    if len(seg_hosts) >= 2:
                        r_ip = str(seg_hosts[0]); sw_ip = str(seg_hosts[1])
                        r_ifid = router_next_ifid.get(rid, 0); router_next_ifid[rid] = r_ifid + 1
                        r_if = Interface(id=r_ifid, name=f"r{rid}-rsw{seq}-if{r_ifid}", ip4=r_ip, ip4_mask=seg_net.prefixlen, mac=mac_alloc.next_mac())
                        sw_if = Interface(id=0, name=f"rsw{seq}-r{rid}", ip4=sw_ip, ip4_mask=seg_net.prefixlen, mac=mac_alloc.next_mac())
                        r_obj = router_nodes.get(rid)
                        if r_obj:
                            safe_add_link(session, sw_node, r_obj, iface1=sw_if, iface2=r_if)
                        lan_net2 = subnet_alloc.next_random_subnet(30 if len(selected_hosts)==1 else 28)
                        lan2_hosts = list(lan_net2.hosts())
                        if len(lan2_hosts) >= 2:
                            for idx_h, h_sel in enumerate(selected_hosts):
                                if idx_h + 1 >= len(lan2_hosts):
                                    break
                                h_obj = session.get_node(h_sel) if hasattr(session, 'get_node') else None
                                if not h_obj:
                                    continue
                                hip = str(lan2_hosts[idx_h+1])
                                h_if = Interface(id=1+idx_h, name=f"eth{1+idx_h}", ip4=hip, ip4_mask=lan_net2.prefixlen, mac=mac_alloc.next_mac())
                                sw_l_if = Interface(id=idx_h+1, name=f"rsw{seq}-h{h_sel}-if{idx_h+1}", ip4=str(lan2_hosts[0]), ip4_mask=lan_net2.prefixlen, mac=mac_alloc.next_mac())
                                safe_add_link(session, h_obj, sw_node, iface1=h_if, iface2=sw_l_if)
                        r2s_counts[rid] += 1
                        pool.switches_allocated += 1
                        rehomed_hosts.extend(selected_hosts)
        try:
            rs_stats = _int_list_stats(list(r2s_counts.values())) if r2s_counts else {"min":0,"max":0,"avg":0.0,"std":0.0,"gini":0.0}
            # Transition r2s to degree-like semantics (Exact mode) mirroring r2r: target = switches per router
            topo_stats['r2s_policy'] = {
                'mode': 'Exact',
                'target_per_router': float(r2s_ratio),
                'target': float(r2s_ratio),  # backward compatibility
                'counts': r2s_counts,
                'count_min': rs_stats['min'], 'count_max': rs_stats['max'], 'count_avg': rs_stats['avg'], 'count_std': rs_stats['std'], 'count_gini': rs_stats['gini'],
                'rehomed_hosts': rehomed_hosts,
            }
            # Provide display normalization fields similar to r2r (for UI/report symmetry)
            if r2s_counts:
                topo_stats['r2s_policy']['display_min_count'] = rs_stats['min']
                topo_stats['r2s_policy']['display_max_count'] = rs_stats['max']
        except Exception:
            pass
    else:
        topo_stats['r2s_policy'] = { 'ratio': r2s_ratio or 0.0, 'mode': 'ratio', 'target': r2s_ratio or 0.0 }
    if r2s_ratio is not None:
        topo_stats['r2s_policy']['counts'] = {}  # counts populated after regroup in future iteration

    # Phase 5: Services (routing protocol assignment simplified)
    router_protocols: Dict[int, List[str]] = {r.node_id: [] for r in routers}
    if routing_items:
        # minimal replication: assign abs_count first
        remaining = [r.node_id for r in routers]
        random.shuffle(remaining)
        for ri in routing_items:
            if getattr(ri, 'abs_count', 0) > 0 and remaining:
                take = min(len(remaining), int(getattr(ri, 'abs_count', 0)))
                chosen = [remaining.pop(0) for _ in range(take)]
                for rid in chosen:
                    proto = ri.protocol
                    router_protocols[rid].append(proto)
        # weight-based allocation (optional) omitted for brevity in first pass
        for rid, protos in router_protocols.items():
            node_obj = router_nodes.get(rid)
            for proto in protos:
                if proto in ROUTING_STACK_SERVICES:
                    ensure_service(session, rid, proto, node_obj=node_obj)
    topo_stats['router_protocols'] = router_protocols

    # Phase 6: Vulnerabilities assignment (simple proportional distribution across hosts)
    if pool.vulnerabilities_plan and hosts:
        topo_stats['vulnerabilities_plan'] = pool.vulnerabilities_plan
        total_hosts_local = len(hosts)
        assigned = 0
        # deterministic order for reproducibility under seed
        host_ids_order = [h.node_id for h in hosts]
        random.shuffle(host_ids_order)
        cursor = 0
        for vuln_name, count in pool.vulnerabilities_plan.items():
            take = min(count, total_hosts_local - cursor)
            if take <= 0:
                break
            # pseudo-assignment: we just mark metadata; real service injection would go here
            assigned += take
            cursor += take
        pool.vulnerabilities_assigned = assigned
        topo_stats['vulnerabilities_assigned'] = assigned

    # Phase validations (soft collection only; not raising yet)
    try:
        for ph in ['routers','r2r','hosts','r2s','vulns']:
            issues = validate_phase({**topo_stats, **pool.summarize()}, ph)
            if issues:
                logger.info("[phased][validation] phase %s issues: %s", ph, "; ".join(issues))
    except Exception:
        pass

    # Segmentation preview rule attachment (no CORE rule application here, just propagate for report)
    try:
        if getattr(pool, 'full_preview', None):
            seg_prev = pool.full_preview.get('segmentation_preview') or {}
            if seg_prev.get('rules'):
                topo_stats['segmentation_preview_rules'] = seg_prev.get('rules')
                topo_stats['segmentation_preview_density'] = seg_prev.get('density')
    except Exception:
        pass

    setattr(session, 'topo_stats', topo_stats)

    # Drift snapshot vs full preview (if attached) – initial minimal metrics.
    try:
        if getattr(pool, 'full_preview', None):
            fp = pool.full_preview
            drift: dict[str, any] = {}
            try:
                drift['preview_router_count'] = len(fp.get('routers', []))
                drift['actual_router_count'] = topo_stats.get('routers_total_planned') or len(routers)
            except Exception:
                pass
            try:
                drift['preview_r2r_edges'] = len(fp.get('r2r_edges_preview') or [])
                # Approximate actual edges via pool counter if available
                drift['actual_r2r_edges'] = pool.r2r_edges_created
            except Exception:
                pass
            topo_stats['drift_preview'] = drift
    except Exception:
        pass

    return session, routers, hosts, router_protocols, docker_by_name

# Utilities copied (light) to avoid import cycles

def _grid_positions(count: int, cols: Optional[int] = None, cell_w: int = 800, cell_h: int = 600, jitter: int = 60):
    if count <= 0:
        return []
    if cols is None:
        cols = max(1, int(math.ceil(math.sqrt(count))))
    rows = int(math.ceil(count / cols))
    positions = []
    rng = random.Random()
    for i in range(count):
        r = i // cols
        c = i % cols
        x = c * cell_w + cell_w // 2 + rng.randint(-jitter, jitter)
        y = r * cell_h + cell_h // 2 + rng.randint(-jitter, jitter)
        positions.append((x, y))
    return positions

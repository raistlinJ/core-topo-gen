from __future__ import annotations
"""Full topology planning preview.

Generates a deterministic (seeded) plan including:
 - Router list with planned IDs, names, roles
 - Host list with planned IDs, names, roles
 - IP allocation preview (subnets + host / router interface IPs)
 - Planned router-to-router (R2R) connectivity policy summary (no edges yet)
 - Estimated router-to-switch (R2S) policy (ratio & placeholder counts)
 - Service assignment distribution preview (counts and deterministic slot order)
 - Vulnerability assignment preview (slot -> vuln mapping) if available
 - Segmentation rule plan preview (using segmentation density/items without applying to CORE)

No CORE gRPC calls are made; this is purely an algorithmic forecast so the user can
inspect and approve before any session creation.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any, Set
import ipaddress
import math
import random
from ..utils.allocators import make_subnet_allocator, UniqueAllocator


@dataclass
class PreviewNode:
    node_id: int
    name: str
    role: str
    kind: str  # router | host | switch
    ip4: str | None = None


def _stable_shuffle(seq: List[Any], seed: int) -> List[Any]:
    routing_items: List[Any] | None = None,
    rnd = random.Random(seed)
    out = list(seq)
    rnd.shuffle(out)
    return out


def _allocate_host_ips(total_hosts: int, base_prefix: str, seed: int) -> List[str]:
    # For preview, just linear assign /24 hosts ignoring collisions; build code does richer subnet mgmt
    net = ipaddress.ip_network(base_prefix, strict=False)
    ips = [str(h) for h in net.hosts()]
    return ips[: total_hosts]


def _role_expansion(role_counts: Dict[str, int]) -> List[str]:
    expanded: List[str] = []
    for r, c in role_counts.items():
        expanded.extend([r] * int(c))
    return expanded


def _estimate_r2s_ratio(hosts_total: int, routers_planned: int) -> float:
    if routers_planned <= 0:
        return 0.0
    # Heuristic: number of router-served switches ~ hosts/(routers*4) rounded up
    return max(0.0, round((hosts_total / max(routers_planned, 1)) / 4.0, 2))


def _preview_services(service_plan: Dict[str, int], host_ids: List[int], seed: int) -> Dict[int, List[str]]:
    # Distribute service counts deterministically via round-robin over shuffled host ids
    assignments: Dict[int, List[str]] = {h: [] for h in host_ids}
    cur_index = 0
    ordered_hosts = _stable_shuffle(host_ids, seed + 17)
    for svc, count in service_plan.items():
        for _ in range(int(count)):
            if not ordered_hosts:
                break
            hid = ordered_hosts[cur_index % len(ordered_hosts)]
            assignments[hid].append(svc)
            cur_index += 1
    # Drop empty lists
    return {k: v for k, v in assignments.items() if v}


def build_full_preview(
    role_counts: Dict[str, int],
    routers_planned: int,
    services_plan: Dict[str, int] | None = None,
    vulnerabilities_plan: Dict[str, int] | None = None,
    r2r_policy: Dict[str, Any] | None = None,
    r2s_policy: Dict[str, Any] | None = None,
    routing_items: List[Any] | None = None,
    routing_plan: Dict[str, int] | None = None,
    segmentation_density: float | None = None,
    segmentation_items: List[Dict[str, Any]] | None = None,
    seed: Optional[int] = None,
    ip4_prefix: str = "10.0.0.0/16",
    ip_mode: str = "private",
    ip_region: str = "all",
) -> Dict[str, Any]:
    services_plan = services_plan or {}
    vulnerabilities_plan = vulnerabilities_plan or {}
    routing_plan = routing_plan or {}
    segmentation_items = segmentation_items or []
    seed_generated = False
    if seed is None:
        # Use system randomness for preview generation; capture for deterministic rebuild later
        seed = random.randint(1, 2**31 - 1)
        seed_generated = True
    rnd_seed = seed
    random.seed(rnd_seed)

    total_hosts = sum(role_counts.values())
    role_expanded = _role_expansion(role_counts)
    # Assign IDs: routers 1..R, hosts R+1..R+H (switch IDs later after regrouping)
    router_nodes: List[PreviewNode] = []
    for i in range(routers_planned):
        router_nodes.append(PreviewNode(node_id=i + 1, name=f"r{i+1}", role="Router", kind="router"))
    host_nodes: List[PreviewNode] = []
    for idx, role in enumerate(role_expanded):
        host_nodes.append(PreviewNode(node_id=routers_planned + idx + 1, name=f"h{idx+1}-{role.lower()}", role=role, kind="host"))

    # Realistic subnet allocation preview mirroring builder strategy:
    # - /30 point-to-point subnets for initial host-router links
    # - later /30 router-switch and /28 host LANs when regrouping (r2s)
    subnet_alloc = make_subnet_allocator(ip_mode, ip4_prefix, ip_region)
    mac_alloc = UniqueAllocator(ip4_prefix)
    ptp_subnets: List[str] = []
    lan_subnets: List[str] = []
    router_switch_subnets: List[str] = []
    # Distribute hosts evenly to routers for initial direct links
    host_router_map: Dict[int, int] = {}
    r2s_unmet: Dict[int, int] = {}
    r2s_host_pairs_possible: Dict[int, int] = {}
    r2s_host_pairs_used: Dict[int, int] = {}
    if routers_planned > 0:
        r_cycle = [r.node_id for r in router_nodes]
        for idx, hn in enumerate(host_nodes):
            rid = r_cycle[idx % len(r_cycle)]
            host_router_map[hn.node_id] = rid
            # allocate /30 subnet
            try:
                lan_net = subnet_alloc.next_random_subnet(30)
            except Exception:
                # fallback /30 from ip4_prefix sequential
                net = ipaddress.ip_network("10.255.{}.0/30".format(idx % 255), strict=False)
                lan_net = net
            lan_hosts = list(lan_net.hosts())
            if len(lan_hosts) >= 2:
                r_ip = str(lan_hosts[0]); h_ip = str(lan_hosts[1])
                # assign addresses
                hn.ip4 = f"{h_ip}/{lan_net.prefixlen}"
                # store router placeholder ip only once (first host seen for that router)
                for r in router_nodes:
                    if r.node_id == rid and not r.ip4:
                        r.ip4 = f"{r_ip}/{lan_net.prefixlen}"
                        break
                ptp_subnets.append(str(lan_net))
    else:
        # No routers: simple linear assignment from base /24 style
        host_ips = _allocate_host_ips(total_hosts, ip4_prefix, rnd_seed)
        for i, hn in enumerate(host_nodes):
            if i < len(host_ips):
                hn.ip4 = f"{host_ips[i]}/24"

    # R2R policy preview: echo given or derive minimal
    r2r_preview = r2r_policy or {"mode": "Unknown", "target_degree": 0}
    if not r2r_policy and routers_planned > 0:
        # Simple inferred mode: chain vs mesh threshold
        if routers_planned <= 2:
            r2r_preview = {"mode": "Min", "target_degree": 1}
        elif routers_planned <= 4:
            r2r_preview = {"mode": "Uniform", "target_degree": 2}
        else:
            r2r_preview = {"mode": "NonUniform", "target_degree": min(routers_planned - 1, 4)}

    # R2S policy & regroup simulation (support Explicit/Exact modes)
    # If user supplied an r2s_policy (e.g., {'mode':'Exact','target_per_router':1}) honor it; else derive ratio heuristic.
    switch_nodes: List[PreviewNode] = []
    switches_detail: List[Dict[str, Any]] = []
    r2s_counts: Dict[int, int] = {r.node_id: 0 for r in router_nodes}
    computed_r2s_policy: Dict[str, Any]
    if routers_planned > 0:
        # If no explicit r2s_policy passed, attempt to derive from routing_items (e.g., list of RoutingInfo)
        if not r2s_policy and routing_items:
            try:
                # Find first item with r2s_mode attribute or dict key
                for it in routing_items:
                    try:
                        mode_val = getattr(it, 'r2s_mode', None)
                    except Exception:
                        mode_val = None
                    if not mode_val and isinstance(it, dict):
                        mode_val = it.get('r2s_mode') or it.get('r2sMode')
                    if mode_val:
                        edges_val = 0
                        try:
                            edges_val = int(getattr(it, 'r2s_edges', 0))
                        except Exception:
                            try:
                                if isinstance(it, dict):
                                    edges_val = int(it.get('r2s_edges') or it.get('r2sEdges') or 0)
                            except Exception:
                                edges_val = 0
                        mode_norm = str(mode_val).strip()
                        if mode_norm:
                            if mode_norm.lower() == 'exact' and edges_val > 0:
                                r2s_policy = {'mode': 'Exact', 'target_per_router': edges_val}
                            else:
                                r2s_policy = {'mode': mode_norm}
                            break
            except Exception:
                pass
        hosts_by_router: Dict[int, List[int]] = {r.node_id: [] for r in router_nodes}
        for h_id, rid in host_router_map.items():
            hosts_by_router.setdefault(rid, []).append(h_id)
        # Determine mode
        mode = (r2s_policy or {}).get('mode') if r2s_policy else None
        if not mode:
            # Fallback ratio heuristic
            r2s_ratio = _estimate_r2s_ratio(total_hosts, routers_planned)
            mode = 'ratio'
            target_per_router = r2s_ratio
        else:
            target_per_router = (r2s_policy or {}).get('target_per_router') or (r2s_policy or {}).get('target') or 0
        # Robust fallback: if mode Exact but target missing/zero, attempt derive from routing_items or default to 1
        derived_effective_target = None
        if str(mode).lower() == 'exact':
            try:
                tp_val = float(target_per_router)
            except Exception:
                tp_val = 0.0
            if tp_val <= 0:
                # Derive from routing_items if possible
                if routing_items:
                    for it in routing_items:
                        try:
                            ev = getattr(it, 'r2s_edges', None)
                        except Exception:
                            ev = None
                        if ev is None and isinstance(it, dict):
                            ev = it.get('r2s_edges') or it.get('r2sEdges')
                        try:
                            ev_int = int(ev)
                        except Exception:
                            ev_int = 0
                        if ev_int > 0:
                            target_per_router = ev_int
                            derived_effective_target = ev_int
                            break
                # If still zero and we have hosts at all, default to 1 (user intent ambiguous but wants switches)
                if (not derived_effective_target) and (sum(len(v) for v in hosts_by_router.values()) > 0):
                    target_per_router = 1
                    derived_effective_target = 1
        next_switch_id = routers_planned + len(host_nodes) + 1
        for rid, hlist in hosts_by_router.items():
            local = list(hlist)
            random.Random(rnd_seed + rid).shuffle(local)
            r2s_host_pairs_possible[rid] = len(local)//2
            max_sw = 0
            if mode == 'Exact':
                # Normalize target_per_router from any float/str
                try:
                    tgt = int(round(float(target_per_router)))
                except Exception:
                    tgt = 0
                if tgt == 1 and len(local) >= 1:
                    # Aggregated single-switch: all hosts for this router under one switch (no host pairing requirement)
                    max_sw = 1
                else:
                    max_sw = min(tgt, len(local)//2)
            elif mode == 'Min':
                max_sw = 1 if len(local) >= 2 else 0
            elif mode == 'Uniform':
                # Approximation: one switch per 4 hosts rounded up, but at least 1 if >=2 hosts
                import math as _math
                max_sw = min(len(local)//2, max(1 if len(local)>=2 else 0, int(_math.ceil(len(local)/4))))
            elif mode == 'NonUniform':
                import math as _math
                # Randomized but deterministic per rid using seed
                rnd_local = random.Random(rnd_seed + 900 + rid)
                max_sw = rnd_local.randint(0, max(0, int(_math.ceil(len(local)/3))))
            elif mode == 'Random':
                rnd_local = random.Random(rnd_seed + 901 + rid)
                max_sw = 1 if (len(local) >= 2 and rnd_local.random() < 0.5) else 0
            else:  # ratio
                r2s_ratio = _estimate_r2s_ratio(total_hosts, routers_planned)
                max_sw = min(int(r2s_ratio), len(local)//2)
                target_per_router = r2s_ratio
            seq = 0
            start_pairs = len(local)//2
            if mode == 'Exact' and max_sw == 1 and int(target_per_router)==1:
                # Build one aggregated switch connecting all hosts (>=1)
                # router-switch /30
                try:
                    rs_net = subnet_alloc.next_random_subnet(30)
                except Exception:
                    rs_net = ipaddress.ip_network(f"10.254.{rid}.{seq*4}/30", strict=False)
                router_switch_subnets.append(str(rs_net))
                rs_hosts = list(rs_net.hosts())
                r_ip = str(rs_hosts[0]) if rs_hosts else None
                sw_ip = str(rs_hosts[1]) if len(rs_hosts) > 1 else None
                # Pick LAN prefix large enough
                total_hosts_needed = len(local)
                import math as _math
                # Determine host bits so usable >= hosts_needed + 1 (gateway)
                for hb in range(2, 17):
                    usable = (2 ** hb) - 2
                    if usable >= total_hosts_needed + 1:
                        prefix = 32 - hb
                        break
                else:
                    prefix = 24
                try:
                    lan_net2 = subnet_alloc.next_random_subnet(prefix)
                except Exception:
                    lan_net2 = ipaddress.ip_network(f"10.253.{rid}.{seq*16}/{prefix}", strict=False)
                lan_subnets.append(str(lan_net2))
                lan_hosts2 = list(lan_net2.hosts())
                sw_name = f"rsw-{rid}-{seq+1}"
                switch_nodes.append(PreviewNode(node_id=next_switch_id, name=sw_name, role="Switch", kind="switch"))
                r2s_counts[rid] += 1
                host_if_ips: Dict[int, str] = {}
                # Assign each host sequentially
                for idx_h, h_sel in enumerate(list(local)):
                    if idx_h + 1 < len(lan_hosts2):
                        host_ip = str(lan_hosts2[idx_h + 1])
                        host_if_ips[h_sel] = host_ip + f"/{lan_net2.prefixlen}"
                        for hn in host_nodes:
                            if hn.node_id == h_sel:
                                hn.ip4 = host_if_ips[h_sel]
                                break
                switches_detail.append({
                    'switch_id': next_switch_id,
                    'router_id': rid,
                    'hosts': list(local),
                    'rsw_subnet': str(rs_net),
                    'lan_subnet': str(lan_net2),
                    'router_ip': r_ip,
                    'switch_ip': sw_ip,
                    'host_if_ips': host_if_ips,
                })
                next_switch_id += 1; seq += 1; max_sw = 0
                local.clear()
            while max_sw > 0 and len(local) >= 2:
                h_a = local.pop(); h_b = local.pop()
                # router-switch /30
                try:
                    rs_net = subnet_alloc.next_random_subnet(30)
                except Exception:
                    rs_net = ipaddress.ip_network(f"10.254.{rid}.{seq*4}/30", strict=False)
                router_switch_subnets.append(str(rs_net))
                rs_hosts = list(rs_net.hosts())
                r_ip = str(rs_hosts[0]) if rs_hosts else None
                sw_ip = str(rs_hosts[1]) if len(rs_hosts) > 1 else None
                # host LAN /28
                try:
                    lan_net2 = subnet_alloc.next_random_subnet(28)
                except Exception:
                    lan_net2 = ipaddress.ip_network(f"10.253.{rid}.{seq*16}/28", strict=False)
                lan_subnets.append(str(lan_net2))
                lan_hosts2 = list(lan_net2.hosts())
                sw_name = f"rsw-{rid}-{seq+1}"
                switch_nodes.append(PreviewNode(node_id=next_switch_id, name=sw_name, role="Switch", kind="switch"))
                r2s_counts[rid] += 1
                host_if_ips: Dict[int, str] = {}
                for idx_h, h_sel in enumerate([h_a, h_b]):
                    if idx_h + 1 < len(lan_hosts2):
                        host_ip = str(lan_hosts2[idx_h + 1])
                        host_if_ips[h_sel] = host_ip + f"/{lan_net2.prefixlen}"
                        for hn in host_nodes:
                            if hn.node_id == h_sel:
                                hn.ip4 = host_if_ips[h_sel]
                                break
                switches_detail.append({
                    'switch_id': next_switch_id,
                    'router_id': rid,
                    'hosts': [h_a, h_b],
                    'rsw_subnet': str(rs_net),
                    'lan_subnet': str(lan_net2),
                    'router_ip': r_ip,
                    'switch_ip': sw_ip,
                    'host_if_ips': host_if_ips,
                })
                next_switch_id += 1; seq += 1; max_sw -= 1
            used_pairs = start_pairs - (len(local)//2)
            r2s_host_pairs_used[rid] = used_pairs
            if mode == 'Exact':
                try:
                    unmet = max(0, int(target_per_router) - r2s_counts[rid])
                except Exception:
                    unmet = 0
                r2s_unmet[rid] = unmet
        # Build policy summary
        if mode == 'Exact':
            computed_r2s_policy = {'mode': 'Exact', 'target_per_router': target_per_router, 'counts': r2s_counts}
            if derived_effective_target is not None:
                computed_r2s_policy['target_per_router_effective'] = derived_effective_target
        else:
            # Provide ratio-like summary for other modes for UI consistency
            computed_r2s_policy = {'mode': mode, 'target_per_router': target_per_router, 'counts': r2s_counts}
    else:
        computed_r2s_policy = {'mode': 'None', 'target_per_router': 0, 'counts': {}}

    # Service assignment preview
    service_assignments = _preview_services(services_plan, [h.node_id for h in host_nodes], rnd_seed)

    # Vulnerability preview (deterministic round-robin of plan counts)
    vuln_assignments: Dict[int, List[str]] = {}
    if vulnerabilities_plan:
        ordered_hosts = _stable_shuffle([h.node_id for h in host_nodes], rnd_seed + 101)
        cursor = 0
        flat: List[str] = []
        for name, count in vulnerabilities_plan.items():
            for _ in range(int(count)):
                flat.append(name)
        for vname in flat:
            if not ordered_hosts:
                break
            hid = ordered_hosts[cursor % len(ordered_hosts)]
            vuln_assignments.setdefault(hid, []).append(vname)
            cursor += 1

    # Segmentation preview: expanded IP-centric rules (approximated) using host + router IPs
    seg_preview: Dict[str, Any] = {"density": segmentation_density or 0.0, "planned": [], "rules": []}
    if segmentation_density and segmentation_density > 0 and segmentation_items:
        # number of slots = density * hosts (round)
        slots = int(round((segmentation_density or 0.0) * max(total_hosts, 0)))
        items_weighted: List[Tuple[str, float]] = []
        for it in segmentation_items:
            sel = (it.get("selected") or it.get("name") or "").strip() or "Random"
            factor = float(it.get("factor") or 0.0)
            if sel.lower() == "random":
                # distribute weight across common types
                kinds = ["Firewall", "NAT", "CUSTOM"]
                for k in kinds:
                    items_weighted.append((k, factor / len(kinds) if factor > 0 else 0))
            else:
                items_weighted.append((sel, factor))
        if not items_weighted:
            items_weighted = [("Firewall", 1.0)]
        total_w = sum(w for _, w in items_weighted) or 1.0
        # Weighted pick deterministic
        rnd = random.Random(rnd_seed + 202)
        choices = []
        for _ in range(slots):
            r = rnd.random() * total_w
            acc = 0.0
            pick = items_weighted[-1][0]
            for name, w in items_weighted:
                acc += w
                if r <= acc:
                    pick = name; break
            choices.append(pick)
        seg_preview["planned"] = choices
        # Build simplistic rules: for NAT pick a router + host subnet; for Firewall choose host_block between two hosts; CUSTOM placeholder
        # Limit number of generated rules to slots count for readability
        ip_host_map = {h.node_id: h.ip4 for h in host_nodes if h.ip4}
        rnd = random.Random(rnd_seed + 303)
        for ct in choices:
            if ct == 'NAT' and router_nodes and ip_host_map:
                rid = rnd.choice([r.node_id for r in router_nodes])
                hid = rnd.choice(list(ip_host_map.keys()))
                try:
                    internal_cidr = str(ipaddress.ip_network(ip_host_map[hid], strict=False))
                except Exception:
                    internal_cidr = ip_host_map[hid].split('/')[0] + '/32'
                seg_preview['rules'].append({
                    'node_id': rid,
                    'rule': {
                        'type': 'nat', 'internal': internal_cidr, 'external': '0.0.0.0/0', 'mode': 'SNAT', 'egress_ip': router_nodes[0].ip4.split('/')[0] if router_nodes and router_nodes[0].ip4 else ''
                    }
                })
            elif ct == 'Firewall' and len(ip_host_map) >= 2:
                a, b = rnd.sample(list(ip_host_map.keys()), 2)
                seg_preview['rules'].append({
                    'node_id': a,
                    'rule': { 'type': 'host_block', 'src': ip_host_map[a].split('/')[0], 'dst': ip_host_map[b].split('/')[0] }
                })
            elif ct == 'CUSTOM':
                seg_preview['rules'].append({'node_id': 0, 'rule': {'type': 'custom', 'description': 'custom-seg-placeholder'}})

    # Router-to-router edge simulation (simple policy for preview)
    r2r_edges: List[Tuple[int, int]] = []
    if routers_planned > 1:
        mode = r2r_preview.get('mode')
        target_deg = r2r_preview.get('target_degree') or 0
        router_ids = [r.node_id for r in router_nodes]
        if mode == 'Min':  # chain
            for a, b in zip(router_ids, router_ids[1:]):
                r2r_edges.append((a, b))
        elif mode == 'Uniform' and target_deg >= 2:
            # ring then extra chords if needed
            for a, b in zip(router_ids, router_ids[1:]):
                r2r_edges.append((a, b))
            r2r_edges.append((router_ids[-1], router_ids[0]))
        else:
            # Generic: build only what's needed to satisfy target_deg (if >0) while ensuring connectivity.
            # Avoid accidental full mesh when target_deg == 0 (treat as minimal connectivity / spanning tree).
            adj: Dict[int, Set[int]] = {r: set() for r in router_ids}
            pairs = [(a,b) for i,a in enumerate(router_ids) for b in router_ids[i+1:]]
            rnd_edges = _stable_shuffle(pairs, rnd_seed+404)
            # Step 1: ensure connectivity via a simple random spanning tree if currently disconnected
            comp_parent = {r: r for r in router_ids}
            def _find(x):
                while comp_parent[x] != x:
                    comp_parent[x] = comp_parent[comp_parent[x]]; x = comp_parent[x]
                return x
            def _union(a,b):
                ra, rb = _find(a), _find(b)
                if ra != rb:
                    comp_parent[rb] = ra; return True
                return False
            for a,b in rnd_edges:
                if _union(a,b):
                    adj[a].add(b); adj[b].add(a); r2r_edges.append((a,b))
                # Early exit if tree completed
                roots = {_find(r) for r in router_ids}
                if len(roots) == 1 and len(r2r_edges) == len(router_ids)-1:
                    break
            # Step 2: if target_deg > current min degree, add edges to raise low-degree nodes without over-linking.
            if target_deg > 0:
                degs = {r: len(adj[r]) for r in router_ids}
                for a,b in rnd_edges:
                    if (a,b) in r2r_edges or (b,a) in r2r_edges:
                        continue
                    if all(d >= target_deg for d in degs.values()):
                        break
                    # consider only if one endpoint is still below target
                    if degs[a] < target_deg or degs[b] < target_deg:
                        if b not in adj[a]:
                            adj[a].add(b); adj[b].add(a); r2r_edges.append((a,b))
                            degs[a] += 1; degs[b] += 1
                            # No attempt to fill beyond degree target
                            continue
    # Degree stats
    r2r_degree: Dict[int,int] = {}
    for a,b in r2r_edges:
        r2r_degree[a] = r2r_degree.get(a,0)+1
        r2r_degree[b] = r2r_degree.get(b,0)+1
    def _stats(vals: List[int]):
        if not vals: return {}
        return {
            'min': min(vals), 'max': max(vals), 'avg': round(sum(vals)/len(vals),2)
        }
    r2r_stats = _stats(list(r2r_degree.values()))

    # Aggregate saturation stats
    total_pairs_possible = sum(r2s_host_pairs_possible.values()) or 0
    total_pairs_used = sum(r2s_host_pairs_used.values()) or 0
    saturation = 0.0
    if total_pairs_possible > 0:
        saturation = round(total_pairs_used / total_pairs_possible, 3)
    # Enrich policy with stats (without mutating earlier reference)
    try:
        computed_r2s_policy['host_pairs_possible_total'] = total_pairs_possible
        computed_r2s_policy['host_pairs_used_total'] = total_pairs_used
        computed_r2s_policy['host_pair_saturation'] = saturation
        if r2s_unmet:
            computed_r2s_policy['unmet_switch_targets'] = r2s_unmet
        if r2s_host_pairs_possible:
            computed_r2s_policy['host_pairs_possible'] = r2s_host_pairs_possible
        if r2s_host_pairs_used:
            computed_r2s_policy['host_pairs_used'] = r2s_host_pairs_used
    except Exception:
        pass

    return {
        "routers": [rn.__dict__ for rn in router_nodes],
        "hosts": [hn.__dict__ for hn in host_nodes],
        "switches": [sn.__dict__ for sn in switch_nodes],
        "switches_detail": switches_detail,
        "host_router_map": host_router_map,  # for visualization / deterministic host->router relation
        "services_preview": service_assignments,
        "vulnerabilities_preview": vuln_assignments,
        "r2r_policy_preview": r2r_preview,
        "r2r_edges_preview": r2r_edges,
        "r2r_degree_preview": r2r_degree,
        "r2r_stats_preview": r2r_stats,
        "r2s_policy_preview": computed_r2s_policy,
        "segmentation_preview": seg_preview,
        "ptp_subnets": ptp_subnets,
        "router_switch_subnets": router_switch_subnets,
        "lan_subnets": lan_subnets,
        "routing_plan": routing_plan,
        "services_plan": services_plan,
        "vulnerabilities_plan": vulnerabilities_plan,
        "role_counts": dict(role_counts),
        "seed": seed,
        "seed_generated": seed_generated,
    }

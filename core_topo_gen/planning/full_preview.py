from __future__ import annotations
"""Full topology planning preview (reconstructed after corruption).

This module provides a deterministic forecast of the planned topology including:
 - Routers / Hosts / (preview) Switches
 - Simple IP allocation preview
 - R2R policy & edge approximation
 - R2S policy (with Exact=1 aggregated semantics) + counts
 - Service & Vulnerability assignment previews
 - Segmentation density sampling

The implementation is intentionally simpler than the builder logic but keeps
the same public return contract relied upon by the web UI, CLI and tests.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Optional, Set
import ipaddress
import random
import os
import tempfile
from ..utils.allocators import UniqueAllocator, make_subnet_allocator  # runtime-like allocators
from .router_host_plan import plan_router_counts, plan_r2s_grouping  # reuse builder's router count & grouping logic
from .node_plan import _normalize_role_name  # internal normalization helper


@dataclass
class PreviewNode:
    node_id: int
    name: str
    role: str
    kind: str  # router | host | switch
    ip4: str | None = None


def _stable_shuffle(seq: List[Any], seed: int) -> List[Any]:
    rnd = random.Random(seed)
    out = list(seq)
    rnd.shuffle(out)
    return out


def _expand_roles(role_counts: Dict[str, int]) -> List[str]:
    out: List[str] = []
    for r, c in role_counts.items():
        out.extend([r] * int(c))
    return out


def _preview_services(service_plan: Dict[str, int], host_ids: List[int], seed: int) -> Dict[int, List[str]]:
    if not service_plan:
        return {}
    ordered = _stable_shuffle(list(host_ids), seed + 17)
    if not ordered:
        return {}
    assignments: Dict[int, List[str]] = {h: [] for h in ordered}
    idx = 0
    for svc, count in service_plan.items():
        for _ in range(int(count)):
            hid = ordered[idx % len(ordered)]
            assignments[hid].append(svc)
            idx += 1
    return {k: v for k, v in assignments.items() if v}


def _derive_r2s_policy_from_items(routing_items: Optional[List[Any]]) -> Optional[Dict[str, Any]]:
    if not routing_items:
        return None
    for it in routing_items:
        try:
            mode_val = getattr(it, 'r2s_mode', None)
        except Exception:
            mode_val = None
        if not mode_val and isinstance(it, dict):
            mode_val = it.get('r2s_mode') or it.get('r2sMode')
        if not mode_val:
            continue
        edges_val = 0
        try:
            edges_val = int(getattr(it, 'r2s_edges', 0))
        except Exception:
            if isinstance(it, dict):
                try:
                    edges_val = int(it.get('r2s_edges') or it.get('r2sEdges') or 0)
                except Exception:
                    edges_val = 0
        m = str(mode_val).strip()
        if not m:
            continue
        if m.lower() == 'exact' and edges_val > 0:
            return {'mode': 'Exact', 'target_per_router': edges_val}
        return {'mode': m}
    return None


def build_full_preview(
    role_counts: Dict[str, int],
    routers_planned: int,
    services_plan: Dict[str, int],
    vulnerabilities_plan: Dict[str, int],
    r2r_policy: Optional[Dict[str, Any]],
    r2s_policy: Optional[Dict[str, Any]],
    routing_items: Optional[List[Any]],
    routing_plan: Dict[str, Any],
    segmentation_density: Optional[float],
    segmentation_items: Optional[List[Dict[str, Any]]],
    traffic_plan: Optional[List[Dict[str, Any]]] = None,
    seed: Optional[int] = None,
    ip4_prefix: str = '10.0.0.0/16',
    ip_mode: str | None = None,
    ip_region: str | None = None,
    r2s_hosts_min_list: Optional[List[int]] = None,
    r2s_hosts_max_list: Optional[List[int]] = None,
):
    """Return a topology preview dictionary.

    Parameters mirror previous implementation (extra args accepted & ignored
    if not used for forward compatibility).
    """
    seed_generated = False
    if seed is None:
        seed = random.randint(1, 2**31 - 1)
        seed_generated = True
    rnd_seed = seed

    # ---- Validation: any remaining 'Random' placeholders indicate upstream resolution failed ----
    def _has_random_label() -> List[str]:
        offenders: List[str] = []
        # services
        if services_plan and any(k.strip().lower() == 'random' for k in services_plan.keys()):
            offenders.append('services_plan')
        # vulnerabilities
        if vulnerabilities_plan and any(k.strip().lower() == 'random' for k in vulnerabilities_plan.keys()):
            offenders.append('vulnerabilities_plan')
        # segmentation items
        if segmentation_items and any(((it.get('name') or it.get('selected') or '').strip().lower() == 'random') for it in segmentation_items):
            offenders.append('segmentation_items')
        # traffic
        if traffic_plan and any(((it.get('kind') or it.get('selected') or '').strip().lower() == 'random') for it in traffic_plan):
            offenders.append('traffic_plan')
        # routing items
        if routing_items and any(getattr(it, 'protocol', '').strip().lower() == 'random' for it in routing_items):
            offenders.append('routing_items')
        return offenders
    # Pre-resolve 'Random' segmentation placeholders into concrete kinds BEFORE validation
    # Segmentation random expansion: split total factor of all Random rows evenly across defaults
    default_seg_kinds = ['Firewall', 'NAT', 'CUSTOM']
    if segmentation_items:
        total_random_factor = 0.0
        concrete_items: List[Dict[str, Any]] = []
        for it in segmentation_items:
            name_l = str((it.get('name') or it.get('selected') or '')).strip().lower()
            try:
                fval = float(it.get('factor') or 0.0)
            except Exception:
                fval = 0.0
            if name_l == 'random':
                total_random_factor += fval
            else:
                concrete_items.append(it)
        if total_random_factor > 0 and default_seg_kinds:
            share = total_random_factor / len(default_seg_kinds)
            for k in default_seg_kinds:
                concrete_items.append({'selected': k, 'factor': share})
        segmentation_items = concrete_items

    random_offenders = _has_random_label()
    # After expansion, any remaining Random is an error (other sections must already resolve Random upstream)
    if random_offenders:
        raise ValueError(f"Unresolved 'Random' placeholders present in: {', '.join(random_offenders)}. They must be expanded before preview.")

    # ---- Routers (recomputed via shared planner if discrepancy) ----
    try:
        # Attempt to recompute router count for parity; fall back silently if inputs incomplete
        recompute_stats = plan_router_counts(role_counts, (r2r_policy or {}).get('density', 0.0) if False else 0.0, routing_items or [], sum(role_counts.values()), None)
        recomputed = recompute_stats.get('router_count')
        if isinstance(recomputed, int) and recomputed > 0 and recomputed != routers_planned:
            routers_planned = recomputed
            router_plan_stats = recompute_stats
        else:
            router_plan_stats = {'router_count_input': routers_planned}
    except Exception:
        router_plan_stats = {'router_count_input': routers_planned}
    router_nodes: List[PreviewNode] = []
    for i in range(routers_planned):
        router_nodes.append(PreviewNode(node_id=i + 1, name=f"r{i+1}", role="Router", kind="router"))

    # ---- Hosts ----
    total_hosts = sum(int(c) for c in role_counts.values())
    # Normalize role_counts in case caller bypassed compute_node_plan
    normalized_counts = {}
    for r, c in role_counts.items():
        nr = _normalize_role_name(r)
        normalized_counts[nr] = normalized_counts.get(nr, 0) + int(c)
    role_counts = normalized_counts
    role_expanded = _expand_roles(role_counts)
    host_nodes: List[PreviewNode] = []
    host_router_map: Dict[int, int] = {}
    if total_hosts:
        # Deterministic distribution: round-robin, stable order (roles already normalized by node_plan)
        for idx, role in enumerate(role_expanded):
            host_id = routers_planned + idx + 1  # host IDs start after routers
            if routers_planned > 0:
                rid = (idx % routers_planned) + 1
            else:
                rid = 0
            host_router_map[host_id] = rid
            host_nodes.append(PreviewNode(node_id=host_id, name=f"h{idx+1}", role=role, kind="host"))

    # ---- Runtime-like IP assignment (using allocators similar to topology.py) ----
    # We mimic the builder behavior more closely by using UniqueAllocator which rolls to the next
    # contiguous block when exhausted. Subnet allocation (make_subnet_allocator) is reserved for
    # switch / LAN preview later; here we focus on per-node primary IPs.
    ip_alloc_mode = 'runtime_like'
    try:
        uniq_alloc = UniqueAllocator(ip4_prefix)
    except Exception:
        # Fallback to legacy simple list approach if allocator fails
        uniq_alloc = None
    if uniq_alloc:
        # Assign router primary IPs only (hosts will be assigned from LAN subnets after grouping)
        for rn in router_nodes:
            try:
                ip, mask = uniq_alloc.next_ip()
                rn.ip4 = f"{ip}/{mask}"
            except Exception:
                break
    else:
        try:
            net = ipaddress.ip_network(ip4_prefix, strict=False)
            all_ips = [str(h) for h in net.hosts()]
        except Exception:
            all_ips = []
        ip_iter = iter(all_ips)
        for rn in router_nodes:
            try:
                rn.ip4 = next(ip_iter) + "/24"
            except StopIteration:
                break
        for hn in host_nodes:
            try:
                hn.ip4 = next(ip_iter) + "/24"
            except StopIteration:
                break

    # ---- R2R Policy Preview ----
    if r2r_policy:
        r2r_preview = dict(r2r_policy)
    else:
        if routers_planned <= 1:
            r2r_preview = {"mode": "None", "target_degree": 0}
        elif routers_planned <= 2:
            r2r_preview = {"mode": "Min", "target_degree": 1}
        elif routers_planned <= 4:
            r2r_preview = {"mode": "Uniform", "target_degree": 2}
        else:
            r2r_preview = {"mode": "NonUniform", "target_degree": min(routers_planned - 1, 4)}

    # Build simple R2R edges (chain / ring / partial) for preview
    r2r_edges: List[Tuple[int, int]] = []
    if routers_planned > 1:
        mode_rr = r2r_preview.get('mode')
        ids = [r.node_id for r in router_nodes]
        if mode_rr == 'Min':
            for a, b in zip(ids, ids[1:]):
                r2r_edges.append((a, b))
        elif mode_rr == 'Uniform':
            for a, b in zip(ids, ids[1:]):
                r2r_edges.append((a, b))
            if len(ids) > 2:
                r2r_edges.append((ids[-1], ids[0]))
        else:  # NonUniform/Other -> minimal spanning chain
            for a, b in zip(ids, ids[1:]):
                r2r_edges.append((a, b))
    r2r_degree: Dict[int, int] = {}
    for a, b in r2r_edges:
        r2r_degree[a] = r2r_degree.get(a, 0) + 1
        r2r_degree[b] = r2r_degree.get(b, 0) + 1
    if r2r_degree:
        vals = list(r2r_degree.values())
        r2r_stats = {'min': min(vals), 'max': max(vals), 'avg': round(sum(vals) / len(vals), 2)}
    else:
        r2r_stats = {}

    # ---- Helper: assign routing items to routers to derive per-router bounds ----
    def _assign_items_to_routers(items: Optional[List[Any]], count: int) -> List[Optional[Any]]:
        if not items or count <= 0:
            return [None] * count
        expanded: List[Any] = []
        # First expand items with abs_count if present
        for it in items:
            abs_c = int(getattr(it, 'abs_count', 0) or (it.get('abs_count') if isinstance(it, dict) else 0) or 0)
            if abs_c > 0:
                expanded.extend([it] * abs_c)
        # If still short, append remaining items (weight / factor based) round-robin
        if len(expanded) < count:
            idx = 0
            while len(expanded) < count:
                expanded.append(items[idx % len(items)])
                idx += 1
        return expanded[:count]

    item_assignment = _assign_items_to_routers(routing_items, routers_planned)

    # ---- R2S Policy (focus on Exact=1 semantics used in tests, extended with grouping preview) ----
    if not r2s_policy:
        r2s_policy = _derive_r2s_policy_from_items(routing_items)
    mode_rs = (r2s_policy or {}).get('mode') if r2s_policy else None
    target_per_router = (r2s_policy or {}).get('target_per_router') if r2s_policy else None
    if not mode_rs:
        mode_rs = 'ratio'
    switch_nodes: List[PreviewNode] = []
    switches_detail: List[Dict[str, Any]] = []
    router_switch_subnets: List[str] = []
    lan_subnets: List[str] = []
    ptp_subnets: List[str] = []  # keep key for backward compatibility

    # Host grouping per router (deterministic): collect hosts by rid
    hosts_by_router: Dict[int, List[int]] = {r.node_id: [] for r in router_nodes}
    for hid, rid in host_router_map.items():
        if rid in hosts_by_router:
            hosts_by_router[rid].append(hid)

    next_switch_id = routers_planned + total_hosts + 1
    derived_effective_target = None
    if str(mode_rs).lower() == 'exact':
        try:
            if target_per_router is None:
                raise ValueError
            _ = float(target_per_router)
        except Exception:
            # attempt derive edges from first routing item
            for it in (routing_items or []):
                ev = getattr(it, 'r2s_edges', None) if not isinstance(it, dict) else it.get('r2s_edges') or it.get('r2sEdges')
                try:
                    ev_int = int(ev)
                except Exception:
                    ev_int = 0
                if ev_int > 0:
                    target_per_router = ev_int
                    derived_effective_target = ev_int
                    break
            if target_per_router is None:
                target_per_router = 1
                derived_effective_target = 1

    grouping_out = plan_r2s_grouping(routers_planned, host_router_map, host_nodes, routing_items, r2s_policy, rnd_seed, ip4_prefix=ip4_prefix, ip_mode=ip_mode, ip_region=ip_region)
    grouping_preview = grouping_out['grouping_preview']
    computed_r2s_policy = grouping_out['computed_r2s_policy']
    # adopt switch + subnet previews
    switches_detail = grouping_out['switches_detail']
    router_switch_subnets = grouping_out['router_switch_subnets']
    lan_subnets = grouping_out['lan_subnets']
    ptp_subnets = grouping_out['ptp_subnets']
    r2r_subnets = grouping_out.get('r2r_subnets', [])
    # convert generic switch nodes to PreviewNodes
    switch_nodes = [PreviewNode(node_id=sn['node_id'], name=sn.get('name', f"sw-{sn['node_id']}"), role="Switch", kind="switch") for sn in grouping_out['switch_nodes']]

    # Override host IPs using LAN subnets for realistic per-LAN addressing
    try:
        host_map = {h.node_id: h for h in host_nodes}
        router_map = {r.node_id: r for r in router_nodes}
        for swd in switches_detail:
            lan_sub = swd.get('lan_subnet')
            hosts_ids = swd.get('hosts') or []
            if not lan_sub or not hosts_ids:
                continue
            try:
                lan_net = ipaddress.ip_network(lan_sub, strict=False)
                lan_hosts = list(lan_net.hosts())
            except Exception:
                continue
            # Reserve first host address (index 0) for switch/gateway; assign from index 1 upward
            for idx_h, hid in enumerate(sorted(hosts_ids)):
                if idx_h + 1 < len(lan_hosts):
                    ip_addr = lan_hosts[idx_h + 1]
                    h = host_map.get(hid)
                    if h:
                        h.ip4 = f"{ip_addr}/{lan_net.prefixlen}"
                    # Also record into switches_detail host_if_ips for completeness
                    swd.setdefault('host_if_ips', {})[hid] = f"{ip_addr}/{lan_net.prefixlen}"
            # Apply router/switch link IPs if provided
            r_ip = swd.get('router_ip'); s_ip = swd.get('switch_ip')
            try:
                if r_ip:
                    rid = int(swd.get('router_id'))
                    rnode = router_map.get(rid)
                    if rnode and (not rnode.ip4 or rnode.ip4.split('/')[0].startswith('10.')):
                        rnode.ip4 = r_ip
            except Exception:
                pass
        ip_alloc_mode = 'lan_subnet'
    except Exception:
        pass

    # Host group bounds summary from routing_items
    try:
        mins: List[int] = []
        maxs: List[int] = []
        for it in (routing_items or []):
            mi = getattr(it, 'r2s_hosts_min', None) if not isinstance(it, dict) else it.get('r2s_hosts_min')
            ma = getattr(it, 'r2s_hosts_max', None) if not isinstance(it, dict) else it.get('r2s_hosts_max')
            if isinstance(mi, int) and mi > 0:
                mins.append(mi)
            if isinstance(ma, int) and ma > 0:
                maxs.append(ma)
        if mins or maxs:
            computed_r2s_policy['host_group_bounds'] = {
                'effective_min': min(mins) if mins else None,
                'effective_max': max(maxs) if maxs else None,
            }
    except Exception:
        pass

    # Add saturation stats similar to previous contract
    # (All pairs statistics already embedded by helper)

    # ---- Services & Vulnerabilities ----
    service_assignments = _preview_services(services_plan, [h.node_id for h in host_nodes], rnd_seed)
    vuln_assignments: Dict[int, List[str]] = {}
    if vulnerabilities_plan:
        ordered = _stable_shuffle([h.node_id for h in host_nodes], rnd_seed + 101)
        flat: List[str] = []
        for name, count in vulnerabilities_plan.items():
            for _ in range(int(count)):
                flat.append(name)
        for idx, vname in enumerate(flat):
            if not ordered:
                break
            hid = ordered[idx % len(ordered)]
            vuln_assignments.setdefault(hid, []).append(vname)

    # ---- Traffic Materialization (resolve abstract items to concrete flows) ----
    traffic_summary: Dict[str, Any] = {}
    if traffic_plan:
        try:
            rnd = random.Random(rnd_seed + 703)
            host_ids = [h.node_id for h in host_nodes]
            flows: List[Dict[str, Any]] = []
            if host_ids:
                for item in traffic_plan:
                    factor = float(item.get('factor', 0) or 0)
                    abs_count = int(item.get('abs_count') or 0)
                    pattern = item.get('pattern') or 'continuous'
                    rate = item.get('rate_kbps') or item.get('rate') or 0
                    # derive target flows
                    if abs_count > 0:
                        flows_needed = abs_count
                    else:
                        flows_needed = int(round(factor * len(host_ids))) if factor > 0 else 0
                        if factor > 0 and flows_needed == 0:
                            flows_needed = 1
                    flows_needed = min(flows_needed, max(1, len(host_ids) * 2))
                    for _ in range(flows_needed):
                        if len(host_ids) == 1:
                            src = dst = host_ids[0]
                        else:
                            src = rnd.choice(host_ids)
                            dst = rnd.choice(host_ids)
                            if src == dst and len(host_ids) > 1:
                                for _attempt in range(3):
                                    dst = rnd.choice(host_ids)
                                    if dst != src:
                                        break
                        flows.append({'src_id': src, 'dst_id': dst, 'pattern': pattern, 'rate_kbps': rate})
            traffic_summary = {'flows': flows, 'count': len(flows)}
        except Exception as _e:
            traffic_summary = {'error': str(_e)}

    # ---- Segmentation Preview (lightweight) ----
    seg_preview: Dict[str, Any] = {"density": segmentation_density or 0.0, "planned": [], "rules": [], 'source': 'runtime_planner'}
    segmentation_rules_preview: List[Dict[str, Any]] = []
    deep_segmentation_error: Optional[str] = None
    if segmentation_density and segmentation_density > 0 and segmentation_items:
        try:
            # Convert raw segmentation items into SegmentationInfo objects (they should already be Random-resolved upstream)
            from ..types import SegmentationInfo, NodeInfo as _NI  # type: ignore
            seg_objs: List[SegmentationInfo] = []
            for it in segmentation_items:
                name = (it.get('name') or it.get('selected') or '').strip()
                factor = float(it.get('factor') or 0.0)
                abs_c = int(it.get('abs_count') or 0)
                if name:
                    seg_objs.append(SegmentationInfo(name=name, factor=factor, abs_count=abs_c))

            # Build stub session & nodes compatible with segmentation planner
            class _StubServices:
                def __init__(self):
                    self._map: Dict[int, List[str]] = {}
                def add(self, node_id, service_name):
                    self._map.setdefault(getattr(node_id, 'id', node_id), []).append(service_name)
                def get(self, node_id):
                    nid = getattr(node_id, 'id', node_id)
                    return list(self._map.get(nid, []))

            class _StubNode:
                def __init__(self, node_id: int, name: str, ip4: str, role: str):
                    self.id = node_id
                    self.name = name
                    self.ip4 = ip4
                    self.role = role
                    self.services: List[str] = []
            class _StubSession:
                def __init__(self):
                    self.services = _StubServices()
                    self.nodes: Dict[int, _StubNode] = {}
                def get_node(self, nid):
                    return self.nodes.get(nid)
            stub_session = _StubSession()
            # Populate stub nodes (routers + hosts)
            for r in router_nodes:
                stub_session.nodes[r.node_id] = _StubNode(r.node_id, r.name, r.ip4 or '', r.role)
            for h in host_nodes:
                stub_session.nodes[h.node_id] = _StubNode(h.node_id, h.name, h.ip4 or '', h.role)

            # Prepare NodeInfo lists for planner
            router_infos = [_NI(node_id=r.node_id, ip4=r.ip4 or '', role=r.role) for r in router_nodes]
            host_infos = [_NI(node_id=h.node_id, ip4=h.ip4 or '', role=h.role) for h in host_nodes]

            # Invoke real segmentation planner (dry-run style) writing into temp dir
            from ..utils.segmentation import plan_and_apply_segmentation  # type: ignore
            seg_tmp = os.path.join(tempfile.gettempdir(), f"core-topo-preview-seg-{seed}")
            summary = plan_and_apply_segmentation(
                stub_session,
                routers=router_infos,
                hosts=host_infos,
                density=float(segmentation_density or 0.0),
                items=seg_objs,
                nat_mode='SNAT',
                out_dir=seg_tmp,
                include_hosts=False,
            )
            # Extract rules
            for rr in summary.get('rules', []):
                try:
                    segmentation_rules_preview.append({
                        'node_id': rr.get('node_id'),
                        'rule': rr.get('rule'),
                        'script': rr.get('script'),
                    })
                except Exception:
                    continue
            # For preview display, synthesize 'planned' list by type of each rule
            seg_preview['planned'] = [ (r.get('rule') or {}).get('type','') for r in summary.get('rules', []) ]
            seg_preview['rules'] = segmentation_rules_preview
            seg_preview['out_dir'] = seg_tmp
            seg_preview['planned_slots'] = len(segmentation_rules_preview)
            seg_preview['note'] = 'Segmentation preview produced by runtime planner logic.'
            # Collect artifact file metadata for preview (without moving to /tmp/segmentation runtime dir)
            artifacts: List[Dict[str, Any]] = []
            try:
                for fname in sorted(os.listdir(seg_tmp)):
                    fpath = os.path.join(seg_tmp, fname)
                    if not os.path.isfile(fpath):
                        continue
                    size = 0
                    try:
                        size = os.path.getsize(fpath)
                    except Exception:
                        pass
                    snippet = ''
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh:
                            snippet = ''.join(fh.readlines()[:5])
                    except Exception:
                        pass
                    artifacts.append({'file': fname, 'size': size, 'snippet': snippet})
            except Exception:
                pass
            seg_preview['artifacts'] = artifacts
        except Exception as _se:
            deep_segmentation_error = str(_se)
            seg_preview['source'] = 'lightweight_fallback'
            seg_preview['error'] = deep_segmentation_error
            # If runtime planner fails, leave rules list empty (no fallback lightweight recreation to avoid drift)

    # ---- Traffic Script Early Generation ----
    traffic_scripts_preview: Dict[str, Any] = {}
    if traffic_plan and host_nodes:
        try:
            from ..types import TrafficInfo, NodeInfo  # type: ignore
            from ..utils.traffic import generate_traffic_scripts  # type: ignore
            from ..utils.segmentation import plan_preview_allow_rules  # type: ignore
            # Heuristic density: average of factors capped at 1.0
            factors = [float(it.get('factor') or 0.0) for it in traffic_plan]
            density_est = 0.0
            if factors:
                density_est = min(1.0, max(0.0, sum(factors) / max(1.0, len(factors))))
            # Build TrafficInfo list
            t_items: List[TrafficInfo] = []
            for it in traffic_plan:
                t_items.append(TrafficInfo(kind=(it.get('kind') or 'TCP'), factor=float(it.get('factor') or 0.0), pattern=it.get('pattern') or 'continuous', rate_kbps=float(it.get('rate_kbps') or 0.0), abs_count=int(it.get('abs_count') or 0)))
            ninfos: List[NodeInfo] = []
            for h in host_nodes:
                if h.ip4:
                    ninfos.append(NodeInfo(node_id=h.node_id, ip4=h.ip4, role=h.role))
            # Use deterministic per-seed preview temp dir; don't pollute final /tmp/traffic until execution.
            preview_dir = os.path.join(tempfile.gettempdir(), f"core-topo-preview-traffic-{seed}")
            os.makedirs(preview_dir, exist_ok=True)
            script_map = generate_traffic_scripts(ninfos, density_est, t_items, out_dir=preview_dir) or {}
            # Summarize
            summary_nodes = {}
            for nid, paths in script_map.items():
                summary_nodes[str(nid)] = {'count': len(paths), 'paths': paths[:5]}  # cap list for payload size
            traffic_scripts_preview = {
                'nodes': summary_nodes,
                'density_est': density_est,
                'preview_dir': preview_dir,
                'final_dir_hint': '/tmp/traffic',
                'note': 'Preview scripts will be copied to runtime dir for reuse (unified preview/runtime).'
            }
            # Predicted allow rules (dry-run) for preview purposes
            host_ip_map = {h.node_id: h.ip4.split('/')[0] for h in host_nodes if h.ip4}
            try:
                predicted = plan_preview_allow_rules(seg_preview or {}, traffic_plan, host_ip_map, seed=seed)
                traffic_scripts_preview['predicted_allow_rules'] = predicted.get('predicted_allow_rules')
            except Exception as _pae:
                traffic_scripts_preview['predicted_allow_rules_error'] = str(_pae)
        except Exception as _te:
            traffic_scripts_preview = {'error': str(_te)}

    # ---- Unify Preview -> Runtime Scripts + Hashing (Segmentation & Traffic) ----
    try:
        import hashlib, shutil
        # Segmentation scripts
        seg_prev_dir = seg_preview.get('out_dir') if isinstance(seg_preview, dict) else None
        if seg_prev_dir and os.path.isdir(seg_prev_dir):
            runtime_seg_dir = '/tmp/segmentation'
            os.makedirs(runtime_seg_dir, exist_ok=True)
            # clean runtime dir
            for _n in os.listdir(runtime_seg_dir):
                _p = os.path.join(runtime_seg_dir, _n)
                try:
                    if os.path.isfile(_p) or os.path.islink(_p): os.unlink(_p)
                    elif os.path.isdir(_p): shutil.rmtree(_p)
                except Exception: pass
            copied = []
            for _n in sorted(os.listdir(seg_prev_dir)):
                _src = os.path.join(seg_prev_dir, _n)
                if os.path.isfile(_src):
                    try:
                        shutil.copy(_src, os.path.join(runtime_seg_dir, _n))
                        copied.append(_n)
                    except Exception: pass
            seg_preview['runtime_copied'] = True
            seg_preview['runtime_dir'] = runtime_seg_dir
            seg_preview['copied_files'] = copied
            # hash
            h = hashlib.sha256()
            for _n in sorted(copied):
                if not _n.endswith('.py'): continue
                try:
                    with open(os.path.join(runtime_seg_dir,_n),'rb') as _fh: h.update(_fh.read())
                except Exception: pass
            seg_preview['scripts_hash_sha256'] = h.hexdigest()
            # load segmentation_summary.json
            summary_fp = os.path.join(runtime_seg_dir,'segmentation_summary.json')
            if os.path.exists(summary_fp):
                try:
                    import json as _json
                    with open(summary_fp,'r',encoding='utf-8') as _sf: _sum = _json.load(_sf) or {}
                    if isinstance(_sum.get('rules'), list) and len(_sum['rules'])>75:
                        _sum['_rules_truncated'] = True
                        _sum['rules'] = _sum['rules'][:75]
                    seg_preview['runtime_summary'] = _sum
                except Exception: pass
        # Traffic scripts
        tr_prev_dir = traffic_scripts_preview.get('preview_dir') if isinstance(traffic_scripts_preview, dict) else None
        if tr_prev_dir and os.path.isdir(tr_prev_dir):
            runtime_tr_dir = '/tmp/traffic'
            os.makedirs(runtime_tr_dir, exist_ok=True)
            for _n in os.listdir(runtime_tr_dir):
                _p = os.path.join(runtime_tr_dir, _n)
                try:
                    if os.path.isfile(_p) or os.path.islink(_p): os.unlink(_p)
                    elif os.path.isdir(_p): shutil.rmtree(_p)
                except Exception: pass
            copied_t = []
            for _n in sorted(os.listdir(tr_prev_dir)):
                _src = os.path.join(tr_prev_dir, _n)
                if os.path.isfile(_src):
                    try:
                        shutil.copy(_src, os.path.join(runtime_tr_dir, _n))
                        copied_t.append(_n)
                    except Exception: pass
            traffic_scripts_preview['runtime_copied'] = True
            traffic_scripts_preview['runtime_dir'] = runtime_tr_dir
            traffic_scripts_preview['copied_files'] = copied_t
            th = hashlib.sha256()
            for _n in sorted(copied_t):
                if not _n.endswith('.py'): continue
                try:
                    with open(os.path.join(runtime_tr_dir,_n),'rb') as _fh: th.update(_fh.read())
                except Exception: pass
            traffic_scripts_preview['scripts_hash_sha256'] = th.hexdigest()
    except Exception:
        pass

    # ---- Housekeeping: cleanup stale previous preview directories (best-effort) ----
    try:
        from ..utils.cleanup import clean_stale_preview_dirs  # type: ignore
        protect_dirs = []
        try:
            if isinstance(seg_preview, dict) and seg_preview.get('out_dir'):
                protect_dirs.append(seg_preview.get('out_dir'))
        except Exception:
            pass
        try:
            if isinstance(traffic_scripts_preview, dict) and traffic_scripts_preview.get('preview_dir'):
                protect_dirs.append(traffic_scripts_preview.get('preview_dir'))
        except Exception:
            pass
        clean_stale_preview_dirs(protect=protect_dirs)
    except Exception:
        pass

    return {
        'routers': [r.__dict__ for r in router_nodes],
        'hosts': [h.__dict__ for h in host_nodes],
        'switches': [s.__dict__ for s in switch_nodes],
        'switches_detail': switches_detail,
        'host_router_map': host_router_map,
        'services_preview': service_assignments,
        'vulnerabilities_preview': vuln_assignments,
        'r2r_policy_preview': r2r_preview,
        'r2r_edges_preview': r2r_edges,
        'r2r_degree_preview': r2r_degree,
        'r2r_stats_preview': r2r_stats,
        'r2s_policy_preview': computed_r2s_policy,
        'segmentation_preview': seg_preview,
        'segmentation_rules_preview': segmentation_rules_preview,
    'segmentation_items_resolved': segmentation_items or [],
    'traffic_plan': traffic_plan,
    'traffic_summary': traffic_summary,
    'traffic_scripts_preview': traffic_scripts_preview,
        'ptp_subnets': ptp_subnets,
        'router_switch_subnets': router_switch_subnets,
        'lan_subnets': lan_subnets,
    'r2r_subnets': r2r_subnets,
        'routing_plan': routing_plan,
        'services_plan': services_plan,
        'vulnerabilities_plan': vulnerabilities_plan,
        'role_counts': dict(role_counts),
        'seed': seed,
        'seed_generated': seed_generated,
        'r2s_hosts_min_list': r2s_hosts_min_list or [],
        'r2s_hosts_max_list': r2s_hosts_max_list or [],
        'r2s_grouping_preview': grouping_preview,
        'ip_allocation_mode': ip_alloc_mode,
        'router_plan_stats': router_plan_stats,
    }

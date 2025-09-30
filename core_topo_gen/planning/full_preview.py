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

    # ---- Routers ----
    router_nodes: List[PreviewNode] = []
    for i in range(routers_planned):
        router_nodes.append(PreviewNode(node_id=i + 1, name=f"r{i+1}", role="Router", kind="router"))

    # ---- Hosts ----
    total_hosts = sum(int(c) for c in role_counts.values())
    role_expanded = _expand_roles(role_counts)
    host_nodes: List[PreviewNode] = []
    host_router_map: Dict[int, int] = {}
    if total_hosts:
        # Deterministic distribution: round-robin, stable order
        for idx, role in enumerate(role_expanded):
            host_id = routers_planned + idx + 1
            # Assign to router index (idx % routers_planned) if routers present, else 0
            if routers_planned > 0:
                rid = (idx % routers_planned) + 1
            else:
                rid = 0
            host_router_map[host_id] = rid
            host_nodes.append(PreviewNode(node_id=host_id, name=f"h{idx+1}", role=role, kind="host"))

    # ---- Simple IP assignment ----
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
    r2s_counts: Dict[int, int] = {r.node_id: 0 for r in router_nodes}
    r2s_host_pairs_possible: Dict[int, int] = {}
    r2s_host_pairs_used: Dict[int, int] = {}
    r2s_unmet: Dict[int, int] = {}
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

    grouping_preview: List[Dict[str, Any]] = []
    per_router_bounds: Dict[int, Dict[str, Optional[int]]] = {}
    for rid, host_list in hosts_by_router.items():
        host_list_sorted = list(host_list)
        host_list_sorted.sort()
        r2s_host_pairs_possible[rid] = len(host_list_sorted) // 2
        # Determine bounds for this router from assigned routing item
        bounds_item = None
        try:
            if item_assignment and 0 <= (rid - 1) < len(item_assignment):
                bounds_item = item_assignment[rid - 1]
        except Exception:
            bounds_item = None
        hmin_r = None; hmax_r = None; proto_name = None
        if bounds_item is not None:
            try:
                hmin_r = int(getattr(bounds_item, 'r2s_hosts_min', 0)) or None
                hmax_r = int(getattr(bounds_item, 'r2s_hosts_max', 0)) or None
                proto_name = getattr(bounds_item, 'protocol', None)
            except Exception:
                if isinstance(bounds_item, dict):
                    try:
                        hmin_r = int(bounds_item.get('r2s_hosts_min') or 0) or None
                        hmax_r = int(bounds_item.get('r2s_hosts_max') or 0) or None
                        proto_name = bounds_item.get('protocol')
                    except Exception:
                        pass
        per_router_bounds[rid] = {'min': hmin_r, 'max': hmax_r}
        if str(mode_rs).lower() == 'exact' and int(float(target_per_router or 0)) == 1:
            # Aggregated single switch per router containing all that router's hosts
            if not host_list_sorted:
                r2s_host_pairs_used[rid] = 0
                r2s_unmet[rid] = 0
                continue
            rsw_name = f"rsw-{rid}-1"
            switch_nodes.append(PreviewNode(node_id=next_switch_id, name=rsw_name, role="Switch", kind="switch"))
            # Provide synthetic subnets
            rsw_subnet = f"10.254.{rid}.0/30"
            lan_subnet = f"10.253.{rid}.0/28"
            router_switch_subnets.append(rsw_subnet)
            lan_subnets.append(lan_subnet)
            host_if_ips: Dict[int, str] = {}
            try:
                lan_net = ipaddress.ip_network(lan_subnet, strict=False)
                lan_hosts = list(lan_net.hosts())
            except Exception:
                lan_hosts = []
            for idx_h, h_id in enumerate(host_list_sorted):
                if idx_h + 1 < len(lan_hosts):
                    ip_assigned = str(lan_hosts[idx_h + 1]) + f"/{lan_net.prefixlen if lan_hosts else 28}"
                    host_if_ips[h_id] = ip_assigned
                    # update host node ip (overwrite previous simple assignment for richer preview)
                    for hn in host_nodes:
                        if hn.node_id == h_id:
                            hn.ip4 = ip_assigned
                            break
            switches_detail.append({
                'switch_id': next_switch_id,
                'router_id': rid,
                'hosts': host_list_sorted,
                'rsw_subnet': rsw_subnet,
                'lan_subnet': lan_subnet,
                'router_ip': None,
                'switch_ip': None,
                'host_if_ips': host_if_ips,
            })
            r2s_counts[rid] = 1
            r2s_host_pairs_used[rid] = len(host_list_sorted) // 2
            try:
                unmet = max(0, int(float(target_per_router)) - 1)
            except Exception:
                unmet = 0
            r2s_unmet[rid] = unmet
            grouping_preview.append({
                'router_id': rid,
                'protocol': proto_name,
                'bounds': {'min': hmin_r, 'max': hmax_r},
                'host_ids': host_list_sorted,
                'groups': [host_list_sorted],
                'group_sizes': [len(host_list_sorted)]
            })
            next_switch_id += 1
        else:
            # Non-Exact (simplified): no switches if <2 hosts, else one per 4 hosts (ceil)
            if len(host_list_sorted) < 2:
                r2s_host_pairs_used[rid] = 0
                grouping_preview.append({
                    'router_id': rid,
                    'protocol': proto_name,
                    'bounds': {'min': hmin_r, 'max': hmax_r},
                    'host_ids': host_list_sorted,
                    'groups': [],
                    'group_sizes': []
                })
                continue
            # Determine dynamic group sizes honoring per-router bounds if present
            rnd_local = random.Random(rnd_seed + 7000 + rid)
            lo = hmin_r if (hmin_r and hmin_r > 0) else 2
            hi = hmax_r if (hmax_r and hmax_r > 0 and (not hmin_r or hmax_r >= hmin_r)) else 4
            if lo > hi:
                lo = hi
            remaining = list(host_list_sorted)
            groups: List[List[int]] = []
            while remaining:
                # If the remaining hosts already fit within bounds, take them as a final group
                if len(remaining) <= hi and len(remaining) >= lo:
                    groups.append(list(remaining)); remaining.clear(); break
                # If the remainder is smaller than the minimum allowed group size, we need an adjustment.
                # Strategy: merge the remainder into the previous group (even if it exceeds hi) to avoid
                # creating an undersized dangling group that would violate min constraint more severely.
                if len(remaining) < lo:
                    if groups:
                        groups[-1].extend(remaining)
                    else:
                        groups.append(list(remaining))  # no prior group, accept undersized
                    remaining.clear()
                    break
                # pick size with bias toward lower sizes for variability
                sizes = list(range(lo, min(hi, len(remaining)) + 1))
                if not sizes:  # defensive (should be caught by remainder < lo case above)
                    groups.append(list(remaining)); remaining.clear(); break
                weights = [1.0/(s**1.15) for s in sizes]
                tot = sum(weights)
                pick = rnd_local.random() * tot
                acc = 0.0; chosen = sizes[0]
                for s,w in zip(sizes, weights):
                    acc += w
                    if pick <= acc:
                        chosen = s; break
                if chosen > len(remaining):
                    chosen = len(remaining)
                groups.append(remaining[:chosen])
                remaining = remaining[chosen:]
            for gi, group in enumerate(groups):
                rsw_name = f"rsw-{rid}-{gi+1}"
                switch_nodes.append(PreviewNode(node_id=next_switch_id, name=rsw_name, role="Switch", kind="switch"))
                rsw_subnet = f"10.254.{rid}.{gi*4}/30"
                lan_subnet = f"10.253.{rid}.{gi*16}/28"
                router_switch_subnets.append(rsw_subnet)
                lan_subnets.append(lan_subnet)
                host_if_ips: Dict[int, str] = {}
                switches_detail.append({
                    'switch_id': next_switch_id,
                    'router_id': rid,
                    'hosts': list(group),
                    'rsw_subnet': rsw_subnet,
                    'lan_subnet': lan_subnet,
                    'router_ip': None,
                    'switch_ip': None,
                    'host_if_ips': host_if_ips,
                })
                next_switch_id += 1
            r2s_counts[rid] = len(groups)
            r2s_host_pairs_used[rid] = sum(len(g) // 2 for g in groups)
            grouping_preview.append({
                'router_id': rid,
                'protocol': proto_name,
                'bounds': {'min': hmin_r, 'max': hmax_r},
                'host_ids': host_list_sorted,
                'groups': groups,
                'group_sizes': [len(g) for g in groups]
            })

    # Build R2S policy summary
    if str(mode_rs).lower() == 'exact':
        computed_r2s_policy = {'mode': 'Exact', 'target_per_router': target_per_router or 1, 'counts': r2s_counts}
        if derived_effective_target is not None:
            computed_r2s_policy['target_per_router_effective'] = derived_effective_target
    else:
        computed_r2s_policy = {'mode': mode_rs, 'target_per_router': target_per_router or 0, 'counts': r2s_counts}

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
    total_pairs_possible = sum(r2s_host_pairs_possible.values()) or 0
    total_pairs_used = sum(r2s_host_pairs_used.values()) or 0
    saturation = 0.0
    if total_pairs_possible > 0:
        saturation = round(total_pairs_used / total_pairs_possible, 3)
    computed_r2s_policy.update({
        'host_pairs_possible_total': total_pairs_possible,
        'host_pairs_used_total': total_pairs_used,
        'host_pair_saturation': saturation,
        'host_pairs_possible': r2s_host_pairs_possible,
        'host_pairs_used': r2s_host_pairs_used,
        'per_router_bounds': per_router_bounds,
    })
    if r2s_unmet:
        computed_r2s_policy['unmet_switch_targets'] = r2s_unmet

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

    # ---- Segmentation Preview (lightweight) ----
    seg_preview: Dict[str, Any] = {"density": segmentation_density or 0.0, "planned": [], "rules": []}
    if segmentation_density and segmentation_density > 0 and segmentation_items:
        slots = int(round(segmentation_density * max(total_hosts, 0)))
        weights: List[Tuple[str, float]] = []
        for it in segmentation_items:
            sel = (it.get('selected') or it.get('name') or '').strip() or 'Random'
            factor = float(it.get('factor') or 0.0)
            if sel.lower() == 'random':
                kinds = ['Firewall', 'NAT', 'CUSTOM']
                for k in kinds:
                    weights.append((k, factor / len(kinds) if factor > 0 else 0))
            else:
                weights.append((sel, factor))
        if not weights:
            weights = [('Firewall', 1.0)]
        total_w = sum(w for _, w in weights) or 1.0
        rnd = random.Random(rnd_seed + 202)
        picks: List[str] = []
        for _ in range(slots):
            r = rnd.random() * total_w
            acc = 0.0
            choice = weights[-1][0]
            for name, w in weights:
                acc += w
                if r <= acc:
                    choice = name; break
            picks.append(choice)
        seg_preview['planned'] = picks

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
        'ptp_subnets': ptp_subnets,
        'router_switch_subnets': router_switch_subnets,
        'lan_subnets': lan_subnets,
        'routing_plan': routing_plan,
        'services_plan': services_plan,
        'vulnerabilities_plan': vulnerabilities_plan,
        'role_counts': dict(role_counts),
        'seed': seed,
        'seed_generated': seed_generated,
        'r2s_hosts_min_list': r2s_hosts_min_list or [],
        'r2s_hosts_max_list': r2s_hosts_max_list or [],
        'r2s_grouping_preview': grouping_preview,
    }

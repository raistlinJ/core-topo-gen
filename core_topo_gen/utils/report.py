from __future__ import annotations
import os
import json
import time
from typing import Dict, List, Optional
from ..types import NodeInfo


def _read_traffic_summary(path: str) -> List[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        flows = data.get("flows", [])
        # basic shape check
        if isinstance(flows, list):
            return flows
    except Exception:
        pass
    return []


def _read_segmentation_summary(path: str) -> List[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", [])
        if isinstance(rules, list):
            return rules
    except Exception:
        pass
    return []


def write_report(
    out_path: str,
    scenario_name: Optional[str],
    routers: Optional[List[NodeInfo]] = None,
    router_protocols: Optional[Dict[int, List[str]]] = None,
    switches: Optional[List[int]] = None,
    hosts: Optional[List[NodeInfo]] = None,
    service_assignments: Optional[Dict[int, List[str]]] = None,
    traffic_summary_path: Optional[str] = None,
    segmentation_summary_path: Optional[str] = None,
    metadata: Optional[Dict[str, object]] = None,
    routing_cfg: Optional[Dict[str, object]] = None,
    traffic_cfg: Optional[Dict[str, object]] = None,
    services_cfg: Optional[List[Dict[str, object]]] = None,
    segmentation_cfg: Optional[Dict[str, object]] = None,
    vulnerabilities_cfg: Optional[Dict[str, object]] = None,
) -> str:
    routers = routers or []
    hosts = hosts or []
    switches = switches or []
    router_protocols = router_protocols or {}
    service_assignments = service_assignments or {}

    flows: List[dict] = []
    if traffic_summary_path and os.path.exists(traffic_summary_path):
        flows = _read_traffic_summary(traffic_summary_path)
    seg_rules: List[dict] = []
    if segmentation_summary_path and os.path.exists(segmentation_summary_path):
        seg_rules = _read_segmentation_summary(segmentation_summary_path)

    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    total_nodes = len(routers) + len(hosts) + len(switches)

    lines: List[str] = []
    lines.append(f"# Scenario Report")
    lines.append("")
    # Plan Summary (phased builder)
    try:
        plan_summary = None
        if metadata:
            plan_summary = metadata.get('plan_summary') or metadata.get('planSummary')
        if isinstance(plan_summary, dict) and plan_summary:
            lines.append("## Plan Summary (Phased Build)")
            try:
                # Show key resource alignment
                lines.append(f"- Hosts planned: {plan_summary.get('hosts_total')} | allocated: {plan_summary.get('hosts_allocated')}")
                lines.append(f"- Routers planned: {plan_summary.get('routers_planned')} | allocated: {plan_summary.get('routers_allocated')}")
                if plan_summary.get('r2s_ratio_used') is not None:
                    lines.append(f"- R2S ratio used: {plan_summary.get('r2s_ratio_used')}")
                if plan_summary.get('switches_allocated') is not None:
                    lines.append(f"- Switches allocated: {plan_summary.get('switches_allocated')}")
                if plan_summary.get('vulnerabilities_plan'):
                    vt = sum((plan_summary.get('vulnerabilities_plan') or {}).values())
                    lines.append(f"- Vulnerabilities planned: {vt} | assigned: {plan_summary.get('vulnerabilities_assigned')}")
                if plan_summary.get('r2r_policy'):
                    rp = plan_summary.get('r2r_policy') or {}
                    mode = rp.get('mode') or 'n/a'
                    tdeg = rp.get('target_degree') or 0
                    lines.append(f"- R2R policy: mode={mode} target_degree={tdeg}")
            except Exception:
                pass
            # Drift details if present
            drift = plan_summary.get('plan_drift') or metadata.get('plan_drift') or metadata.get('preview_drift')
            if drift:
                lines.append("### Plan / Preview Drift")
                for v in drift:
                    lines.append(f"- {v}")
            lines.append("")
    except Exception:
        pass
    if scenario_name:
        lines.append(f"Scenario: {scenario_name}")
    lines.append(f"Generated: {ts}")
    lines.append("")
    lines.append("## Summary")
    # Schema / XML diagnostics if provided in metadata
    try:
        if metadata and (metadata.get('xml_path') or metadata.get('xml_schema_classification')):
            lines.append("### Source XML")
            if metadata.get('xml_path'):
                lines.append(f"- XML Path: {metadata.get('xml_path')}")
            if metadata.get('xml_schema_classification'):
                lines.append(f"- XML Classification: {metadata.get('xml_schema_classification')}")
            if metadata.get('xml_container_flag') is True:
                lines.append(f"- Contains <container>: true (session export)")
            lines.append("")
    except Exception:
        pass
    lines.append(f"- Total nodes: {total_nodes}")
    # Base host pool removed; show additive breakdown only if provided
    try:
        if metadata:
            if metadata.get('count_rows_additive_total'):
                lines.append(f"- Additive Count Rows Total: {metadata.get('count_rows_additive_total')}")
            try:
                cc = metadata.get('count_rows_breakdown') or {}
                if cc:
                    lines.append(f"- Role Additive Counts: {', '.join(f'{r}={c}' for r,c in cc.items())}")
            except Exception:
                pass
    except Exception:
        pass
    lines.append(f"- Routers: {len(routers)}  |  Switches: {len(switches)}  |  Hosts: {len(hosts)}")
    lines.append(f"- Traffic flows: {len(flows)}")
    lines.append(f"- Segmentation rules: {len(seg_rules)}")
    try:
        if metadata and metadata.get('segmentation_preview_rules') and not seg_rules:
            lines.append(f"- Segmentation (preview injected): {len(metadata.get('segmentation_preview_rules') or [])}")
    except Exception:
        pass
    # Planned vs Actual reconciliation (counts) leveraging plan_summary if present
    try:
        plan_summary = None
        if metadata:
            plan_summary = metadata.get('plan_summary') or metadata.get('planSummary')
        if isinstance(plan_summary, dict) and plan_summary:
            reconc_rows = []
            def fmt_match(label: str, planned, actual):
                if planned is None:
                    return None
                status = 'MATCH' if planned == actual else f'DRIFT (Δ={actual - planned})'
                return f"| {label} | {planned} | {actual} | {status} |"
            planned_hosts = plan_summary.get('hosts_total') or plan_summary.get('hosts_planned')
            planned_routers = plan_summary.get('routers_planned') or plan_summary.get('routers_allocated')
            planned_switches = plan_summary.get('switches_allocated') or plan_summary.get('switches_planned')
            # Edge count (preview vs actual) if available
            planned_edges = plan_summary.get('r2r_edges_planned') or plan_summary.get('r2r_edges_preview_count')
            actual_edges = None
            try:
                if metadata and metadata.get('router_degrees'):
                    # Sum degrees /2 gives undirected edge count
                    dv = list((metadata.get('router_degrees') or {}).values())
                    if dv:
                        actual_edges = int(sum(dv)/2)
            except Exception:
                actual_edges = None
            # Segmentation rules
            planned_seg_rules = None
            if metadata and metadata.get('segmentation_preview_rules'):
                planned_seg_rules = len(metadata.get('segmentation_preview_rules') or [])
            actual_seg_rules = len(seg_rules)

            reconc_rows.extend(filter(None, [
                fmt_match('Hosts', planned_hosts, len(hosts)),
                fmt_match('Routers', planned_routers, len(routers)),
                fmt_match('Switches', planned_switches, len(switches)),
                fmt_match('R2R Edges', planned_edges, actual_edges) if (planned_edges is not None and actual_edges is not None) else None,
                fmt_match('Segmentation Rules', planned_seg_rules, actual_seg_rules) if (planned_seg_rules is not None) else None,
            ]))
            if reconc_rows:
                lines.append('')
                lines.append('### Reconciliation (Planned vs Actual)')
                lines.append('| Resource | Planned | Actual | Status |')
                lines.append('| --- | ---: | ---: | --- |')
                lines.extend(reconc_rows)
                lines.append('')
    except Exception:
        pass
    # Router edges policy / degree stats if present (from session.topo_stats stored in metadata under keys)
    try:
        rep = None; degs = None
        if metadata:
            rep = metadata.get('router_edges_policy') or metadata.get('topo_router_edges_policy')
            degs = metadata.get('router_degrees') or metadata.get('topo_router_degrees')
        # One-line summary in Summary section
        if degs and isinstance(degs, dict) and degs:
            try:
                dv = list(degs.values())
                lines.append(f"- Connectivity: degree_min={min(dv)} avg={round(sum(dv)/len(dv),2)} max={max(dv)}")
            except Exception:
                pass
        if rep or degs:
            lines.append("## Router Edge Connectivity")
            if isinstance(rep, dict):
                mode = rep.get('mode', 'Unknown'); tgt = rep.get('target_degree')
                if mode == 'Exact' and tgt:
                    meth = rep.get('construction_method') or rep.get('method')
                    if meth:
                        lines.append(f"- Policy: Exact (target degree={tgt}, method={meth})")
                    else:
                        lines.append(f"- Policy: Exact (target degree={tgt})")
                elif mode == 'Max':
                    lines.append("- Policy: Max (full mesh)")
                elif mode == 'Min':
                    lines.append("- Policy: Min (chain path)")
                elif mode == 'NonUniform':
                    lines.append("- Policy: NonUniform (heterogeneous random degrees)")
                elif mode == 'Random':
                    lines.append("- Policy: Random (spanning tree)")
                elif mode == 'Uniform':
                    lines.append("- Policy: Uniform (balanced near-regular degrees)")
                else:
                    lines.append(f"- Policy: {mode}")
                if rep.get('degree_avg') is not None:
                    disp_min = rep.get('display_degree_min') or rep.get('degree_min')
                    disp_max = rep.get('display_degree_max') or rep.get('degree_max')
                    lines.append("- Degree stats: min={mn} avg={av} max={mx} std={sd} gini={gi}".format(
                        mn=disp_min, av=rep.get('degree_avg'), mx=disp_max, sd=rep.get('degree_std'), gi=rep.get('degree_gini')))
                    note = rep.get('note') if isinstance(rep, dict) else None
                    if note:
                        lines.append(f"- Note: {note}")
            if isinstance(degs, dict) and degs:
                vals = list(degs.values())
                mn, mx = min(vals), max(vals)
                avg = round(sum(vals)/len(vals), 2)
                # Normalize display for target_degree=1 (perfect matching with optional single isolated)
                tdeg = (rep or {}).get('target_degree') if isinstance(rep, dict) else None
                if tdeg == 1:
                    note = ''
                    if (len(vals) % 2 == 1) and 0 in vals:
                        note = ' (one router isolated due to odd count)'
                    lines.append(f"- Degrees: min={1 if mn in (0,1) else mn} avg={avg} max={1 if mx in (0,1) else mx}{note}")
                else:
                    lines.append(f"- Degrees: min={mn} avg={avg} max={mx}")
                from collections import Counter
                c = Counter(vals)
                hist = ', '.join(f"{k}:{c[k]}" for k in sorted(c))
                lines.append(f"- Histogram: {hist}")
            lines.append("")
    except Exception:
        pass

    # Segmentation preview rules fallback (only if no runtime rules were produced)
    try:
        if not seg_rules and metadata and metadata.get('segmentation_preview_rules'):
            lines.append("## Segmentation Rules (Preview Injected)")
            lines.append("| Node | Type | Details | Source |")
            lines.append("| ---: | --- | --- | --- |")
            for r in metadata.get('segmentation_preview_rules') or []:
                node_id = r.get('node_id')
                rr = r.get('rule') or {}
                typ = rr.get('type', '')
                det = ''
                if typ == 'nat':
                    det = f"{rr.get('internal','')} -> {rr.get('external','')} ({rr.get('mode','')})"
                elif typ in ('host_block','subnet_block'):
                    det = f"{rr.get('src','')} -> {rr.get('dst','')}"
                elif typ == 'custom':
                    det = rr.get('description','')
                lines.append(f"| {node_id} | {typ} | {det} | preview |")
            lines.append("")
    except Exception:
        pass

    # Router-to-Switch connectivity policy (if recorded in metadata)
    try:
        r2s = None
        if metadata:
            r2s = metadata.get('r2s_policy') or metadata.get('topo_r2s_policy')
        if isinstance(r2s, dict):
            lines.append("## Router-to-Switch Connectivity")
            mode = r2s.get('mode')
            tgt = r2s.get('target_per_router') or r2s.get('target')
            if mode == 'Exact' and tgt is not None:
                lines.append(f"- Policy: Exact (target switches per router={tgt})")
            else:
                lines.append(f"- Policy: {mode}")
            counts = r2s.get('counts') or {}
            if counts:
                vals = list(counts.values())
                mn, mx = min(vals), max(vals)
                avg = round(sum(vals)/len(vals), 2)
                from collections import Counter
                c = Counter(vals)
                hist = ', '.join(f"{k}:{c[k]}" for k in sorted(c))
                lines.append(f"- Switch counts per router: min={mn} avg={avg} max={mx}")
                lines.append(f"- Histogram: {hist}")
            if r2s.get('count_avg') is not None:
                lines.append("- Switch count stats: min={mn} avg={av} max={mx} std={sd} gini={gi}".format(
                    mn=r2s.get('count_min'), av=r2s.get('count_avg'), mx=r2s.get('count_max'), sd=r2s.get('count_std'), gi=r2s.get('count_gini')))
            reh = r2s.get('rehomed_hosts') or []
            if reh:
                lines.append(f"- Hosts rehomed behind new R2S switches: {len(reh)}")
            lines.append("")
    except Exception:
        pass
    # Vulnerability assignment count (best effort):
    # Prefer runtime assignment summary if present, else infer from vulnerabilities_cfg
    vuln_assigned = None
    try:
        assign_summary_path = "/tmp/vulns/compose_assignments.json"
        if os.path.exists(assign_summary_path):
            with open(assign_summary_path, "r", encoding="utf-8") as vf:
                _assign_data = json.load(vf)
            assignments = (_assign_data.get("assignments") or {})
            if isinstance(assignments, dict):
                vuln_assigned = len(assignments)
    except Exception:
        pass
    if vuln_assigned is None and vulnerabilities_cfg:
        try:
            items = vulnerabilities_cfg.get("items") or []
            # Sum explicit v_count values (Count metric or Specific with v_count)
            total_counts = 0
            for it in items:
                vc = it.get("v_count") if isinstance(it, dict) else None
                if isinstance(vc, int) and vc > 0:
                    total_counts += vc
            if total_counts == 0:
                # Fallback: treat each item as 1 planned vulnerability if no counts specified
                total_counts = len(items)
            vuln_assigned = total_counts
        except Exception:
            vuln_assigned = None
    if vuln_assigned is not None:
        lines.append(f"- Vulnerabilities assigned: {vuln_assigned}")
    # Optional additive stats (routers/vulns) from metadata/topo_stats
    try:
        if metadata:
            rdens = metadata.get("routers_density_count") or metadata.get("routers_density")
            rcount = metadata.get("routers_count_count")
            rtot = metadata.get("routers_total_planned")
            if rtot is not None and (rdens is not None or rcount is not None):
                parts = []
                count_only_flag = False
                if (rcount and rcount > 0) and (not rdens or float(rdens) == 0):
                    count_only_flag = True
                if rdens is not None:
                    parts.append(f"density_component={rdens}")
                if rcount is not None:
                    parts.append(f"count_component={rcount}")
                if count_only_flag:
                    parts.append("mode=count-only")
                lines.append(f"- Routers planned (additive): {rtot} ({', '.join(parts)})")
            vden_t = metadata.get("vuln_density_target")
            vcnt_t = metadata.get("vuln_count_items_total")
            vadd = metadata.get("vuln_total_planned_additive")
            vassn = metadata.get("vuln_docker_assignments")
            if any(x is not None for x in [vden_t, vcnt_t, vadd]):
                lines.append(f"- Vulnerabilities planned (additive): target={vden_t} count_items={vcnt_t} total_est={vadd} assigned={vassn}")
    except Exception:
        pass
    lines.append("")

    # Dedicated Planning Stats section consolidating additive semantics (optional clarity)
    try:
        if metadata and any(k.startswith('vuln_') or k.startswith('routers_') for k in metadata.keys()):
            lines.append("## Planning Stats")
            # Host role planning breakdown
            if metadata.get('density_base_count') is not None:
                lines.append(f"- Hosts base (density): {metadata.get('density_base_count')}")
            if metadata.get('count_rows_additive_total'):
                lines.append(f"- Hosts additive (count rows): {metadata.get('count_rows_additive_total')}")
            if metadata.get('role_counts'):
                rc = metadata.get('role_counts') or {}
                lines.append(f"- Final role counts: {', '.join(f'{r}={c}' for r,c in rc.items())}")
            if 'routers_total_planned' in metadata:
                lines.append(f"- Routers total (additive): {metadata.get('routers_total_planned')} (density_component={metadata.get('routers_density_count')} count_component={metadata.get('routers_count_count')})")
            if 'vuln_total_planned_additive' in metadata:
                lines.append(f"- Vulnerabilities total est (additive): {metadata.get('vuln_total_planned_additive')} (density_target={metadata.get('vuln_density_target')} count_items={metadata.get('vuln_count_items_total')} assigned={metadata.get('vuln_docker_assignments')})")
            lines.append("")
    except Exception:
        pass
    # New enriched planning metadata (namespaced plan_*)
    try:
        if metadata and any(k.startswith('plan_') for k in metadata.keys()):
            lines.append("## Planning Metadata (from XML)")
            mapping = [
                ("Node Base", 'plan_node_base_nodes'),
                ("Node Additive", 'plan_node_additive_nodes'),
                ("Node Combined", 'plan_node_combined_nodes'),
                ("Node Weight Rows", 'plan_node_weight_rows'),
                ("Node Count Rows", 'plan_node_count_rows'),
                ("Node Weight Sum", 'plan_node_weight_sum'),
                ("Routing Explicit", 'plan_routing_explicit'),
                ("Routing Derived", 'plan_routing_derived'),
                ("Routing Total", 'plan_routing_total'),
                ("Routing Weight Rows", 'plan_routing_weight_rows'),
                ("Routing Count Rows", 'plan_routing_count_rows'),
                ("Routing Weight Sum", 'plan_routing_weight_sum'),
                ("Vuln Explicit", 'plan_vuln_explicit'),
                ("Vuln Derived", 'plan_vuln_derived'),
                ("Vuln Total", 'plan_vuln_total'),
                ("Vuln Weight Rows", 'plan_vuln_weight_rows'),
                ("Vuln Count Rows", 'plan_vuln_count_rows'),
                ("Vuln Weight Sum", 'plan_vuln_weight_sum'),
            ]
            for label, key in mapping:
                if metadata.get(key) is not None:
                    lines.append(f"- {label}: {metadata.get(key)}")
            lines.append("")
    except Exception:
        pass

    if routers:
        lines.append("## Routers")
        for r in routers:
            protos = router_protocols.get(r.node_id, [])
            svc = ["IPForward", "zebra"] + protos if protos else ["IPForward", "zebra"]
            proto_str = ",".join(protos) if protos else "(none)"
            lines.append(f"- Router {r.node_id}: protocol={proto_str} services=[{', '.join(svc)}]")
        lines.append("")

    if switches:
        lines.append("## Switches")
        lines.append(", ".join(str(sid) for sid in switches))
        lines.append("")
    elif metadata and metadata.get('switches_allocated') is not None:
        try:
            lines.append("## Switches")
            lines.append(f"(allocated: {metadata.get('switches_allocated')})")
            lines.append("")
        except Exception:
            pass

    if hosts:
        lines.append("## Hosts")
        lines.append("| Node ID | IPv4 | Role | Services |")
        lines.append("| --- | --- | --- | --- |")
        for h in hosts:
            svcs = service_assignments.get(h.node_id, [])
            lines.append(f"| {h.node_id} | {h.ip4 or ''} | {h.role} | {', '.join(svcs)} |")
        lines.append("")

    if flows:
        lines.append("## Traffic Flows")
        lines.append("| Src | Dst | Proto | Dst IP:Port | Pattern | Rate (KB/s) | Period (s) | Jitter (%) | Content | Sender | Receiver |")
        lines.append("| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | --- |")
        for f in flows:
            lines.append(
                "| {src} | {dst} | {proto} | {ip}:{port} | {pattern} | {rate} | {period} | {jitter} | {content} | {sender} | {receiver} |".format(
                    src=f.get("src_id", ""),
                    dst=f.get("dst_id", ""),
                    proto=f.get("protocol", ""),
                    ip=f.get("dst_ip", ""),
                    port=f.get("dst_port", ""),
                    pattern=f.get("pattern", ""),
                    rate=f.get("rate_kbps", ""),
                    period=f.get("period_s", ""),
                    jitter=f.get("jitter_pct", ""),
                    content=f.get("content_type", ""),
                    sender=os.path.basename(f.get("sender_script", "")),
                    receiver=os.path.basename(f.get("receiver_script", "")),
                )
            )
        lines.append("")

    if seg_rules:
        lines.append("## Segmentation Rules")
        lines.append("| Node | Service | Type | Details | Script |")
        lines.append("| ---: | --- | --- | --- | --- |")
        for r in seg_rules:
            typ = (r.get("rule", {}) or {}).get("type", "")
            det = ""
            rr = r.get("rule", {}) or {}
            if typ == "subnet_block":
                det = f"{rr.get('src','')} -> {rr.get('dst','')}"
            elif typ == "host_block":
                det = f"{rr.get('src','')} -> {rr.get('dst','')}"
            elif typ == "protect_internal":
                det = f"subnet {rr.get('subnet','')}"
            elif typ == "nat":
                # Show internal/external, mode and egress ip when available
                internal = rr.get("internal", "")
                external = rr.get("external", "")
                mode = rr.get("mode", "")
                eip = rr.get("egress_ip", "")
                arrow = "->"
                det = f"{internal} {arrow} {external} (mode={mode or 'SNAT'}, egress={eip})"
            elif typ == "dnat":
                rip = rr.get("router_ip", "")
                dst = rr.get("dst", "")
                port = rr.get("port", "")
                proto = rr.get("proto", "")
                det = f"{proto.upper()} {rip}:{port} -> {dst}:{port}"
            elif typ == "allow":
                det = f"{rr.get('src','')} -> {rr.get('dst','')} {rr.get('proto','').upper()}:{rr.get('port','')} ({rr.get('chain','')})"
            elif typ == "custom":
                det = "custom policy" + (" (fallback)" if rr.get("fallback") else "")
            lines.append(
                "| {node} | {svc} | {typ} | {det} | {script} |".format(
                    node=r.get("node_id", ""),
                    svc=r.get("service", ""),
                    typ=typ,
                    det=det,
                    script=os.path.basename(r.get("script", "")),
                )
            )
        lines.append("")

    # Optional Details section (extra info grouped at end)
    if any([metadata, routing_cfg, traffic_cfg, services_cfg, segmentation_cfg, vulnerabilities_cfg]):
        lines.append("## Details")
        # Connectivity Matrix (router adjacency + R2S counts) if metadata has degrees / edges
        try:
            degs = None; rep = None; r2s = None; host_counts = None
            if metadata:
                rep = metadata.get('router_edges_policy') or metadata.get('topo_router_edges_policy')
                degs = metadata.get('router_degrees') or metadata.get('topo_router_degrees')
                r2s = metadata.get('r2s_policy') or metadata.get('topo_r2s_policy')
                host_counts = metadata.get('router_host_counts')
            if isinstance(degs, dict) and degs:
                lines.append("### Connectivity Matrix")
                rids = sorted(degs.keys())
                r2s_counts = {}
                if isinstance(r2s, dict):
                    rc = r2s.get('counts') or {}
                    if isinstance(rc, dict):
                        r2s_counts = rc
                # Add host counts column if available
                has_hosts_col = isinstance(host_counts, dict) and host_counts
                header = "| Router | Degree | R2S Switches |" + (" Hosts |" if has_hosts_col else "")
                sep = "| ---: | ---: | ---: |" + (" ---: |" if has_hosts_col else "")
                lines.append(header)
                lines.append(sep)
                matrix_rows: list[str] = []
                for rid in rids:
                    deg_v = degs.get(rid, 0)
                    swc = r2s_counts.get(rid, 0)
                    hc = host_counts.get(rid, 0) if has_hosts_col else None
                    row = f"| {rid} | {deg_v} | {swc} |" + (f" {hc} |" if has_hosts_col else "")
                    lines.append(row)
                    matrix_rows.append(row)
                lines.append("")
                # Emit CSV alongside markdown (same directory) for programmatic consumption
                try:
                    csv_path = out_path + ".connectivity.csv"
                    with open(csv_path, 'w', encoding='utf-8') as cf:
                        # header row sans pipes for CSV
                        cols = ["Router","Degree","R2S_Switches"] + (["Hosts"] if has_hosts_col else [])
                        cf.write(",".join(cols) + "\n")
                        for rid in rids:
                            deg_v = degs.get(rid, 0)
                            swc = r2s_counts.get(rid, 0)
                            hc = host_counts.get(rid, 0) if has_hosts_col else None
                            row_vals = [str(rid), str(deg_v), str(swc)] + ([str(hc)] if has_hosts_col else [])
                            cf.write(",".join(row_vals) + "\n")
                except Exception:
                    pass
        except Exception:
            pass
        if metadata:
            lines.append("### Generation parameters")
            for k in sorted(metadata.keys()):
                v = metadata.get(k)
                lines.append(f"- {k}: {v}")
            lines.append("")
        if routing_cfg:
            den = routing_cfg.get("density", "")
            items = routing_cfg.get("items", []) or []
            lines.append("### Routing config")
            lines.append(f"- Density: {den}")
            if items:
                lines.append("| Protocol | Factor |")
                lines.append("| --- | ---: |")
                for it in items:
                    lines.append(f"| {it.get('protocol','')} | {it.get('factor','')} |")
            lines.append("")
        if traffic_cfg:
            den = traffic_cfg.get("density", "")
            items = traffic_cfg.get("items", []) or []
            lines.append("### Traffic config")
            lines.append(f"- Density: {den}")
            if items:
                lines.append("| Kind | Factor | Pattern | Rate (KB/s) | Period (s) | Jitter (%) | Content |")
                lines.append("| --- | ---: | --- | ---: | ---: | ---: | --- |")
                for it in items:
                    lines.append("| {kind} | {factor} | {pattern} | {rate} | {period} | {jitter} | {content} |".format(
                        kind=it.get("kind",""),
                        factor=it.get("factor",""),
                        pattern=it.get("pattern",""),
                        rate=it.get("rate_kbps",""),
                        period=it.get("period_s",""),
                        jitter=it.get("jitter_pct",""),
                        content=it.get("content_type",""),
                    ))
            lines.append("")
        if services_cfg:
            lines.append("### Services config")
            if services_cfg:
                lines.append("| Service | Factor | Density |")
                lines.append("| --- | ---: | ---: |")
                for s in services_cfg:
                    lines.append(f"| {s.get('name','')} | {s.get('factor','')} | {s.get('density','')} |")
            lines.append("")
        if segmentation_cfg:
            den = segmentation_cfg.get("density", "")
            items = segmentation_cfg.get("items", []) or []
            lines.append("### Segmentation config")
            lines.append(f"- Density: {den}")
            if items:
                lines.append("| Service | Factor |")
                lines.append("| --- | ---: |")
                for it in items:
                    lines.append(f"| {it.get('name','')} | {it.get('factor','')} |")
            lines.append("")
        if vulnerabilities_cfg:
            den = vulnerabilities_cfg.get("density", "")
            items = vulnerabilities_cfg.get("items", []) or []
            lines.append("### Vulnerabilities config")
            lines.append(f"- Density: {den}")
            if items:
                lines.append("| Selected | Metric | Factor | Type | Vector | Name | Path | Count |")
                lines.append("| --- | --- | ---: | --- | --- | --- | --- | ---: |")
                for it in items:
                    lines.append("| {sel} | {metric} | {factor} | {vt} | {vv} | {vn} | {vp} | {vc} |".format(
                        sel=it.get("selected",""),
                        metric=it.get("v_metric",""),
                        factor=it.get("factor",""),
                        vt=it.get("v_type",""),
                        vv=it.get("v_vector",""),
                        vn=it.get("v_name",""),
                        vp=it.get("v_path",""),
                        vc=it.get("v_count",""),
                    ))
            lines.append("")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).strip() + "\n")
    return out_path

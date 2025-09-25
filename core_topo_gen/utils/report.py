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
    if scenario_name:
        lines.append(f"Scenario: {scenario_name}")
    lines.append(f"Generated: {ts}")
    lines.append("")
    lines.append("## Summary")
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

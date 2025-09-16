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
    lines.append(f"- Routers: {len(routers)}  |  Switches: {len(switches)}  |  Hosts: {len(hosts)}")
    lines.append(f"- Traffic flows: {len(flows)}")
    lines.append(f"- Segmentation rules: {len(seg_rules)}")
    lines.append("")

    if routers:
        lines.append("## Routers")
        for r in routers:
            protos = router_protocols.get(r.node_id, [])
            svc = ["IPForward", "zebra"] + protos if protos else ["IPForward", "zebra"]
            lines.append(f"- Router {r.node_id}: services=[{', '.join(svc)}]")
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

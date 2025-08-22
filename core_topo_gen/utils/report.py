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


def write_report(
    out_path: str,
    scenario_name: Optional[str],
    routers: Optional[List[NodeInfo]] = None,
    router_protocols: Optional[Dict[int, List[str]]] = None,
    switches: Optional[List[int]] = None,
    hosts: Optional[List[NodeInfo]] = None,
    service_assignments: Optional[Dict[int, List[str]]] = None,
    traffic_summary_path: Optional[str] = None,
    metadata: Optional[Dict[str, object]] = None,
    routing_cfg: Optional[Dict[str, object]] = None,
    traffic_cfg: Optional[Dict[str, object]] = None,
    services_cfg: Optional[List[Dict[str, object]]] = None,
) -> str:
    routers = routers or []
    hosts = hosts or []
    switches = switches or []
    router_protocols = router_protocols or {}
    service_assignments = service_assignments or {}

    flows: List[dict] = []
    if traffic_summary_path and os.path.exists(traffic_summary_path):
        flows = _read_traffic_summary(traffic_summary_path)

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

    # Optional Details section (extra info grouped at end)
    if any([metadata, routing_cfg, traffic_cfg, services_cfg]):
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

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).strip() + "\n")
    return out_path

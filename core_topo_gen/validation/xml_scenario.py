"""CORE scenario XML sanity checks.

Validates invariants we care about for generated CORE session exports:
- No duplicate IPv4 addresses across all interfaces.
- For every L2 switch network, all connected IPv4 interfaces must be in the same IPv4 subnet
  (i.e., router<->switch and host<->switch share a common LAN subnet).

This module is intentionally lightweight and uses only the standard library.

Usage:
  python -m core_topo_gen.validation.xml_scenario /path/to/session.xml
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class Issue:
    code: str
    message: str


def _iter_ifaces(link_el: ET.Element) -> Iterable[Tuple[str, Dict[str, str]]]:
    for tag in ("iface1", "iface2"):
        child = link_el.find(tag)
        if child is None:
            continue
        yield tag, dict(child.attrib)


def _parse_ip4(iface_attrib: Dict[str, str]) -> Optional[ipaddress.IPv4Interface]:
    ip4 = iface_attrib.get("ip4")
    mask = iface_attrib.get("ip4_mask")
    if not ip4 or not mask:
        return None
    try:
        return ipaddress.ip_interface(f"{ip4}/{int(mask)}")
    except Exception:
        return None


def validate_scenario_xml(xml_bytes: bytes) -> List[Issue]:
    """Validate a CORE-exported scenario XML document."""

    try:
        root = ET.fromstring(xml_bytes)
    except Exception as exc:
        return [Issue(code="xml_parse", message=f"failed to parse XML: {exc}")]

    # Collect which node IDs represent L2 switches.
    switch_ids: Set[str] = set()
    for net in root.findall("./networks/network"):
        if net.attrib.get("type") == "SWITCH":
            nid = net.attrib.get("id")
            if nid:
                switch_ids.add(nid)

    # Build link adjacency and interface IP inventory.
    seen_ip4: Dict[str, List[str]] = {}
    # For each switch: list of (peer_id, ipv4interface)
    switch_ifaces: Dict[str, List[Tuple[str, ipaddress.IPv4Interface]]] = {}

    for link in root.findall("./links/link"):
        node1 = link.attrib.get("node1")
        node2 = link.attrib.get("node2")
        if not node1 or not node2:
            continue

        iface1 = link.find("iface1")
        iface2 = link.find("iface2")
        a1 = dict(iface1.attrib) if iface1 is not None else {}
        a2 = dict(iface2.attrib) if iface2 is not None else {}

        ip1 = _parse_ip4(a1)
        ip2 = _parse_ip4(a2)

        # Global duplicate-IP detection (across all interface endpoints).
        for ip_iface, node, attrib in ((ip1, node1, a1), (ip2, node2, a2)):
            if ip_iface is None:
                continue
            ip_str = str(ip_iface.ip)
            ref = f"node={node} iface={attrib.get('name', '?')}"
            seen_ip4.setdefault(ip_str, []).append(ref)

        # Switch subnet consistency checks.
        if node1 in switch_ids and ip2 is not None:
            switch_ifaces.setdefault(node1, []).append((node2, ip2))
        if node2 in switch_ids and ip1 is not None:
            switch_ifaces.setdefault(node2, []).append((node1, ip1))

    issues: List[Issue] = []

    # Duplicate IPv4 addresses.
    for ip_str, refs in sorted(seen_ip4.items()):
        if len(refs) > 1:
            issues.append(
                Issue(
                    code="dup_ip4",
                    message=f"duplicate ip4 {ip_str} appears {len(refs)} times: {', '.join(refs)}",
                )
            )

    # Per-switch subnet consistency.
    for sid, peers in sorted(switch_ifaces.items(), key=lambda kv: int(kv[0])):
        nets = {p.network for _, p in peers}
        if len(nets) > 1:
            detail = "; ".join(sorted({f"{peer}:{ip_iface}" for peer, ip_iface in peers}))
            issues.append(
                Issue(
                    code="switch_subnet_mismatch",
                    message=f"switch id={sid} has multiple IPv4 subnets on connected ifaces: {sorted(map(str, nets))}; {detail}",
                )
            )

    return issues


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate CORE scenario XML addressing invariants")
    parser.add_argument("xml_path", help="Path to CORE-exported scenario XML")
    args = parser.parse_args(argv)

    with open(args.xml_path, "rb") as f:
        data = f.read()

    issues = validate_scenario_xml(data)
    if not issues:
        print("OK: no issues found")
        return 0

    for issue in issues:
        print(f"{issue.code}: {issue.message}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

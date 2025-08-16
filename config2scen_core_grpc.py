#!/usr/bin/env python3
"""
auto-core.py — CORE 9.2.1 gRPC: build a star topology from an XML scenario

- Reads <Scenario>/<section name="Node Information"> for:
    - total_nodes="N"
    - multiple <item selected="Role" factor="f" />
- Assigns node roles proportionally to factors (Random bucket is distributed across other roles)
- Creates N DEFAULT hosts connected to a central SWITCH
- Ensures unique interface IDs on the switch side

Usage:
  python3 auto-core.py \
      --xml /path/to/sample.xml \
      --scenario ctf1 \
      --host 127.0.0.1 --port 50051 \
      --prefix 10.0.0.0/24 \
      [--max-nodes 100]
"""

from __future__ import annotations
from dataclasses import dataclass
import argparse
import math
import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple

from core.api.grpc import client
from core.api.grpc.wrappers import NodeType, Position, Interface


# ---------------- XML parsing ----------------

def _find_scenario(root: ET.Element, scenario_name: str | None) -> ET.Element | None:
    scenarios = root.findall(".//Scenario")
    if not scenarios:
        return None
    if scenario_name:
        for s in scenarios:
            if s.get("name") == scenario_name:
                return s
    return scenarios[0]


def parse_node_info(xml_path: str, scenario_name: str | None) -> Tuple[int, List[Tuple[str, float]]]:
    """
    Parse total_nodes and (role,factor) items under:
      <Scenario name="...">
        <ScenarioEditor>
          <section name="Node Information" total_nodes="...">
            <item selected="Server" factor="0.2" />
            <item selected="Workstation" factor="0.7" />
            <item selected="Random" factor="0.1" />
          </section>

    Returns:
      total_nodes (int), items [(role, factor_float), ...]
    """
    # Safe defaults
    default_count = 5
    default_items = [("Workstation", 1.0)]

    if not os.path.exists(xml_path):
        print(f"[warn] XML file not found: {xml_path}; defaulting total_nodes={default_count}, items={default_items}")
        return default_count, default_items

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        print(f"[warn] Failed to parse XML ({e}); defaulting values")
        return default_count, default_items

    scenario = _find_scenario(root, scenario_name)
    if scenario is None:
        print("[warn] No <Scenario> found; defaulting values")
        return default_count, default_items

    section = scenario.find(".//section[@name='Node Information']")
    if section is None:
        print("[warn] 'Node Information' section not found; defaulting values")
        return default_count, default_items

    # total_nodes
    total_str = section.get("total_nodes", "").strip()
    try:
        total = int(total_str)
        if total <= 0:
            raise ValueError
    except Exception:
        print(f"[warn] Invalid total_nodes='{total_str}'; defaulting to {default_count}")
        total = default_count

    # items
    items_el = section.findall("./item")
    parsed: List[Tuple[str, float]] = []
    for it in items_el:
        role = (it.get("selected") or "").strip()
        factor_str = (it.get("factor") or "").strip()
        if not role:
            continue
        try:
            factor = float(factor_str)
        except Exception:
            factor = 0.0
        if factor < 0:
            factor = 0.0
        parsed.append((role, factor))

    # If nothing valid, use default
    if not parsed:
        parsed = default_items

    return total, parsed


def compute_role_counts(total: int, role_factors: List[Tuple[str, float]]) -> Dict[str, int]:
    """
    Convert role factors into integer counts that sum to `total`.

    - Non-'Random' roles are allocated proportionally using floor + largest remainder.
    - The 'Random' bucket (if present) fills any remaining slots by distributing
      them *evenly* among the non-random roles.
    - If only 'Random' exists, everything becomes 'Workstation' (fallback).
    """
    non_random = [(r, f) for r, f in role_factors if r.lower() != "random"]
    random_factor = sum(f for r, f in role_factors if r.lower() == "random")

    if not non_random:
        # Only Random provided — pick a sensible default type
        return {"Workstation": total}

    # Proportional allocation for non-random roles using largest remainder
    exacts = [(r, f * total) for r, f in non_random]
    counts = {r: math.floor(x) for r, x in exacts}
    remaining = total - sum(counts.values())

    # Distribute by largest fractional remainder
    remainders = sorted(((r, x - math.floor(x)) for r, x in exacts),
                        key=lambda t: t[1], reverse=True)
    i = 0
    while remaining > 0 and i < len(remainders):
        r, _ = remainders[i]
        counts[r] += 1
        remaining -= 1
        i += 1

    # Let Random bucket fill any remaining seats evenly across non-random roles
    # (This implicitly uses the leftover from integer rounding; we don't separately round random_factor*total)
    remaining = total - sum(counts.values())
    if remaining > 0:
        labels = [r for r, _ in non_random]
        for j in range(remaining):
            counts[labels[j % len(labels)]] += 1

    return counts


# ---------------- CORE building ----------------

@dataclass
class NodeInfo:
    node_id: int
    ip4: str
    role: str


def _map_role_to_node_type(role: str) -> NodeType:
    """
    Map a role label from XML to a CORE NodeType.
    For most host roles (Server/Workstation/Client), DEFAULT is correct.
    """
    low = role.lower()
    if low in {"switch"}:
        return NodeType.SWITCH
    if low in {"hub"}:
        return NodeType.HUB
    if low in {"wlan", "wireless", "wireless_lan"}:
        return NodeType.WIRELESS_LAN
    # Servers/Workstations/Clients/etc. are DEFAULT hosts
    return NodeType.DEFAULT


def build_star_from_roles(core: client.CoreGrpcClient,
                          role_counts: Dict[str, int],
                          ip4_prefix: str = "10.0.0.0/24"):
    """
    Build a star with hosts created according to `role_counts` and a central SWITCH.

    Returns: (session, switch_node, [NodeInfo...])
    """
    iface_helper = client.InterfaceHelper(ip4_prefix=ip4_prefix)
    session = core.create_session()

    # Central switch at center (node id 1)
    cx, cy = 500, 400
    switch = session.add_node(1, _type=NodeType.SWITCH, position=Position(x=cx, y=cy))

    # Determine total number of hosts
    total_hosts = sum(role_counts.values())

    # Place hosts on a circle
    radius = 250
    node_infos: List[NodeInfo] = []

    # Create ordered list of (role, count) expanded to single roles for placement
    expanded_roles: List[str] = []
    for role, count in role_counts.items():
        expanded_roles.extend([role] * count)

    # Create hosts and link to switch
    sw_ifid = 0
    for idx, role in enumerate(expanded_roles):
        theta = (2 * math.pi * idx) / max(total_hosts, 1)
        x = int(cx + radius * math.cos(theta))
        y = int(cy + radius * math.sin(theta))

        node_id = idx + 2  # start after the switch
        node_type = _map_role_to_node_type(role)
        # Host node (even if role is 'Server'/'Workstation', it's a DEFAULT node type in CORE)
        node_name = f"{role.lower()}-{idx+1}"
        node = session.add_node(node_id, _type=node_type, position=Position(x=x, y=y), name=node_name)

        # Give host an interface/IP only if it's a host (DEFAULT). Switch/Hub/WLAN nodes don't need IPs.
        if node_type == NodeType.DEFAULT:
            host_iface = iface_helper.create_iface(node_id=node.id, iface_id=0, name="eth0")
            node_infos.append(NodeInfo(node_id=node.id,
                                       ip4=f"{host_iface.ip4}/{host_iface.ip4_mask}",
                                       role=role))
            # Link to switch with explicit ifaces at both ends
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}")
            sw_ifid += 1
            session.add_link(node1=node, node2=switch, iface1=host_iface, iface2=sw_iface)
        else:
            # Non-host roles (if present) still connect to the switch with a link (no IP on their side)
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}")
            sw_ifid += 1
            session.add_link(node1=node, node2=switch, iface2=sw_iface)

    core.start_session(session)
    return session, switch, node_infos


# ---------------- CLI ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xml", required=True, help="Path to XML scenario file")
    ap.add_argument("--scenario", default=None, help="Scenario name to use (defaults to first)")
    ap.add_argument("--host", default="127.0.0.1", help="core-daemon gRPC host")
    ap.add_argument("--port", type=int, default=50051, help="core-daemon gRPC port")
    ap.add_argument("--prefix", default="10.0.0.0/24", help="IPv4 prefix for auto-assigned addresses")
    ap.add_argument("--max-nodes", type=int, default=None,
                    help="Optional cap on hosts to create (useful for very large XMLs)")
    args = ap.parse_args()

    total, items = parse_node_info(args.xml, args.scenario)
    if args.max_nodes is not None and args.max_nodes > 0:
        total = min(total, args.max_nodes)

    role_counts = compute_role_counts(total, items)

    core = client.CoreGrpcClient(address=f"{args.host}:{args.port}")
    core.connect()  # ensure core-daemon is running with gRPC enabled

    session, switch, nodes = build_star_from_roles(core, role_counts, ip4_prefix=args.prefix)

    print(f"Started CORE session id: {session.id}")
    print(f"Switch node id: {switch.id}")
    print(f"Created {len(nodes)} nodes from XML")
    print("Role distribution:")
    for role, count in role_counts.items():
        print(f"  {role}: {count}")
    print("Hosts (DEFAULT type) with IPs:")
    for n in nodes:
        print(f"  node {n.node_id} ({n.role}) -> {n.ip4}")


if __name__ == "__main__":
    main()

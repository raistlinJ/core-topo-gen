#!/usr/bin/env python3
"""
auto-core.py — CORE 9.2.1 gRPC: build a star topology from an XML scenario

- Reads <Scenario name="...">/<section name="Node Information" total_nodes="N"> from an XML file
- Creates N DEFAULT nodes connected to a central SWITCH
- Ensures unique interface IDs on the switch side to avoid "interface(0) already exists"

Usage:
  python3 auto-core.py \
      --xml /path/to/sample.xml \
      --scenario ctf1 \
      --host 127.0.0.1 --port 50051 \
      --prefix 10.0.0.0/24
"""

from dataclasses import dataclass
import argparse
import math
import os
import xml.etree.ElementTree as ET

from core.api.grpc import client
from core.api.grpc.wrappers import NodeType, Position, Interface


# ---------------- XML parsing ----------------

def parse_total_nodes(xml_path: str, scenario_name: str | None) -> int:
    """
    Parse 'total_nodes' from:
      <Scenarios><Scenario name="..."><ScenarioEditor>
        <section name="Node Information" total_nodes="N">...</section>

    If scenario_name is None, use the first <Scenario>.
    Falls back to 5 if not found/invalid.
    """
    if not os.path.exists(xml_path):
        print(f"[warn] XML file not found: {xml_path}; defaulting total_nodes=5")
        return 5

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        print(f"[warn] Failed to parse XML ({e}); defaulting total_nodes=5")
        return 5

    scenarios = root.findall(".//Scenario")
    if not scenarios:
        print("[warn] No <Scenario> elements found; defaulting total_nodes=5")
        return 5

    target = None
    if scenario_name:
        for s in scenarios:
            if s.get("name") == scenario_name:
                target = s
                break
        if target is None:
            print(f"[warn] Scenario name '{scenario_name}' not found; using first scenario.")
            target = scenarios[0]
    else:
        target = scenarios[0]

    # Find the "Node Information" section under this scenario
    section = target.find(".//section[@name='Node Information']")
    if section is None:
        print("[warn] 'Node Information' section not found; defaulting total_nodes=5")
        return 5

    total_nodes_str = section.get("total_nodes")
    try:
        n = int(total_nodes_str)
        if n <= 0:
            raise ValueError
        return n
    except Exception:
        print(f"[warn] Invalid total_nodes='{total_nodes_str}'; defaulting total_nodes=5")
        return 5


# ---------------- CORE building ----------------

@dataclass
class NodeInfo:
    node_id: int
    ip4: str


def build_star_from_count(core: client.CoreGrpcClient, count: int, ip4_prefix: str = "10.0.0.0/24"):
    """
    Build a star with `count` hosts connected to a central switch.

    Returns: (session, switch_node, [NodeInfo...])
    """
    iface_helper = client.InterfaceHelper(ip4_prefix=ip4_prefix)
    session = core.create_session()

    # Place switch at center; node id 1
    cx, cy = 500, 400
    switch = session.add_node(1, _type=NodeType.SWITCH, position=Position(x=cx, y=cy))

    node_infos: list[NodeInfo] = []

    radius = 250
    sw_ifid = 0  # unique iface ids on switch side

    for i in range(count):
        theta = (2 * math.pi * i) / max(count, 1)
        x = int(cx + radius * math.cos(theta))
        y = int(cy + radius * math.sin(theta))

        node_id = i + 2  # start after the switch
        node = session.add_node(node_id, _type=NodeType.DEFAULT, position=Position(x=x, y=y))

        # Host side interface with IP
        host_iface = iface_helper.create_iface(node_id=node.id, iface_id=0, name="eth0")

        # Switch side interface: unique ID, no IP
        sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}")
        sw_ifid += 1

        # Link host <-> switch
        session.add_link(node1=node, node2=switch, iface1=host_iface, iface2=sw_iface)

        node_infos.append(NodeInfo(node_id=node.id, ip4=f"{host_iface.ip4}/{host_iface.ip4_mask}"))

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

    total = parse_total_nodes(args.xml, args.scenario)
    if args.max_nodes is not None and args.max_nodes > 0:
        total = min(total, args.max_nodes)

    core = client.CoreGrpcClient(address=f"{args.host}:{args.port}")
    core.connect()  # ensure core-daemon is running with gRPC enabled

    session, switch, nodes = build_star_from_count(core, total, ip4_prefix=args.prefix)

    print(f"Started CORE session id: {session.id}")
    print(f"Switch node id: {switch.id}")
    print(f"Created {len(nodes)} hosts from XML (requested {total})")
    for n in nodes:
        print(f"  node {n.node_id}: {n.ip4}")


if __name__ == "__main__":
    main()

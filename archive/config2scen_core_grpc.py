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
import random
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
import ipaddress

from core.api.grpc import client
from core.api.grpc.wrappers import NodeType, Position, Interface

# module logger
logger = logging.getLogger(__name__)


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


@dataclass
class ServiceInfo:
    name: str
    factor: float  # Distribution across selected nodes
    density: float  # Distribution across entire scenario

@dataclass
class RoutingInfo:
    protocol: str
    factor: float

# Routing protocol services that require zebra base service
ROUTING_STACK_SERVICES = {
    "BGP",
    "Babel",
    "OSPFv2",
    "OSPFv3",
    "OSPFv3MDR",
    "RIP",
    "RIPNG",
    "Xpimd",
}

def parse_routing_info(xml_path: str, scenario_name: str | None) -> Tuple[float, List[RoutingInfo]]:
    """
    Parse the Routing section:
      <section name="Routing" density="0.5">
        <item selected="OSPFv2" factor="1.0" />
      </section>

    Returns: (routing_density, [RoutingInfo...])
    """
    density = 0.0
    items: List[RoutingInfo] = []

    if not os.path.exists(xml_path):
        logger.warning("XML not found for routing parse: %s", xml_path)
        return density, items

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML for routing (%s)", e)
        return density, items

    scenario = _find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found for routing parse")
        return density, items

    section = scenario.find(".//section[@name='Routing']")
    if section is None:
        return density, items

    den_raw = (section.get("density") or "").strip()
    if den_raw:
        try:
            density = float(den_raw)
            if density < 0:
                density = 0.0
            if density > 1:
                density = 1.0
        except Exception:
            logger.warning("Invalid Routing density '%s'", den_raw)
            density = 0.0

    for it in section.findall("./item"):
        proto = (it.get("selected") or "").strip()
        if not proto:
            continue
        try:
            factor = float((it.get("factor") or "0").strip())
        except Exception:
            factor = 0.0
        if factor > 0:
            items.append(RoutingInfo(protocol=proto, factor=factor))

    logger.debug("Parsed routing: density=%s items=%s", density, [(i.protocol, i.factor) for i in items])
    return density, items

def parse_services(scenario: ET.Element) -> List[ServiceInfo]:
    """
    Parse services under:
      <Scenario>
        <Services>
          <Service selected="HTTP" factor="0.5" density="0.3" />
    """
    services: List[ServiceInfo] = []

    # Prefer ScenarioEditor section style: <section name="Services" density="..."><item .../></section>
    section = scenario.find(".//section[@name='Services']")
    if section is not None:
        den_section_raw = (section.get("density") or "").strip()
        if not den_section_raw:
            logger.warning("'Services' section missing 'density'; no services will be assigned from this section")
        try:
            section_density = float(den_section_raw) if den_section_raw else 0.0
        except Exception:
            logger.warning("'Services' section has invalid 'density' value '%s'", den_section_raw)
            section_density = 0.0
        for it in section.findall("./item"):
            name = (it.get("selected") or "").strip()
            if not name:
                continue
            try:
                factor = float((it.get("factor") or "0").strip())
            except Exception:
                factor = 0.0
            # If an item-level density is present, ignore it and warn
            if it.get("density"):
                logger.warning("Ignoring item-level 'density' for service '%s'; using section-level density", name)
            if factor > 0 and section_density > 0:
                services.append(ServiceInfo(name=name, factor=factor, density=section_density))
                logger.debug(
                    "Parsed service (section/item): name=%s factor=%s density=%s",
                    name, factor, section_density,
                )

    # No legacy fallback parsing; density must be defined at the Services section level

    return services

def parse_node_info(xml_path: str, scenario_name: str | None) -> Tuple[int, List[Tuple[str, float]], List[ServiceInfo]]:
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
      total_nodes (int), items [(role, factor_float), ...], services [ServiceInfo, ...]
    """
    # Safe defaults
    default_count = 5
    default_items = [("Workstation", 1.0)]

    if not os.path.exists(xml_path):
        logger.warning(
            "XML file not found: %s; defaulting total_nodes=%s, items=%s",
            xml_path, default_count, default_items,
        )
        return default_count, default_items, []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML (%s); defaulting values", e)
        return default_count, default_items, []

    scenario = _find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found; defaulting values")
        return default_count, default_items, []

    section = scenario.find(".//section[@name='Node Information']")
    if section is None:
        logger.warning("'Node Information' section not found; defaulting values")
        return default_count, default_items, []

    # total_nodes
    total_str = section.get("total_nodes", "").strip()
    try:
        total = int(total_str)
        if total <= 0:
            raise ValueError
    except Exception:
        logger.warning("Invalid total_nodes='%s'; defaulting to %s", total_str, default_count)
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

    # Parse services
    services = []
    if scenario is not None:
        services = parse_services(scenario)

    return total, parsed, services


def compute_role_counts(total: int, role_factors: List[Tuple[str, float]]) -> Dict[str, int]:
    """
    Convert role factors into integer counts that sum to `total`.

    - Non-'Random' roles are allocated proportionally using floor + largest remainder.
    - The 'Random' bucket (if present) fills any remaining slots by distributing
      them *evenly* among the non-random roles.
    - If only 'Random' exists, everything becomes 'Workstation' (fallback).
    """
    logger.debug("Computing role counts: total=%s role_factors=%s", total, role_factors)
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

    logger.debug("Computed role counts -> %s", counts)
    return counts


# ---------------- CORE building ----------------

@dataclass
class NodeInfo:
    node_id: int
    ip4: str
    role: str


class UniqueAllocator:
    """
    Allocate unique IPv4 addresses and MAC addresses across a session.
    - IPv4s are allocated sequentially from the provided prefix; if exhausted,
      move to the next contiguous subnet with the same prefix length.
    - MACs are locally administered (02:xx:xx:xx:xx:xx) and increment per call.
    """
    def __init__(self, ip4_prefix: str):
        self.net = ipaddress.IPv4Network(ip4_prefix, strict=False)
        # start with first usable host IP
        self.host_offset = 1
        self.mac_counter = 1

    def next_ip(self) -> Tuple[str, int]:
        # if we hit or exceed broadcast, advance to next network
        if int(self.net.network_address) + self.host_offset >= int(self.net.broadcast_address):
            base = int(self.net.network_address) + self.net.num_addresses
            self.net = ipaddress.IPv4Network((ipaddress.IPv4Address(base), self.net.prefixlen))
            self.host_offset = 1
        ip_int = int(self.net.network_address) + self.host_offset
        self.host_offset += 1
        ip = str(ipaddress.IPv4Address(ip_int))
        return ip, self.net.prefixlen

    def next_mac(self) -> str:
        n = self.mac_counter
        self.mac_counter += 1
        # construct 6 bytes: 0x02 (locally administered) + 5 bytes of counter
        b5 = [
            (n >> 32) & 0xFF,
            (n >> 24) & 0xFF,
            (n >> 16) & 0xFF,
            (n >> 8) & 0xFF,
            n & 0xFF,
        ]
        return "02:" + ":".join(f"{x:02x}" for x in b5)


class SubnetAllocator:
    """
    Allocate non-overlapping IPv4 subnets from a base network. Supports
    different requested prefix lengths by aligning to the next suitable boundary.
    """
    def __init__(self, ip4_prefix: str):
        self.base = ipaddress.IPv4Network(ip4_prefix, strict=False)
        self.next_addr = int(self.base.network_address)
        # track allocated subnets as tuples of (network_int, prefixlen)
        self._allocated: set[tuple[int, int]] = set()

    def next_subnet(self, prefixlen: int) -> ipaddress.IPv4Network:
        size = 1 << (32 - prefixlen)
        # align next_addr to prefix boundary
        aligned = (self.next_addr + size - 1) // size * size
        net = ipaddress.IPv4Network((ipaddress.IPv4Address(aligned), prefixlen))
        self.next_addr = aligned + size
        # record allocation
        self._allocated.add((int(net.network_address), prefixlen))
        return net

    def next_random_subnet(self, prefixlen: int, attempts: int = 256) -> ipaddress.IPv4Network:
        """
        Pick a random subnet of the requested size inside the base prefix,
        avoiding overlaps with previously allocated subnets. If we fail to
        find an unused subnet in the base after a number of attempts (or the
        base cannot fit more), fall back to sequential allocation which can
        progress beyond the base if needed.
        """
        size = 1 << (32 - prefixlen)
        base_size = self.base.num_addresses
        # number of subnets of given size within base (floor)
        total_slots = base_size // size if base_size >= size else 0

        if total_slots > 0:
            base_start = int(self.base.network_address)
            # quick stop if we've already allocated all possible inside base
            if sum(1 for k in self._allocated if k[1] == prefixlen and base_start <= k[0] < base_start + base_size) >= total_slots:
                # exhausted base pool, fall back
                net = self.next_subnet(prefixlen)
                return net
            for _ in range(max(8, attempts)):
                slot = random.randrange(0, total_slots)
                cand = base_start + slot * size
                key = (cand, prefixlen)
                if key in self._allocated:
                    continue
                try:
                    net = ipaddress.IPv4Network((ipaddress.IPv4Address(cand), prefixlen))
                except Exception:
                    continue
                # ensure it's within base
                if (int(net.network_address) < base_start) or (int(net.broadcast_address) >= base_start + base_size):
                    continue
                self._allocated.add(key)
                return net
        # fallback to sequential (may move beyond base)
        net = self.next_subnet(prefixlen)
        return net


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

def _compute_counts_by_factor(total: int, items: List[Tuple[str, float]]) -> Dict[str, int]:
    """Helper: largest remainder allocation for names with factors summing arbitrarily."""
    if total <= 0 or not items:
        return {}
    exacts = [(name, f * total) for name, f in items]
    counts = {name: math.floor(x) for name, x in exacts}
    remaining = total - sum(counts.values())
    remainders = sorted(((name, x - math.floor(x)) for name, x in exacts), key=lambda t: t[1], reverse=True)
    i = 0
    while remaining > 0 and i < len(remainders):
        name, _ = remainders[i]
        counts[name] += 1
        remaining -= 1
        i += 1
    return counts


def distribute_services(nodes: List[NodeInfo], services: List[ServiceInfo]) -> Dict[int, List[str]]:
    """
    Distribute services across nodes based on factor and density attributes.
    Returns a mapping of node_id -> list of service names to apply.
    Each service will be assigned at most once to any given node.
    """
    node_services: Dict[int, List[str]] = {}
    
    # Filter out non-host nodes and routers (they don't get services)
    host_nodes = [
        n for n in nodes
        if _map_role_to_node_type(n.role) == NodeType.DEFAULT and "router" not in n.role.lower()
    ]
    if not host_nodes:
        return node_services
        
    for service in services:
        # Calculate how many nodes should get this service based on density
        total_service_nodes = max(1, math.floor(len(host_nodes) * service.density))
        logger.debug(
            "Distributing service '%s': host_nodes=%s density=%s -> target_nodes=%s",
            service.name, len(host_nodes), service.density, total_service_nodes,
        )

        # Only include nodes that don't already have this service
        eligible_nodes = [
            node for node in host_nodes
            if node.node_id not in node_services or service.name not in node_services[node.node_id]
        ]
        if not eligible_nodes:
            logger.debug("No eligible nodes for service '%s'", service.name)
            continue

        # Shuffle for fairness
        random.shuffle(eligible_nodes)

        # Preselect nodes with probability = factor
        preselected = [n for n in eligible_nodes if random.random() < service.factor]
        if len(preselected) > total_service_nodes:
            selected_nodes = preselected[:total_service_nodes]
        else:
            # Fill remaining from the rest deterministically (already shuffled)
            remaining_needed = total_service_nodes - len(preselected)
            remainder = [n for n in eligible_nodes if n not in preselected]
            selected_nodes = preselected + remainder[:remaining_needed]

        logger.debug(
            "Selected nodes for service '%s': %s",
            service.name, [n.node_id for n in selected_nodes],
        )

        # Assign service to selected nodes (unique per node)
        for node in selected_nodes:
            if node.node_id not in node_services:
                node_services[node.node_id] = []
            node_services[node.node_id].append(service.name)
    
    return node_services

def build_star_from_roles(core: client.CoreGrpcClient,
                          role_counts: Dict[str, int],
                          services: Optional[List[ServiceInfo]] = None,
                          ip4_prefix: str = "10.0.0.0/24"):
    """
    Build a star with hosts created according to `role_counts` and a central SWITCH.

    Returns: (session, switch_node, [NodeInfo...])
    """
    logger.info("Creating CORE session and building star topology")
    # allocate MACs; IPs come from subnets per link/segment
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = SubnetAllocator(ip4_prefix)
    session = core.create_session()

    # Central switch at center (node id 1)
    cx, cy = 500, 400
    switch = session.add_node(1, _type=NodeType.SWITCH, position=Position(x=cx, y=cy))
    logger.debug("Added central switch node id=%s at (%s,%s)", switch.id, cx, cy)

    # Determine total number of hosts
    total_hosts = sum(role_counts.values())

    # Place hosts on a circle
    radius = 250
    node_infos: List[NodeInfo] = []

    # Create ordered list of (role, count) expanded to single roles for placement
    expanded_roles: List[str] = []
    for role, count in role_counts.items():
        expanded_roles.extend([role] * count)
    logger.debug("Expanded roles for placement: %s", expanded_roles)

    # Create hosts and link to switch
    sw_ifid = 0
    nodes_by_id: Dict[int, object] = {}
    for idx, role in enumerate(expanded_roles):
        theta = (2 * math.pi * idx) / max(total_hosts, 1)
        x = int(cx + radius * math.cos(theta))
        y = int(cy + radius * math.sin(theta))

        node_id = idx + 2  # start after the switch
        node_type = _map_role_to_node_type(role)
        # Host node (even if role is 'Server'/'Workstation', it's a DEFAULT node type in CORE)
        node_name = f"{role.lower()}-{idx+1}"
        node = session.add_node(node_id, _type=node_type, position=Position(x=x, y=y), name=node_name)
        nodes_by_id[node.id] = node
        logger.debug("Added node id=%s name=%s type=%s at (%s,%s)", node.id, node_name, node_type, x, y)

        # Give host an interface/IP only if it's a host (DEFAULT). Switch/Hub/WLAN nodes don't need IPs.
        if node_type == NodeType.DEFAULT:
            host_ip, host_mask = mac_alloc.next_ip()
            host_mac = mac_alloc.next_mac()
            host_iface = Interface(id=0, name="eth0", ip4=host_ip, ip4_mask=host_mask, mac=host_mac)
            node_infos.append(NodeInfo(node_id=node.id,
                                       ip4=f"{host_ip}/{host_mask}",
                                       role=role))
            # Link to switch with explicit ifaces at both ends
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}", mac=mac_alloc.next_mac())
            sw_ifid += 1
            session.add_link(node1=node, node2=switch, iface1=host_iface, iface2=sw_iface)
            logger.debug("Linked host node %s <-> switch (sw_ifid=%s)", node.id, sw_ifid - 1)
        else:
            # Non-host roles (if present) still connect to the switch with a link (no IP on their side)
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}", mac=mac_alloc.next_mac())
            sw_ifid += 1
            session.add_link(node1=node, node2=switch, iface2=sw_iface)
            logger.debug("Linked non-host node %s <-> switch (sw_ifid=%s)", node.id, sw_ifid - 1)

    # Apply services if provided
    service_assignments: Dict[int, List[str]] = {}
    if services:
        service_assignments = distribute_services(node_infos, services)
        for node_id, service_list in service_assignments.items():
            for service_name in service_list:
                logger.debug("Assigning service '%s' to node %s", service_name, node_id)
                assigned = False
                # Try session-level API first
                try:
                    if hasattr(session, "add_service"):
                        session.add_service(node_id=node_id, service_name=service_name)
                        assigned = True
                except Exception as e:
                    logger.debug("session.add_service failed for node %s service %s: %s", node_id, service_name, e)

                # Try session.services.add helper
                if not assigned:
                    try:
                        if hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, service_name)
                            except TypeError:
                                # some versions may expect a node object
                                node_obj_try = nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, service_name)
                                else:
                                    raise
                            assigned = True
                    except Exception as e:
                        logger.debug("session.services.add failed for node %s service %s: %s", node_id, service_name, e)

                if not assigned:
                    node_obj = nodes_by_id.get(node_id)
                    if node_obj is None:
                        logger.warning("No node object found for node_id=%s to assign service '%s'", node_id, service_name)
                    else:
                        # Try common wrapper patterns
                        try:
                            if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                                node_obj.services.add(service_name)
                                assigned = True
                            elif hasattr(node_obj, "add_service"):
                                node_obj.add_service(service_name)
                                assigned = True
                        except Exception as e:
                            logger.warning("Failed to assign service '%s' to node %s: %s", service_name, node_id, e)

                if assigned:
                    logger.debug("Service '%s' assigned to node %s", service_name, node_id)
                else:
                    logger.warning("Service '%s' could not be assigned to node %s", service_name, node_id)

                # If a routing protocol service was assigned, also assign zebra
                if assigned and service_name in ROUTING_STACK_SERVICES:
                    zebra_assigned = False
                    try:
                        if hasattr(session, "add_service"):
                            session.add_service(node_id=node_id, service_name="zebra")
                            zebra_assigned = True
                    except Exception as e:
                        logger.debug("session.add_service failed for zebra on node %s: %s", node_id, e)
                    if not zebra_assigned:
                        try:
                            if hasattr(session, "services") and hasattr(session.services, "add"):
                                try:
                                    session.services.add(node_id, "zebra")
                                except TypeError:
                                    node_obj_try = nodes_by_id.get(node_id)
                                    if node_obj_try is not None:
                                        session.services.add(node_obj_try, "zebra")
                                    else:
                                        raise
                                zebra_assigned = True
                        except Exception as e:
                            logger.debug("session.services.add failed for zebra on node %s: %s", node_id, e)
                    if not zebra_assigned:
                        node_obj = nodes_by_id.get(node_id)
                        if node_obj is not None:
                            try:
                                if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                                    node_obj.services.add("zebra")
                                    zebra_assigned = True
                                elif hasattr(node_obj, "add_service"):
                                    node_obj.add_service("zebra")
                                    zebra_assigned = True
                            except Exception as e:
                                logger.debug("Node-level add zebra failed %s: %s", node_id, e)
                    if zebra_assigned:
                        # reflect in service_assignments mapping
                        svc_list = service_assignments.setdefault(node_id, [])
                        if "zebra" not in svc_list:
                            svc_list.append("zebra")
                        logger.debug("Assigned 'zebra' to node %s due to routing protocol '%s'", node_id, service_name)
    
    core.start_session(session)
    logger.info("Started CORE session id=%s with %s nodes (plus switch)", session.id, len(node_infos))
    return session, switch, node_infos, service_assignments


def build_segmented_topology(core: client.CoreGrpcClient,
                             role_counts: Dict[str, int],
                             routing_density: float,
                             routing_items: List[RoutingInfo],
                             services: Optional[List[ServiceInfo]] = None,
                             ip4_prefix: str = "10.0.0.0/24"):
    """
    Build a segmented topology using routers based on routing_density.
    - Creates R = floor(total_hosts * routing_density) routers (min 1 if density>0)
    - Distributes hosts across routers as segments and links hosts directly to routers
    - Connects routers in a ring to avoid a central star
    - Assigns routing protocols to routers per factors

    Returns: (session, routers: List[NodeInfo], hosts: List[NodeInfo], host_service_assignments: Dict[int, List[str]], router_protocols: Dict[int, List[str]])
    """
    logger.info("Creating CORE session and building segmented topology with routers")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = SubnetAllocator(ip4_prefix)
    session = core.create_session()

    # Create host nodes according to role_counts first (to know total)
    total_hosts = sum(role_counts.values())
    if routing_density <= 0 or total_hosts == 0:
        logger.warning("Routing density <= 0 or no hosts; falling back to star")
        session, switch, nodes, svc = build_star_from_roles(core, role_counts, services=services, ip4_prefix=ip4_prefix)
        return session, [], nodes, svc, {}

    router_count = max(1, min(total_hosts, math.floor(total_hosts * routing_density)))
    logger.debug("Router count computed: %s (density=%s, total_hosts=%s)", router_count, routing_density, total_hosts)

    # Place routers in a large circle
    cx, cy = 600, 500
    router_radius = 300
    host_radius = 120

    routers: List[NodeInfo] = []
    router_nodes: Dict[int, object] = {}
    host_nodes_by_id: Dict[int, object] = {}
    # Track next interface id per router to ensure unique iface ids/names
    router_next_ifid: Dict[int, int] = {}

    for i in range(router_count):
        theta = (2 * math.pi * i) / router_count
        x = int(cx + router_radius * math.cos(theta))
        y = int(cy + router_radius * math.sin(theta))
        node_id = i + 1  # start ids at 1 for routers
        node = session.add_node(node_id, _type=NodeType.DEFAULT, position=Position(x=x, y=y), name=f"router-{i+1}")
        routers.append(NodeInfo(node_id=node.id, ip4="", role="Router"))
        router_nodes[node.id] = node
        logger.debug("Added router id=%s at (%s,%s)", node.id, x, y)

    # Connect routers in a ring; special-case 2 routers to avoid duplicate link
    if router_count > 1:
        link_pairs = []
        if router_count == 2:
            link_pairs = [(1, 2)]
        else:
            link_pairs = [(i + 1, (i + 1) % router_count + 1) for i in range(router_count)]
        for aid, bid in link_pairs:
            a = router_nodes[aid]
            b = router_nodes[bid]
            # allocate unique iface ids per router and unique names per link end
            a_ifid = router_next_ifid.get(a.id, 0)
            b_ifid = router_next_ifid.get(b.id, 0)
            router_next_ifid[a.id] = a_ifid + 1
            router_next_ifid[b.id] = b_ifid + 1
            # allocate a unique /30 per router-router link
            rr_net = subnet_alloc.next_random_subnet(30)
            rr_hosts = list(rr_net.hosts())
            a_ip = str(rr_hosts[0])
            b_ip = str(rr_hosts[1])
            a_if = Interface(id=a_ifid, name=f"r{a.id}-to-r{b.id}", ip4=a_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
            b_if = Interface(id=b_ifid, name=f"r{b.id}-to-r{a.id}", ip4=b_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
            session.add_link(node1=a, node2=b, iface1=a_if, iface2=b_if)
            logger.debug("Linked router %s <-> router %s", a.id, b.id)

    # Expand roles to host list for placement and assignment
    expanded_roles: List[str] = []
    for role, count in role_counts.items():
        expanded_roles.extend([role] * count)

    # Shuffle hosts for more even distribution
    random.shuffle(expanded_roles)

    # Bucket hosts by router
    buckets: List[List[str]] = [[] for _ in range(router_count)]
    for idx, role in enumerate(expanded_roles):
        buckets[idx % router_count].append(role)

    # Create host nodes around each router and link to router
    hosts: List[NodeInfo] = []
    node_id_counter = router_count + 1
    for ridx, roles in enumerate(buckets):
        rx = int(cx + router_radius * math.cos((2 * math.pi * ridx) / router_count))
        ry = int(cy + router_radius * math.sin((2 * math.pi * ridx) / router_count))
        router_node = router_nodes[ridx + 1]
        if len(roles) == 0:
            continue
        elif len(roles) == 1:
            # create a p2p /30 between router and single host
            role = roles[0]
            theta = 0
            x = int(rx + host_radius * math.cos(theta))
            y = int(ry + host_radius * math.sin(theta))
            node_type = _map_role_to_node_type(role)
            name = f"{role.lower()}-{ridx+1}-1"
            host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
            node_id_counter += 1
            host_nodes_by_id[host.id] = host

            # allocate subnet and IPs
            lan_net = subnet_alloc.next_random_subnet(30)
            lan_hosts = list(lan_net.hosts())
            r_ip = str(lan_hosts[0])
            h_ip = str(lan_hosts[1])
            h_mac = mac_alloc.next_mac()
            host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=h_mac)

            r_ifid = router_next_ifid.get(router_node.id, 0)
            router_next_ifid[router_node.id] = r_ifid + 1
            r_if = Interface(id=r_ifid, name=f"r{router_node.id}-h{host.id}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
            session.add_link(node1=host, node2=router_node, iface1=host_if, iface2=r_if)

            if node_type == NodeType.DEFAULT:
                hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
            logger.debug("Added host id=%s role=%s p2p to router %s", host.id, role, router_node.id)
        else:
            # multi-host LAN: create a switch, one router iface, multiple host links
            lan_switch = session.add_node(node_id_counter, _type=NodeType.SWITCH, position=Position(x=rx+40, y=ry+40), name=f"lan-{ridx+1}")
            node_id_counter += 1
            # allocate LAN subnet /24 (random within base)
            lan_net = subnet_alloc.next_random_subnet(24)
            lan_hosts = list(lan_net.hosts())
            # router IP is first usable
            r_ip = str(lan_hosts[0])
            r_ifid = router_next_ifid.get(router_node.id, 0)
            router_next_ifid[router_node.id] = r_ifid + 1
            r_if = Interface(id=r_ifid, name=f"r{router_node.id}-lan{ridx+1}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
            sw_if = Interface(id=0, name=f"lan{ridx+1}-r")
            session.add_link(node1=router_node, node2=lan_switch, iface1=r_if, iface2=sw_if)
            logger.debug("Linked router %s to LAN switch %s on %s/%s", router_node.id, lan_switch.id, r_ip, lan_net.prefixlen)

            # assign hosts IPs starting from second usable
            ip_index = 1
            for j, role in enumerate(roles):
                theta = (2 * math.pi * j) / len(roles)
                x = int(rx + host_radius * math.cos(theta))
                y = int(ry + host_radius * math.sin(theta))
                node_type = _map_role_to_node_type(role)
                name = f"{role.lower()}-{ridx+1}-{j+1}"
                host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
                node_id_counter += 1
                host_nodes_by_id[host.id] = host

                h_ip = str(lan_hosts[ip_index])
                ip_index += 1
                h_mac = mac_alloc.next_mac()
                host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=h_mac)
                sw_if = Interface(id=j+1, name=f"lan{ridx+1}-h{host.id}")
                session.add_link(node1=host, node2=lan_switch, iface1=host_if, iface2=sw_if)

                if node_type == NodeType.DEFAULT:
                    hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
                logger.debug("Added host id=%s role=%s to LAN switch %s", host.id, role, lan_switch.id)

    # Assign routing protocols to routers per factors
    router_protocols: Dict[int, List[str]] = {r.node_id: [] for r in routers}
    if routing_items:
        proto_items = [(ri.protocol, ri.factor) for ri in routing_items]
        counts = _compute_counts_by_factor(router_count, proto_items)
        # Create list of protocols to assign across routers
        expanded_protocols: List[str] = []
        for proto, c in counts.items():
            expanded_protocols.extend([proto] * c)
        # pad if fewer than routers
        while len(expanded_protocols) < router_count and proto_items:
            expanded_protocols.append(proto_items[0][0])
        # assign round-robin
        for i, rid in enumerate(sorted(router_nodes.keys())):
            if i < len(expanded_protocols):
                proto = expanded_protocols[i]
                router_protocols[rid].append(proto)
                assigned = False
                try:
                    if hasattr(session, "add_service"):
                        session.add_service(node_id=rid, service_name=proto)
                        assigned = True
                except Exception as e:
                    logger.debug("session.add_service failed for router %s service %s: %s", rid, proto, e)
                if not assigned:
                    try:
                        if hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(rid, proto)
                            except TypeError:
                                node_obj_try = router_nodes.get(rid)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, proto)
                                else:
                                    raise
                            assigned = True
                    except Exception as e:
                        logger.debug("session.services.add failed for router %s service %s: %s", rid, proto, e)
                if not assigned:
                    node_obj = router_nodes.get(rid)
                    if node_obj is not None:
                        try:
                            if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                                node_obj.services.add(proto)
                                assigned = True
                            elif hasattr(node_obj, "add_service"):
                                node_obj.add_service(proto)
                                assigned = True
                        except Exception as e:
                            logger.debug("Router node-level add service failed %s -> %s: %s", rid, proto, e)
                if not assigned:
                    logger.warning("Routing protocol '%s' could not be assigned to router %s", proto, rid)
                else:
                    logger.debug("Assigned routing protocol '%s' to router %s", proto, rid)

                # If a routing protocol was assigned, also assign zebra to the router
                if assigned and proto in ROUTING_STACK_SERVICES:
                    zebra_assigned = False
                    try:
                        if hasattr(session, "add_service"):
                            session.add_service(node_id=rid, service_name="zebra")
                            zebra_assigned = True
                    except Exception as e:
                        logger.debug("session.add_service failed for zebra on router %s: %s", rid, e)
                    if not zebra_assigned:
                        try:
                            if hasattr(session, "services") and hasattr(session.services, "add"):
                                try:
                                    session.services.add(rid, "zebra")
                                except TypeError:
                                    node_obj_try = router_nodes.get(rid)
                                    if node_obj_try is not None:
                                        session.services.add(node_obj_try, "zebra")
                                    else:
                                        raise
                                zebra_assigned = True
                        except Exception as e:
                            logger.debug("session.services.add failed for zebra on router %s: %s", rid, e)
                    if not zebra_assigned:
                        node_obj = router_nodes.get(rid)
                        if node_obj is not None:
                            try:
                                if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                                    node_obj.services.add("zebra")
                                    zebra_assigned = True
                                elif hasattr(node_obj, "add_service"):
                                    node_obj.add_service("zebra")
                                    zebra_assigned = True
                            except Exception as e:
                                logger.debug("Router node-level add zebra failed %s: %s", rid, e)
                    if zebra_assigned:
                        logger.debug("Assigned 'zebra' to router %s due to routing protocol '%s'", rid, proto)

    # Assign host services (from Services section) if any
    host_service_assignments: Dict[int, List[str]] = {}
    if services:
        host_service_assignments = distribute_services(hosts, services)
        for node_id, svc_list in host_service_assignments.items():
            for svc in svc_list:
                assigned = False
                try:
                    if hasattr(session, "add_service"):
                        session.add_service(node_id=node_id, service_name=svc)
                        assigned = True
                except Exception as e:
                    logger.debug("session.add_service failed for host %s service %s: %s", node_id, svc, e)
                if not assigned:
                    try:
                        if hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, svc)
                            except TypeError:
                                node_obj_try = host_nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, svc)
                                else:
                                    raise
                            assigned = True
                    except Exception as e:
                        logger.debug("session.services.add failed for host %s service %s: %s", node_id, svc, e)
                if not assigned:
                    node_obj = host_nodes_by_id.get(node_id)
                    if node_obj is not None:
                        try:
                            if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                                node_obj.services.add(svc)
                                assigned = True
                            elif hasattr(node_obj, "add_service"):
                                node_obj.add_service(svc)
                                assigned = True
                        except Exception as e:
                            logger.debug("Host node-level add service failed %s -> %s: %s", node_id, svc, e)
                if not assigned:
                    logger.warning("Service '%s' could not be assigned to host node %s", svc, node_id)
                # If a routing protocol service was assigned to a host, also assign zebra
                if assigned and svc in ROUTING_STACK_SERVICES:
                    zebra_assigned = False
                    try:
                        if hasattr(session, "add_service"):
                            session.add_service(node_id=node_id, service_name="zebra")
                            zebra_assigned = True
                    except Exception as e:
                        logger.debug("session.add_service failed for zebra on host %s: %s", node_id, e)
                    if not zebra_assigned:
                        try:
                            if hasattr(session, "services") and hasattr(session.services, "add"):
                                try:
                                    session.services.add(node_id, "zebra")
                                except TypeError:
                                    node_obj_try = host_nodes_by_id.get(node_id)
                                    if node_obj_try is not None:
                                        session.services.add(node_obj_try, "zebra")
                                    else:
                                        raise
                                zebra_assigned = True
                        except Exception as e:
                            logger.debug("session.services.add failed for zebra on host %s: %s", node_id, e)
                    if not zebra_assigned:
                        node_obj = host_nodes_by_id.get(node_id)
                        if node_obj is not None:
                            try:
                                if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                                    node_obj.services.add("zebra")
                                    zebra_assigned = True
                                elif hasattr(node_obj, "add_service"):
                                    node_obj.add_service("zebra")
                                    zebra_assigned = True
                            except Exception as e:
                                logger.debug("Host node-level add zebra failed %s: %s", node_id, e)
                    if zebra_assigned:
                        lst = host_service_assignments.setdefault(node_id, [])
                        if "zebra" not in lst:
                            lst.append("zebra")
                        logger.debug("Assigned 'zebra' to host %s due to routing protocol '%s'", node_id, svc)

    core.start_session(session)
    logger.info("Started CORE session id=%s with %s routers and %s hosts", session.id, len(routers), len(hosts))
    return session, routers, hosts, host_service_assignments, router_protocols


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
    ap.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = ap.parse_args()

    # logging setup
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    total, items, services = parse_node_info(args.xml, args.scenario)
    if args.max_nodes is not None and args.max_nodes > 0:
        total = min(total, args.max_nodes)

    role_counts = compute_role_counts(total, items)

    # routing parse
    routing_density, routing_items = parse_routing_info(args.xml, args.scenario)

    core = client.CoreGrpcClient(address=f"{args.host}:{args.port}")
    core.connect()  # ensure core-daemon is running with gRPC enabled

    # Choose builder based on routing density
    if routing_density and routing_density > 0:
        session, routers, hosts, service_assignments, router_protocols = build_segmented_topology(
            core,
            role_counts,
            routing_density=routing_density,
            routing_items=routing_items,
            services=services,
            ip4_prefix=args.prefix,
        )
    else:
        session, switch, hosts, service_assignments = build_star_from_roles(
            core,
            role_counts,
            services=services,
            ip4_prefix=args.prefix,
        )

    logger.info("Started CORE session id: %s", session.id)
    if routing_density and routing_density > 0:
        logger.info("Created %s routers and %s hosts from XML", len(routers), len(hosts))
    else:
        logger.info("Created %s nodes from XML", len(hosts))
    logger.info("Role distribution:")
    for role, count in role_counts.items():
        logger.info("  %s: %s", role, count)
    logger.info("Hosts (DEFAULT type) with IPs:")
    for n in hosts:
        logger.info("  node %s (%s) -> %s", n.node_id, n.role, n.ip4)
    
    if services and service_assignments:
        logger.info("Configured services:")
        for node_id, service_list in service_assignments.items():
            logger.info("  node %s: %s", node_id, ", ".join(service_list))

    if routing_density and routing_density > 0 and routing_items:
        logger.info("Router protocols:")
        for rid, protos in router_protocols.items():
            logger.info("  router %s: %s", rid, ", ".join(protos))


if __name__ == "__main__":
    main()

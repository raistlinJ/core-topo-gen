from __future__ import annotations
from typing import Dict, List, Optional, Tuple, Set
import math
import random
import logging
from core.api.grpc import client
from core.api.grpc.wrappers import NodeType, Position, Interface

from ..types import NodeInfo, ServiceInfo, RoutingInfo
from ..utils.allocators import UniqueAllocator, SubnetAllocator, make_subnet_allocator
from ..utils.services import (
    map_role_to_node_type,
    distribute_services,
    mark_node_as_router,
    set_node_services,
    ensure_service,
    ROUTING_STACK_SERVICES,
)
from ..utils.allocation import compute_counts_by_factor

logger = logging.getLogger(__name__)


def _router_node_type() -> NodeType:
    return getattr(NodeType, "ROUTER", NodeType.DEFAULT)


def build_star_from_roles(core: client.CoreGrpcClient,
                          role_counts: Dict[str, int],
                          services: Optional[List[ServiceInfo]] = None,
                          ip4_prefix: str = "10.0.0.0/24",
                          ip_mode: str = "private",
                          ip_region: str = "all"):
    logger.info("Creating CORE session and building star topology")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = make_subnet_allocator(ip_mode, ip4_prefix, ip_region)
    session = core.create_session()

    cx, cy = 500, 400
    switch = session.add_node(1, _type=NodeType.SWITCH, position=Position(x=cx, y=cy))

    total_hosts = sum(role_counts.values())
    radius = 250
    node_infos: List[NodeInfo] = []

    expanded_roles: List[str] = []
    for role, count in role_counts.items():
        expanded_roles.extend([role] * count)

    sw_ifid = 0
    nodes_by_id: Dict[int, object] = {}
    for idx, role in enumerate(expanded_roles):
        theta = (2 * math.pi * idx) / max(total_hosts, 1)
        x = int(cx + radius * math.cos(theta))
        y = int(cy + radius * math.sin(theta))

        node_id = idx + 2
        node_type = map_role_to_node_type(role)
        node_name = f"{role.lower()}-{idx+1}"
        node = session.add_node(node_id, _type=node_type, position=Position(x=x, y=y), name=node_name)
        logger.debug("Added node id=%s name=%s type=%s at (%s,%s)", node.id, node_name, node_type, x, y)
        nodes_by_id[node.id] = node

        if node_type == NodeType.DEFAULT:
            host_ip, host_mask = mac_alloc.next_ip()
            host_mac = mac_alloc.next_mac()
            host_iface = Interface(id=0, name="eth0", ip4=host_ip, ip4_mask=host_mask, mac=host_mac)
            node_infos.append(NodeInfo(node_id=node.id, ip4=f"{host_ip}/{host_mask}", role=role))
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}", mac=mac_alloc.next_mac())
            sw_ifid += 1
            session.add_link(node1=node, node2=switch, iface1=host_iface, iface2=sw_iface)
            logger.debug("Link host %s <-> switch (ifids: host=0, sw=%d)", node.id, sw_ifid-1)
            # Ensure default routing service on hosts
            try:
                ensure_service(session, node.id, "DefaultRoute", node_obj=node)
            except Exception:
                pass
        else:
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}", mac=mac_alloc.next_mac())
            sw_ifid += 1
            session.add_link(node1=node, node2=switch, iface2=sw_iface)
            logger.debug("Link device %s -> switch (sw ifid=%d)", node.id, sw_ifid-1)

    service_assignments: Dict[int, List[str]] = {}
    if services:
        service_assignments = distribute_services(node_infos, services)
        for node_id, service_list in service_assignments.items():
            for service_name in service_list:
                assigned = False
                try:
                    if hasattr(session, "add_service"):
                        session.add_service(node_id=node_id, service_name=service_name)
                        assigned = True
                except Exception:
                    pass
                if not assigned:
                    try:
                        if hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, service_name)
                            except TypeError:
                                node_obj_try = nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, service_name)
                                else:
                                    raise
                            assigned = True
                    except Exception:
                        pass
                if not assigned:
                    node_obj = nodes_by_id.get(node_id)
                    if node_obj is not None:
                        try:
                            if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                                node_obj.services.add(service_name)
                                assigned = True
                            elif hasattr(node_obj, "add_service"):
                                node_obj.add_service(service_name)
                                assigned = True
                        except Exception:
                            pass
                if assigned and service_name in ROUTING_STACK_SERVICES:
                    try:
                        if hasattr(session, "add_service"):
                            session.add_service(node_id=node_id, service_name="zebra")
                        elif hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, "zebra")
                            except TypeError:
                                node_obj_try = nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, "zebra")
                    except Exception:
                        pass
    return session, switch, node_infos, service_assignments


def build_multi_switch_topology(core: client.CoreGrpcClient,
                                role_counts: Dict[str, int],
                                services: Optional[List[ServiceInfo]] = None,
                                ip4_prefix: str = "10.0.0.0/24",
                                ip_mode: str = "private",
                                ip_region: str = "all",
                                access_switches: int = 3,
                                layout_density: str = "normal"):
    """Build a simple multi-switch topology with an aggregation switch.

    Returns: session, [switch_ids], host NodeInfo list, service assignments
    """
    logger.info("Creating CORE session and building multi-switch topology (agg + access)")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = make_subnet_allocator(ip_mode, ip4_prefix, ip_region)
    session = core.create_session()

    cx, cy = 800, 800
    agg = session.add_node(1, _type=NodeType.SWITCH, position=Position(x=cx, y=cy), name="agg-sw")
    switch_ids: List[int] = [agg.id]

    total_hosts = sum(role_counts.values())
    access_count = max(1, min(access_switches, max(1, total_hosts // 10)))
    radius = 380 if layout_density == "compact" else (700 if layout_density == "spacious" else 500)
    # create access switches around aggregation
    for i in range(access_count):
        theta = (2 * math.pi * i) / access_count
        x = int(cx + radius * math.cos(theta))
        y = int(cy + radius * math.sin(theta))
        node_id = i + 2
        sw = session.add_node(node_id, _type=NodeType.SWITCH, position=Position(x=x, y=y), name=f"sw-{i+1}")
        switch_ids.append(sw.id)
        # link access switch to aggregation
        session.add_link(node1=sw, node2=agg)

    # Expand roles
    expanded_roles: List[str] = []
    for role, count in role_counts.items():
        expanded_roles.extend([role] * count)
    random.shuffle(expanded_roles)

    node_infos: List[NodeInfo] = []
    service_assignments: Dict[int, List[str]] = {}
    # Place hosts spreading them across access switches
    host_radius = 120 if layout_density == "compact" else (240 if layout_density == "spacious" else 180)
    sw_ifid: Dict[int, int] = {sid: 0 for sid in switch_ids}
    nodes_by_id: Dict[int, object] = {}
    next_id = access_count + 2
    for idx, role in enumerate(expanded_roles):
        # pick an access switch in round-robin
        sw_index = (idx % access_count) + 1  # skip agg at index 0
        # position around that access switch
        theta = random.random() * 2 * math.pi
        r = max(40, int(random.gauss(host_radius, 20)))
        sw_node_id = switch_ids[sw_index]
        sw_node = session.get_node(sw_node_id)
        x = int(sw_node.position.x + r * math.cos(theta))
        y = int(sw_node.position.y + r * math.sin(theta))

        node_type = map_role_to_node_type(role)
        name = f"{role.lower()}-{idx+1}"
        node = session.add_node(next_id, _type=node_type, position=Position(x=x, y=y), name=name)
        nodes_by_id[node.id] = node
        next_id += 1

        if node_type == NodeType.DEFAULT:
            # Allocate a unique /24 LAN and assign the first host IP
            lan = subnet_alloc.next_random_subnet(24)
            lan_hosts = list(lan.hosts())
            h_ip = str(lan_hosts[1])
            h_mac = mac_alloc.next_mac()
            host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan.prefixlen, mac=h_mac)
            sw_ifid[sw_node_id] += 1
            sw_if = Interface(id=sw_ifid[sw_node_id], name=f"sw{sw_node_id}-h{node.id}")
            session.add_link(node1=node, node2=sw_node, iface1=host_if, iface2=sw_if)
            node_infos.append(NodeInfo(node_id=node.id, ip4=f"{h_ip}/{lan.prefixlen}", role=role))
            try:
                ensure_service(session, node.id, "DefaultRoute", node_obj=node)
            except Exception:
                pass
        else:
            sw_ifid[sw_node_id] += 1
            sw_if = Interface(id=sw_ifid[sw_node_id], name=f"sw{sw_node_id}-d{node.id}")
            session.add_link(node1=node, node2=sw_node, iface2=sw_if)

    if services:
        service_assignments = distribute_services(node_infos, services)
        for node_id, svc_list in service_assignments.items():
            for svc in svc_list:
                try:
                    if hasattr(session, "add_service"):
                        session.add_service(node_id=node_id, service_name=svc)
                    elif hasattr(session, "services") and hasattr(session.services, "add"):
                        try:
                            session.services.add(node_id, svc)
                        except TypeError:
                            node_obj_try = session.get_node(node_id)
                            session.services.add(node_obj_try, svc)
                except Exception:
                    pass
                if svc in ROUTING_STACK_SERVICES:
                    try:
                        if hasattr(session, "add_service"):
                            session.add_service(node_id=node_id, service_name="zebra")
                        elif hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, "zebra")
                            except TypeError:
                                node_obj_try = session.get_node(node_id)
                                session.services.add(node_obj_try, "zebra")
                    except Exception:
                        pass

    return session, switch_ids, node_infos, service_assignments


def _sample_router_positions(count: int, width: int, height: int, min_dist: int = 140, max_tries: int = 5000) -> List[Tuple[int, int]]:
    """Sample router positions randomly within bounds with a minimum spacing.

    Simple rejection sampling: try random points, accept when far from previous.
    """
    rng = random.Random()
    positions: List[Tuple[int, int]] = []
    # keep some margins so nodes don't go off-canvas
    margin = max(60, min_dist // 2)
    tries = 0
    while len(positions) < count and tries < max_tries:
        tries += 1
        x = rng.randint(margin, width - margin)
        y = rng.randint(margin, height - margin)
        ok = True
        for (px, py) in positions:
            dx = px - x
            dy = py - y
            if dx * dx + dy * dy < (min_dist * min_dist):
                ok = False
                break
        if ok:
            positions.append((x, y))
    if len(positions) < count:
        # fallback to rough circle for any missing
        cx, cy = width // 2, height // 2
        radius = int(min(width, height) * 0.35)
        for i in range(count - len(positions)):
            theta = (2 * math.pi * i) / max(1, (count - len(positions)))
            positions.append((int(cx + radius * math.cos(theta)), int(cy + radius * math.sin(theta))))
    return positions


def _random_connected_pairs(n: int, extra_edges: Optional[int] = None) -> List[Tuple[int, int]]:
    """Build a connected undirected graph over n nodes and return edge index pairs.

    First create a random spanning tree, then add a few random extra edges.
    Node indices are 0..n-1.
    """
    if n <= 1:
        return []
    rng = random.Random()
    nodes = list(range(n))
    rng.shuffle(nodes)
    # spanning tree via randomized Prim-like growth
    in_tree: Set[int] = {nodes[0]}
    edges: List[Tuple[int, int]] = []
    remaining: Set[int] = set(nodes[1:])
    while remaining:
        a = rng.choice(list(in_tree))
        b = rng.choice(list(remaining))
        edges.append((a, b))
        in_tree.add(b)
        remaining.remove(b)
    # add extra edges to increase redundancy
    if extra_edges is None:
        extra_edges = max(0, n // 3)
    existing = set(tuple(sorted(e)) for e in edges)
    attempts = 0
    while extra_edges > 0 and attempts < n * n:
        attempts += 1
        a, b = rng.sample(range(n), 2)
        if a == b:
            continue
        key = tuple(sorted((a, b)))
        if key in existing:
            continue
        existing.add(key)
        edges.append((a, b))
        extra_edges -= 1
    return edges


def _grid_positions(count: int, cols: Optional[int] = None, cell_w: int = 800, cell_h: int = 600, jitter: int = 60) -> List[Tuple[int, int]]:
    """Lay out positions on a spacious grid for readability.

    Returns a list of (x, y) coordinates. Jitter adds slight randomness.
    """
    if count <= 0:
        return []
    if cols is None:
        cols = max(1, int(math.ceil(math.sqrt(count))))
    rows = int(math.ceil(count / cols))
    positions: List[Tuple[int, int]] = []
    rng = random.Random()
    for i in range(count):
        r = i // cols
        c = i % cols
        x = c * cell_w + cell_w // 2 + rng.randint(-jitter, jitter)
        y = r * cell_h + cell_h // 2 + rng.randint(-jitter, jitter)
        positions.append((x, y))
    return positions


def build_segmented_topology(core: client.CoreGrpcClient,
                             role_counts: Dict[str, int],
                             routing_density: float,
                             routing_items: List[RoutingInfo],
                             services: Optional[List[ServiceInfo]] = None,
                             ip4_prefix: str = "10.0.0.0/24",
                             ip_mode: str = "private",
                             ip_region: str = "all",
                             layout_density: str = "normal"):
    logger.info("Creating CORE session and building segmented topology with routers (randomized placement)")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = make_subnet_allocator(ip_mode, ip4_prefix, ip_region)
    session = core.create_session()

    total_hosts = sum(role_counts.values())
    if routing_density <= 0 or total_hosts == 0:
        session, switch, nodes, svc = build_star_from_roles(
            core,
            role_counts,
            services=services,
            ip4_prefix=ip4_prefix,
            ip_mode=ip_mode,
            ip_region=ip_region,
        )
        return session, [], nodes, svc, {}

    # round-and-clamp for router count selection
    d = max(0.0, min(1.0, float(routing_density)))
    desired = total_hosts * d
    router_count = max(1, min(total_hosts, int(round(desired))))

    # placement parameters tuned by density
    if layout_density == "compact":
        cell_w, cell_h = 600, 450
        host_radius_mean = 140
        host_radius_jitter = 40
    elif layout_density == "spacious":
        cell_w, cell_h = 1000, 750
        host_radius_mean = 260
        host_radius_jitter = 80
    else:  # normal
        cell_w, cell_h = 900, 650
        host_radius_mean = 220
        host_radius_jitter = 60

    routers: List[NodeInfo] = []
    router_nodes: Dict[int, object] = {}
    router_objs: List[object] = []
    host_nodes_by_id: Dict[int, object] = {}
    router_next_ifid: Dict[int, int] = {}

    # place routers on a spacious grid for easier viewing
    r_positions = _grid_positions(router_count, cell_w=cell_w, cell_h=cell_h, jitter=50)
    for i in range(router_count):
        x, y = r_positions[i]
        node_id = i + 1
        node = session.add_node(node_id, _type=_router_node_type(), position=Position(x=x, y=y), name=f"router-{i+1}")
        logger.debug("Added router id=%s at (%s,%s)", node.id, x, y)
        mark_node_as_router(node, session)
        set_node_services(session, node.id, ["IPForward", "zebra"], node_obj=node)
        routers.append(NodeInfo(node_id=node.id, ip4="", role="Router"))
        router_nodes[node.id] = node
        router_objs.append(node)

    if router_count > 1:
        # build a random connected inter-router graph with some redundancy
        idx_pairs: List[Tuple[int, int]] = _random_connected_pairs(router_count)
        for aidx, bidx in idx_pairs:
            a = router_objs[aidx]
            b = router_objs[bidx]
            a_ifid = router_next_ifid.get(a.id, 0)
            b_ifid = router_next_ifid.get(b.id, 0)
            router_next_ifid[a.id] = a_ifid + 1
            router_next_ifid[b.id] = b_ifid + 1
            # Use /24 for inter-router links (temporary uniform sizing)
            rr_net = subnet_alloc.next_random_subnet(24)
            rr_hosts = list(rr_net.hosts())
            a_ip = str(rr_hosts[0])
            b_ip = str(rr_hosts[1])
            a_if = Interface(id=a_ifid, name=f"r{a.id}-to-r{b.id}", ip4=a_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
            b_if = Interface(id=b_ifid, name=f"r{b.id}-to-r{a.id}", ip4=b_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
            session.add_link(node1=a, node2=b, iface1=a_if, iface2=b_if)
            logger.debug("Router link r%d (%s/%s) <-> r%d (%s/%s)", a.id, a_ip, rr_net.prefixlen, b.id, b_ip, rr_net.prefixlen)

    expanded_roles: List[str] = []
    for role, count in role_counts.items():
        expanded_roles.extend([role] * count)

    random.shuffle(expanded_roles)
    buckets: List[List[str]] = [[] for _ in range(router_count)]
    for role in expanded_roles:
        buckets[random.randrange(router_count)].append(role)

    hosts: List[NodeInfo] = []
    node_id_counter = router_count + 1
    for ridx, roles in enumerate(buckets):
        rx, ry = r_positions[ridx]
        router_node = router_objs[ridx]
        if len(roles) == 0:
            continue
        elif len(roles) == 1:
            role = roles[0]
            # offset around router
            theta = 0.0
            r = max(60, int(random.gauss(host_radius_mean, host_radius_jitter)))
            x = int(rx + r * math.cos(theta))
            y = int(ry + r * math.sin(theta))
            node_type = map_role_to_node_type(role)
            name = f"{role.lower()}-{ridx+1}-1"
            host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
            logger.debug("Added host id=%s name=%s type=%s at (%s,%s)", host.id, name, node_type, x, y)
            node_id_counter += 1
            host_nodes_by_id[host.id] = host
            # Allocate a unique /24 LAN
            lan_net = subnet_alloc.next_random_subnet(24)
            lan_hosts = list(lan_net.hosts())
            r_ip = str(lan_hosts[0])
            h_ip = str(lan_hosts[1])
            h_mac = mac_alloc.next_mac()
            host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=h_mac)
            r_ifid = router_next_ifid.get(router_node.id, 0)
            router_next_ifid[router_node.id] = r_ifid + 1
            r_if = Interface(id=r_ifid, name=f"r{router_node.id}-h{host.id}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
            session.add_link(node1=host, node2=router_node, iface1=host_if, iface2=r_if)
            logger.debug("Host %s <-> Router %s LAN /%s", host.id, router_node.id, lan_net.prefixlen)
            if node_type == NodeType.DEFAULT:
                hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
                # Ensure default routing service on hosts
                try:
                    ensure_service(session, host.id, "DefaultRoute", node_obj=host)
                except Exception:
                    pass
        else:
            # place LAN switch slightly offset from router
            sx = rx + random.randint(30, 70)
            sy = ry + random.randint(30, 70)
            lan_switch = session.add_node(node_id_counter, _type=NodeType.SWITCH, position=Position(x=sx, y=sy), name=f"lan-{ridx+1}")
            logger.debug("Added LAN switch id=%s for router %s", lan_switch.id, router_node.id)
            node_id_counter += 1
            lan_net = subnet_alloc.next_random_subnet(24)
            lan_hosts = list(lan_net.hosts())
            r_ip = str(lan_hosts[0])
            r_ifid = router_next_ifid.get(router_node.id, 0)
            router_next_ifid[router_node.id] = r_ifid + 1
            r_if = Interface(id=r_ifid, name=f"r{router_node.id}-lan{ridx+1}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
            sw_if = Interface(id=0, name=f"lan{ridx+1}-r")
            session.add_link(node1=router_node, node2=lan_switch, iface1=r_if, iface2=sw_if)
            host_ip_pool = [str(ip) for ip in lan_hosts[1:]]
            random.shuffle(host_ip_pool)
            for j, role in enumerate(roles):
                # evenly spaced around the router for legibility
                theta = (2 * math.pi * j) / len(roles)
                # scale radius slightly with number of hosts
                r = max(80, int(random.gauss(host_radius_mean + 10 * math.sqrt(len(roles)), host_radius_jitter)))
                x = int(rx + r * math.cos(theta))
                y = int(ry + r * math.sin(theta))
                node_type = map_role_to_node_type(role)
                name = f"{role.lower()}-{ridx+1}-{j+1}"
                host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
                logger.debug("Added host id=%s name=%s type=%s at (%s,%s)", host.id, name, node_type, x, y)
                node_id_counter += 1
                host_nodes_by_id[host.id] = host
                if host_ip_pool:
                    h_ip = host_ip_pool.pop()
                else:
                    h_ip = str(lan_hosts[min(j + 1, len(lan_hosts) - 1)])
                h_mac = mac_alloc.next_mac()
                host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=h_mac)
                sw_if = Interface(id=j+1, name=f"lan{ridx+1}-h{host.id}")
                session.add_link(node1=host, node2=lan_switch, iface1=host_if, iface2=sw_if)
                logger.debug("Host %s -> LAN switch %s (/%s)", host.id, lan_switch.id, lan_net.prefixlen)
                if node_type == NodeType.DEFAULT:
                    hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
                    # Ensure default routing service on hosts
                    try:
                        ensure_service(session, host.id, "DefaultRoute", node_obj=host)
                    except Exception:
                        pass

    router_protocols: Dict[int, List[str]] = {r.node_id: [] for r in routers}
    if routing_items:
        proto_items = [(ri.protocol, ri.factor) for ri in routing_items]
        counts = compute_counts_by_factor(router_count, proto_items)
        expanded_protocols: List[str] = []
        for proto, c in counts.items():
            expanded_protocols.extend([proto] * c)
        while len(expanded_protocols) < router_count and proto_items:
            expanded_protocols.append(proto_items[0][0])
        for i, rnode in enumerate(router_objs):
            rid = rnode.id
            if i < len(expanded_protocols):
                proto = expanded_protocols[i]
                router_protocols[rid].append(proto)
                base = ["IPForward", "zebra"]
                proto_list = base + [proto] if proto else base
                set_node_services(session, rid, proto_list, node_obj=rnode)

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
                except Exception:
                    pass
                if not assigned:
                    try:
                        if hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, svc)
                            except TypeError:
                                node_obj_try = host_nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, svc)
                                    assigned = True
                    except Exception:
                        pass
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
                        except Exception:
                            pass
                if assigned and svc in ROUTING_STACK_SERVICES:
                    try:
                        if hasattr(session, "add_service"):
                            session.add_service(node_id=node_id, service_name="zebra")
                        elif hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, "zebra")
                            except TypeError:
                                node_obj_try = host_nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, "zebra")
                    except Exception:
                        pass
    return session, routers, hosts, host_service_assignments, router_protocols

from __future__ import annotations
from typing import Dict, List, Optional, Tuple
import math
import random
import logging
from core.api.grpc import client
from core.api.grpc.wrappers import NodeType, Position, Interface

from ..types import NodeInfo, ServiceInfo, RoutingInfo
from ..utils.allocators import UniqueAllocator, SubnetAllocator
from ..utils.services import (
    map_role_to_node_type,
    distribute_services,
    mark_node_as_router,
    set_node_services,
    ROUTING_STACK_SERVICES,
)
from ..utils.allocation import compute_counts_by_factor

logger = logging.getLogger(__name__)


def _router_node_type() -> NodeType:
    return getattr(NodeType, "ROUTER", NodeType.DEFAULT)


def build_star_from_roles(core: client.CoreGrpcClient,
                          role_counts: Dict[str, int],
                          services: Optional[List[ServiceInfo]] = None,
                          ip4_prefix: str = "10.0.0.0/24"):
    logger.info("Creating CORE session and building star topology")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = SubnetAllocator(ip4_prefix)
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
        nodes_by_id[node.id] = node

        if node_type == NodeType.DEFAULT:
            host_ip, host_mask = mac_alloc.next_ip()
            host_mac = mac_alloc.next_mac()
            host_iface = Interface(id=0, name="eth0", ip4=host_ip, ip4_mask=host_mask, mac=host_mac)
            node_infos.append(NodeInfo(node_id=node.id, ip4=f"{host_ip}/{host_mask}", role=role))
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}", mac=mac_alloc.next_mac())
            sw_ifid += 1
            session.add_link(node1=node, node2=switch, iface1=host_iface, iface2=sw_iface)
        else:
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}", mac=mac_alloc.next_mac())
            sw_ifid += 1
            session.add_link(node1=node, node2=switch, iface2=sw_iface)

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
    core.start_session(session)
    return session, switch, node_infos, service_assignments


def build_segmented_topology(core: client.CoreGrpcClient,
                             role_counts: Dict[str, int],
                             routing_density: float,
                             routing_items: List[RoutingInfo],
                             services: Optional[List[ServiceInfo]] = None,
                             ip4_prefix: str = "10.0.0.0/24"):
    logger.info("Creating CORE session and building segmented topology with routers")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = SubnetAllocator(ip4_prefix)
    session = core.create_session()

    total_hosts = sum(role_counts.values())
    if routing_density <= 0 or total_hosts == 0:
        session, switch, nodes, svc = build_star_from_roles(core, role_counts, services=services, ip4_prefix=ip4_prefix)
        return session, [], nodes, svc, {}

    router_count = max(1, min(total_hosts, math.floor(total_hosts * routing_density)))

    cx, cy = 600, 500
    router_radius = 300
    host_radius = 120

    routers: List[NodeInfo] = []
    router_nodes: Dict[int, object] = {}
    router_objs: List[object] = []
    host_nodes_by_id: Dict[int, object] = {}
    router_next_ifid: Dict[int, int] = {}

    for i in range(router_count):
        theta = (2 * math.pi * i) / router_count
        x = int(cx + router_radius * math.cos(theta))
        y = int(cy + router_radius * math.sin(theta))
        node_id = i + 1
        node = session.add_node(node_id, _type=_router_node_type(), position=Position(x=x, y=y), name=f"router-{i+1}")
        mark_node_as_router(node, session)
        set_node_services(session, node.id, ["IPForward", "zebra"], node_obj=node)
        routers.append(NodeInfo(node_id=node.id, ip4="", role="Router"))
        router_nodes[node.id] = node
        router_objs.append(node)

    if router_count > 1:
        idx_pairs: List[Tuple[int, int]] = []
        if router_count == 2:
            idx_pairs = [(0, 1)]
        else:
            idx_pairs = [(i, (i + 1) % router_count) for i in range(router_count)]
        for aidx, bidx in idx_pairs:
            a = router_objs[aidx]
            b = router_objs[bidx]
            a_ifid = router_next_ifid.get(a.id, 0)
            b_ifid = router_next_ifid.get(b.id, 0)
            router_next_ifid[a.id] = a_ifid + 1
            router_next_ifid[b.id] = b_ifid + 1
            rr_net = subnet_alloc.next_random_subnet(30)
            rr_hosts = list(rr_net.hosts())
            a_ip = str(rr_hosts[0])
            b_ip = str(rr_hosts[1])
            a_if = Interface(id=a_ifid, name=f"r{a.id}-to-r{b.id}", ip4=a_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
            b_if = Interface(id=b_ifid, name=f"r{b.id}-to-r{a.id}", ip4=b_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
            session.add_link(node1=a, node2=b, iface1=a_if, iface2=b_if)

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
        rx = int(cx + router_radius * math.cos((2 * math.pi * ridx) / router_count))
        ry = int(cy + router_radius * math.sin((2 * math.pi * ridx) / router_count))
        router_node = router_objs[ridx]
        if len(roles) == 0:
            continue
        elif len(roles) == 1:
            role = roles[0]
            theta = 0
            x = int(rx + host_radius * math.cos(theta))
            y = int(ry + host_radius * math.sin(theta))
            node_type = map_role_to_node_type(role)
            name = f"{role.lower()}-{ridx+1}-1"
            host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
            node_id_counter += 1
            host_nodes_by_id[host.id] = host
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
        else:
            lan_switch = session.add_node(node_id_counter, _type=NodeType.SWITCH, position=Position(x=rx+40, y=ry+40), name=f"lan-{ridx+1}")
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
                theta = (2 * math.pi * j) / len(roles)
                x = int(rx + host_radius * math.cos(theta))
                y = int(ry + host_radius * math.sin(theta))
                node_type = map_role_to_node_type(role)
                name = f"{role.lower()}-{ridx+1}-{j+1}"
                host = session.add_node(node_id_counter, _type=node_type, position=Position(x=x, y=y), name=name)
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
                if node_type == NodeType.DEFAULT:
                    hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))

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
    core.start_session(session)
    return session, routers, hosts, host_service_assignments, router_protocols

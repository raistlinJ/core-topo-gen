from __future__ import annotations
import os
import logging
from typing import Dict, List, Optional
from core.api.grpc.wrappers import NodeType
from ..types import NodeInfo, ServiceInfo

logger = logging.getLogger(__name__)

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

# Fallback pool used when only "Random" is specified in Services
# Aligns with default GUI dropdown suggestions
DEFAULT_SERVICE_POOL: List[str] = [
    "SSH",
    "HTTP",
    "DHCPClient",
]

def ensure_service(session: object, node_id: int, service_name: str, node_obj: Optional[object] = None) -> bool:
    """Attempt to add a service to a node without dropping existing services.

    Strategy:
    1) Read current services (via session.services.get or node_obj.services) and set union.
    2) Fall back to additive APIs (session.add_service / session.services.add / node_obj.add).
    """
    # Normalize to custom segmentation services when applicable
    try:
        if isinstance(service_name, str):
            if service_name in ("Firewall", "NAT", "sFirewall", "sNAT"):
                service_name = "Segmentation"
    except Exception:
        pass

    # Try to fetch node object if not provided
    if node_obj is None:
        try:
            if hasattr(session, "get_node"):
                node_obj = session.get_node(node_id)
            elif hasattr(session, "nodes") and isinstance(session.nodes, dict):
                node_obj = session.nodes.get(node_id)
        except Exception:
            node_obj = None

    # First, attempt to read existing and set with union
    current = None
    try:
        if hasattr(session, "services") and hasattr(session.services, "get"):
            try:
                current = list(session.services.get(node_id) or [])
            except TypeError:
                if node_obj is not None:
                    current = list(session.services.get(node_obj) or [])
    except Exception:
        current = None
    if current is None and node_obj is not None:
        try:
            if hasattr(node_obj, "services"):
                # node_obj.services might be list-like or have a getter
                cur = getattr(node_obj, "services")
                if isinstance(cur, (list, tuple)):
                    current = list(cur)
        except Exception:
            current = None

    if current is not None:
        if service_name not in current:
            current.append(service_name)
        try:
            if hasattr(session, "services") and hasattr(session.services, "set"):
                try:
                    session.services.set(node_id, tuple(current))
                    logger.info("services.set: updated node %s -> %s", node_id, ", ".join(current))
                    return True
                except TypeError:
                    if node_obj is not None:
                        session.services.set(node_obj, tuple(current))
                        logger.info("services.set(node_obj): updated node %s -> %s", node_id, ", ".join(current))
                        return True
        except Exception as e:
            logger.debug("services.set failed for node %s: %s", node_id, e)

    # Fallback: direct additive methods
    try:
        if hasattr(session, "add_service"):
            logger.debug("add_service(node_id=%s, %s)", node_id, service_name)
            session.add_service(node_id=node_id, service_name=service_name)
            return True
    except Exception as e:
        logger.debug("session.add_service failed for node %s: %s", node_id, e)

    try:
        if hasattr(session, "services") and hasattr(session.services, "add"):
            try:
                logger.debug("services.add(node_id=%s, %s)", node_id, service_name)
                session.services.add(node_id, service_name)
                return True
            except TypeError:
                if node_obj is not None:
                    logger.debug("services.add(node_obj for node_id=%s, %s)", node_id, service_name)
                    session.services.add(node_obj, service_name)
                    return True
    except Exception as e:
        logger.debug("session.services.add failed for node %s: %s", node_id, e)

    if node_obj is not None:
        try:
            if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                logger.debug("node_obj.services.add(node_id=%s, %s)", node_id, service_name)
                node_obj.services.add(service_name)
                return True
            if hasattr(node_obj, "add_service"):
                logger.debug("node_obj.add_service(node_id=%s, %s)", node_id, service_name)
                node_obj.add_service(service_name)
                return True
        except Exception as e:
            logger.debug("node_obj add service failed for node %s: %s", node_id, e)

    logger.warning("Failed to ensure service '%s' on node %s", service_name, node_id)
    return False

def map_role_to_node_type(role: str) -> NodeType:
    low = role.lower()
    if low in {"router"}:
        return getattr(NodeType, "ROUTER", NodeType.DEFAULT)
    if low in {"switch"}:
        return NodeType.SWITCH
    if low in {"hub"}:
        return NodeType.HUB
    if low in {"wlan", "wireless", "wireless_lan"}:
        return NodeType.WIRELESS_LAN
    return NodeType.DEFAULT

def mark_node_as_router(node: object, session: object) -> None:
    icon_path = os.path.expanduser("~/.coregui/icons/router.png")
    try:
        if hasattr(session, "set_node_icon"):
            try:
                session.set_node_icon(node_id=node.id, icon=icon_path)
            except TypeError:
                session.set_node_icon(node.id, icon_path)
    except Exception:
        pass
    try:
        if hasattr(node, "icon"):
            setattr(node, "icon", icon_path)
    except Exception:
        pass
    try:
        if hasattr(node, "set_icon"):
            node.set_icon(icon_path)
    except Exception:
        pass
    for svc in ("IPForward", "zebra"):
        try:
            if hasattr(session, "add_service"):
                session.add_service(node_id=node.id, service_name=svc)
                continue
        except Exception:
            pass
        try:
            if hasattr(session, "services") and hasattr(session.services, "add"):
                try:
                    session.services.add(node.id, svc)
                except TypeError:
                    session.services.add(node, svc)
        except Exception:
            pass

def set_node_services(session: object, node_id: int, services: List[str], node_obj: Optional[object] = None) -> bool:
    seen = set()
    ordered: List[str] = []
    for s in services:
        if s and s not in seen:
            ordered.append(s)
            seen.add(s)
    try:
        if hasattr(session, "services") and hasattr(session.services, "set"):
            session.services.set(node_id, tuple(ordered))
            logger.debug("Set services on node %s -> %s", node_id, ", ".join(ordered))
            return True
    except Exception as e:
        logger.debug("session.services.set failed for node %s: %s", node_id, e)
    try:
        if hasattr(session, "services") and hasattr(session.services, "clear"):
            try:
                session.services.clear(node_id)
            except TypeError:
                if node_obj is not None:
                    session.services.clear(node_obj)
    except Exception:
        pass
    success_any = False
    for svc in ordered:
        added = False
        try:
            if hasattr(session, "add_service"):
                session.add_service(node_id=node_id, service_name=svc)
                added = True
        except Exception:
            pass
        if not added:
            try:
                if hasattr(session, "services") and hasattr(session.services, "add"):
                    try:
                        session.services.add(node_id, svc)
                    except TypeError:
                        if node_obj is not None:
                            session.services.add(node_obj, svc)
                        else:
                            raise
                    added = True
            except Exception:
                pass
        if not added and node_obj is not None:
            try:
                if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                    node_obj.services.add(svc)
                    added = True
                elif hasattr(node_obj, "add_service"):
                    node_obj.add_service(svc)
                    added = True
            except Exception:
                pass
        success_any = success_any or added
        if not added:
            logger.warning("Failed to add service '%s' to node %s", svc, node_id)
    return success_any


def distribute_services(nodes: List[NodeInfo], services: List[ServiceInfo]) -> Dict[int, List[str]]:
    node_services: Dict[int, List[str]] = {}
    host_nodes = [
        n for n in nodes
        if map_role_to_node_type(n.role) == NodeType.DEFAULT and "router" not in n.role.lower()
    ]
    if not host_nodes:
        return node_services
    import random, math

    # Build a list of concrete (non-Random) service names we can select from.
    # If none are provided (only Random present), fall back to a sensible default pool.
    concrete_service_names = [s.name for s in services if s.name and s.name.lower() != "random"]
    if not concrete_service_names:
        concrete_service_names = list(DEFAULT_SERVICE_POOL)

    for service in services:
        # round-and-clamp: density in [0,1], 1 -> all hosts, else round to nearest, at least 1
        d = max(0.0, min(1.0, float(service.density)))
        desired = len(host_nodes) * d
        total_service_nodes = max(1, min(len(host_nodes), int(round(desired))))

        # Determine eligible nodes. For Random, a node is eligible if it has at
        # least one concrete service not yet assigned to it. For concrete
        # services, eligible if it doesn't already have that service.
        if service.name.lower() == "random":
            eligible_nodes = [
                node for node in host_nodes
                if concrete_service_names and (
                    node.node_id not in node_services or
                    any(s not in node_services[node.node_id] for s in concrete_service_names)
                )
            ]
        else:
            eligible_nodes = [
                node for node in host_nodes
                if node.node_id not in node_services or service.name not in node_services[node.node_id]
            ]

        if not eligible_nodes:
            continue

        random.shuffle(eligible_nodes)
        preselected = [n for n in eligible_nodes if random.random() < service.factor]
        if len(preselected) > total_service_nodes:
            selected_nodes = preselected[:total_service_nodes]
        else:
            remaining_needed = total_service_nodes - len(preselected)
            remainder = [n for n in eligible_nodes if n not in preselected]
            selected_nodes = preselected + remainder[:remaining_needed]

        for node in selected_nodes:
            if node.node_id not in node_services:
                node_services[node.node_id] = []

            if service.name.lower() == "random":
                # Choose a random concrete service not yet on this node
                if not concrete_service_names:
                    continue
                remaining = [s for s in concrete_service_names if s not in node_services[node.node_id]]
                if not remaining:
                    continue
                chosen = random.choice(remaining)
                node_services[node.node_id].append(chosen)
            else:
                node_services[node.node_id].append(service.name)
    return node_services

from __future__ import annotations
import argparse
import logging
import random
import os
from core.api.grpc import client
from .parsers.xml_parser import parse_node_info, parse_routing_info, parse_traffic_info
from .utils.allocation import compute_role_counts
from .builders.topology import build_star_from_roles, build_segmented_topology
from .utils.traffic import generate_traffic_scripts
from .utils.services import ensure_service


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xml", required=True, help="Path to XML scenario file")
    ap.add_argument("--scenario", default=None, help="Scenario name to use (defaults to first)")
    ap.add_argument("--host", default="127.0.0.1", help="core-daemon gRPC host")
    ap.add_argument("--port", type=int, default=50051, help="core-daemon gRPC port")
    ap.add_argument("--prefix", default="10.0.0.0/24", help="IPv4 prefix for auto-assigned addresses")
    ap.add_argument("--max-nodes", type=int, default=None, help="Optional cap on hosts to create")
    ap.add_argument("--verbose", action="store_true", help="Enable debug logging")
    ap.add_argument("--seed", type=int, default=None, help="Optional RNG seed for reproducible topology randomness")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    if args.seed is not None:
        random.seed(args.seed)

    total, items, services = parse_node_info(args.xml, args.scenario)
    if args.max_nodes is not None and args.max_nodes > 0:
        total = min(total, args.max_nodes)
    role_counts = compute_role_counts(total, items)
    routing_density, routing_items = parse_routing_info(args.xml, args.scenario)

    core = client.CoreGrpcClient(address=f"{args.host}:{args.port}")
    core.connect()

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

    # Parse traffic and generate scripts for non-router hosts
    traffic_density, traffic_items = parse_traffic_info(args.xml, args.scenario)
    logging.info(
        "Traffic config: density=%.3f, items=%d",
        float(traffic_density or 0.0),
        len(traffic_items or []),
    )
    if traffic_density and traffic_density > 0:
        try:
            traffic_map = generate_traffic_scripts(hosts, traffic_density, traffic_items, out_dir="/tmp/traffic")
            if not traffic_map:
                logging.info("No hosts selected for traffic after generation (density too low or no eligible hosts)")
            # Enable 'Traffic' service on all nodes that have traffic (additive)
            for node_id in traffic_map.keys():
                logging.info("Enabling Traffic service on node %s", node_id)
                ok = False
                try:
                    # try with node_obj if available for broader compatibility
                    node_obj = None
                    try:
                        if hasattr(session, "get_node"):
                            node_obj = session.get_node(node_id)
                    except Exception:
                        node_obj = None
                    ok = ensure_service(session, node_id, "Traffic", node_obj=node_obj)
                except Exception as e:
                    logging.warning("Error enabling Traffic service on node %s: %s", node_id, e)
                if ok:
                    logging.info("Traffic service enabled on node %s", node_id)
                else:
                    logging.warning("Unable to add 'Traffic' service on node %s (service may not be installed in CORE)", node_id)
            # Summarize traffic scripts (receivers/senders)
            total_r = 0
            total_s = 0
            nodes_with_r = 0
            nodes_with_s = 0
            for nid, paths in traffic_map.items():
                r = s = 0
                for p in paths:
                    b = os.path.basename(p)
                    stem = b.rsplit(".", 1)[0]
                    suffix = stem.split("_")[-1]
                    if suffix.startswith("r"):
                        r += 1
                    elif suffix.startswith("s"):
                        s += 1
                total_r += r
                total_s += s
                if r:
                    nodes_with_r += 1
                if s:
                    nodes_with_s += 1
                logging.debug("Node %s traffic scripts: receivers=%d, senders=%d", nid, r, s)
            logging.info(
                "Traffic scripts written to /tmp/traffic (receivers=%d on %d nodes; senders=%d on %d nodes; up to %.0f%% of hosts)",
                total_r,
                nodes_with_r,
                total_s,
                nodes_with_s,
                traffic_density * 100,
            )
        except Exception as e:
            logging.warning("Failed generating traffic scripts: %s", e)
    else:
        logging.info("Traffic disabled or density is 0; skipping traffic generation and service enablement")

    # Start the CORE session only after all services (including Traffic) are applied
    try:
        core.start_session(session)
        logging.info("CORE session started")
    except Exception as e:
        logging.error("Failed to start CORE session: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations
import argparse
import logging
import random
from core.api.grpc import client
from .parsers.xml_parser import parse_node_info, parse_routing_info
from .utils.allocation import compute_role_counts
from .builders.topology import build_star_from_roles, build_segmented_topology


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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

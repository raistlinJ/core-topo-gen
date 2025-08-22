from __future__ import annotations
import argparse
import logging
import random
import os
from core.api.grpc import client
from .parsers.xml_parser import parse_node_info, parse_routing_info, parse_traffic_info
from .utils.allocation import compute_role_counts
from .builders.topology import build_star_from_roles, build_segmented_topology, build_multi_switch_topology
from .utils.traffic import generate_traffic_scripts
from .utils.report import write_report
from .utils.services import ensure_service


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xml", required=True, help="Path to XML scenario file")
    ap.add_argument("--scenario", default=None, help="Scenario name to use (defaults to first)")
    ap.add_argument("--host", default="127.0.0.1", help="core-daemon gRPC host")
    ap.add_argument("--port", type=int, default=50051, help="core-daemon gRPC port")
    ap.add_argument("--prefix", default="10.0.0.0/24", help="IPv4 prefix for auto-assigned addresses")
    ap.add_argument(
        "--ip-mode",
        choices=["private", "mixed", "public"],
        default="private",
        help="IP address pool mode: private (RFC1918), mixed (private+public), or public",
    )
    ap.add_argument(
        "--ip-region",
        choices=["all", "na", "eu", "apac", "latam", "africa", "middle-east"],
        default="all",
        help="Region for public pools when ip-mode is mixed/public (default: all)",
    )
    ap.add_argument("--max-nodes", type=int, default=None, help="Optional cap on hosts to create")
    ap.add_argument("--verbose", action="store_true", help="Enable debug logging")
    ap.add_argument("--seed", type=int, default=None, help="Optional RNG seed for reproducible topology randomness")
    ap.add_argument(
        "--layout-density",
        choices=["compact", "normal", "spacious"],
        default="normal",
        help="Layout spacing for visual clarity (affects node positions)",
    )
    # Optional overrides for traffic generation
    ap.add_argument("--traffic-pattern", choices=["continuous", "burst", "periodic", "poisson", "ramp"], help="Override traffic pattern for all items")
    ap.add_argument("--traffic-rate", type=float, help="Override traffic rate for all items (KB/s)")
    ap.add_argument("--traffic-period", type=float, help="Override traffic period for all items (seconds)")
    ap.add_argument("--traffic-jitter", type=float, help="Override traffic jitter for all items (percent 0-100)")
    ap.add_argument(
        "--traffic-content",
        choices=["text", "photo", "audio", "video"],
        help="Override traffic content type for all items (text/photo/audio/video)",
    )
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

    scenario_name = args.scenario
    generation_meta = {
        "host": args.host,
        "port": args.port,
        "ip_prefix": args.prefix,
        "ip_mode": args.ip_mode,
        "ip_region": args.ip_region,
        "layout_density": args.layout_density,
        "seed": args.seed,
    }
    if routing_density and routing_density > 0:
        session, routers, hosts, service_assignments, router_protocols = build_segmented_topology(
            core,
            role_counts,
            routing_density=routing_density,
            routing_items=routing_items,
            services=services,
            ip4_prefix=args.prefix,
            ip_mode=args.ip_mode,
            ip_region=args.ip_region,
            layout_density=args.layout_density,
        )
    else:
        # Use multi-switch for more variety when no routing is requested
        session, switches, hosts, service_assignments = build_multi_switch_topology(
            core,
            role_counts,
            services=services,
            ip4_prefix=args.prefix,
            ip_mode=args.ip_mode,
            ip_region=args.ip_region,
            layout_density=args.layout_density,
        )

    # Parse traffic and generate scripts for non-router hosts
    traffic_density, traffic_items = parse_traffic_info(args.xml, args.scenario)
    logging.info(
        "Traffic config: density=%.3f, items=%d",
        float(traffic_density or 0.0),
        len(traffic_items or []),
    )
    traffic_out_dir = "/tmp/traffic"
    traffic_map = {}
    if traffic_density and traffic_density > 0:
        try:
            # apply CLI overrides, if provided
            if traffic_items:
                for i in range(len(traffic_items)):
                    ti = traffic_items[i]
                    if args.traffic_pattern:
                        ti.pattern = args.traffic_pattern
                    if args.traffic_rate is not None:
                        ti.rate_kbps = max(0.0, float(args.traffic_rate))
                    if args.traffic_period is not None:
                        ti.period_s = max(0.0, float(args.traffic_period)) if float(args.traffic_period) > 0 else 10.0
                    if args.traffic_jitter is not None:
                        ti.jitter_pct = max(0.0, min(100.0, float(args.traffic_jitter)))
                    if args.traffic_content:
                        ti.content_type = args.traffic_content
            traffic_map = generate_traffic_scripts(hosts, traffic_density, traffic_items, out_dir=traffic_out_dir)
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

    # Write scenario report (Markdown) under ./reports/
    try:
        import time as _time
        report_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(report_dir, exist_ok=True)
        traffic_summary_path = os.path.join(traffic_out_dir, "traffic_summary.json")
        report_path = os.path.join(report_dir, f"scenario_report_{int(_time.time())}.md")
        routing_cfg = {
            "density": routing_density,
            "items": [{"protocol": i.protocol, "factor": i.factor} for i in (routing_items or [])],
        }
        traffic_cfg = {
            "density": traffic_density,
            "items": [{
                "kind": i.kind,
                "factor": i.factor,
                "pattern": i.pattern,
                "rate_kbps": i.rate_kbps,
                "period_s": i.period_s,
                "jitter_pct": i.jitter_pct,
                "content_type": i.content_type,
            } for i in (traffic_items or [])],
        }
        services_cfg = [{"name": s.name, "factor": s.factor, "density": s.density} for s in (services or [])]
        if routing_density and routing_density > 0:
            write_report(
                report_path,
                scenario_name,
                routers=routers,
                router_protocols=router_protocols,
                switches=[],
                hosts=hosts,
                service_assignments=service_assignments,
                traffic_summary_path=traffic_summary_path if os.path.exists(traffic_summary_path) else None,
                metadata=generation_meta,
                routing_cfg=routing_cfg,
                traffic_cfg=traffic_cfg,
                services_cfg=services_cfg,
            )
        else:
            write_report(
                report_path,
                scenario_name,
                routers=[],
                router_protocols={},
                switches=switches,
                hosts=hosts,
                service_assignments=service_assignments,
                traffic_summary_path=traffic_summary_path if os.path.exists(traffic_summary_path) else None,
                metadata=generation_meta,
                routing_cfg=routing_cfg,
                traffic_cfg=traffic_cfg,
                services_cfg=services_cfg,
            )
        logging.info("Scenario report written to %s", report_path)
    except Exception as e:
        logging.error("Failed to write scenario report: %s", e)

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

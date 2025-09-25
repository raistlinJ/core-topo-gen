from __future__ import annotations
import argparse
import logging
import random
import os
from core.api.grpc import client
from .parsers.xml_parser import (
    parse_node_info,
    parse_routing_info,
    parse_traffic_info,
    parse_segmentation_info,
    parse_vulnerabilities_info,
    parse_planning_metadata,
)
from .utils.allocation import compute_role_counts
from .builders.topology import build_star_from_roles, build_segmented_topology, build_multi_switch_topology
from .utils.traffic import generate_traffic_scripts
from .utils.report import write_report
from .utils.vuln_process import (
    load_vuln_catalog,
    select_vulnerabilities,
    process_vulnerabilities,
    prepare_compose_for_nodes,
    assign_compose_to_nodes,
    prepare_compose_for_assignments,
)
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
        "--router-mesh",
        choices=["full", "ring", "tree"],
        default="full",
        help="Protocol adjacency mesh style among routers sharing a protocol: full (complete), ring (cycle), tree (chain)")
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
    ap.add_argument(
        "--allow-src-subnet-prob",
        type=float,
        default=0.3,
        help="Probability [0..1] to widen firewall allow rules to the source subnet",
    )
    ap.add_argument(
        "--allow-dst-subnet-prob",
        type=float,
        default=0.3,
        help="Probability [0..1] to widen firewall allow rules to the destination subnet",
    )
    ap.add_argument(
        "--nat-mode",
        choices=["SNAT", "MASQUERADE"],
        default="SNAT",
        help="NAT mode when segmentation selects NAT (routers): SNAT or MASQUERADE",
    )
    ap.add_argument(
        "--dnat-prob",
        type=float,
        default=0.0,
        help="Probability [0..1] to create DNAT (port-forward) on routers for generated flows",
    )
    ap.add_argument(
        "--seg-include-hosts",
        action="store_true",
        help="Include host nodes as candidates for segmentation placement (default: routers only)",
    )
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    if args.seed is not None:
        random.seed(args.seed)
        try:
            from .builders.topology import set_global_random_seed
            set_global_random_seed(args.seed)
        except Exception:
            pass

    density_base, weight_items, count_items, services = parse_node_info(args.xml, args.scenario)
    # Optional additive planning metadata (if XML produced by enhanced web UI)
    planning_meta = {}
    try:
        planning_meta = parse_planning_metadata(args.xml, args.scenario) or {}
    except Exception:
        planning_meta = {}
    # First allocate weight-based roles across density base
    base_total = density_base
    if args.max_nodes is not None and args.max_nodes > 0:
        base_total = min(base_total, args.max_nodes)
    role_counts = compute_role_counts(base_total, [(r, f) for r, f in weight_items]) if base_total > 0 else {}
    # Add absolute count rows (subject to max cap)
    additive_total = sum(c for _, c in count_items)
    if args.max_nodes is not None and args.max_nodes > 0:
        remaining = max(0, args.max_nodes - sum(role_counts.values()))
    else:
        remaining = additive_total
    for role, c in count_items:
        to_add = c if args.max_nodes is None else min(c, remaining)
        if to_add <= 0:
            continue
        role_counts[role] = role_counts.get(role, 0) + to_add
        if args.max_nodes is not None:
            remaining -= to_add
            if remaining <= 0:
                break
    effective_total = sum(role_counts.values())
    routing_density, routing_items = parse_routing_info(args.xml, args.scenario)

    core = client.CoreGrpcClient(address=f"{args.host}:{args.port}")
    # Wrap with a logging proxy to trace all gRPC calls
    try:
        from .utils.grpc_logging import wrap_core_client
        core = wrap_core_client(core, logging.getLogger("core_topo_gen.grpc"))
    except Exception:
        pass
    logging.info("[grpc] CoreGrpcClient.connect() -> %s:%s", args.host, args.port)
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
        "router_mesh_style": args.router_mesh,
    "density_base_count": density_base,
    "count_rows_additive_total": sum(c for _, c in count_items),
    "effective_total_nodes": effective_total,
        "count_rows_breakdown": {r: c for r, c in count_items},
        "weight_rows": {r: f for r, f in weight_items},
        "role_counts": role_counts,
    }
    # Merge in planning metadata namespaced to avoid collision
    try:
        if planning_meta:
            if 'node_info' in planning_meta:
                ni = planning_meta['node_info']
                generation_meta.update({
                    'plan_node_base_nodes': ni.get('base_nodes'),
                    'plan_node_additive_nodes': ni.get('additive_nodes'),
                    'plan_node_combined_nodes': ni.get('combined_nodes'),
                    'plan_node_weight_rows': ni.get('weight_rows'),
                    'plan_node_count_rows': ni.get('count_rows'),
                    'plan_node_weight_sum': ni.get('weight_sum'),
                })
            if 'routing' in planning_meta:
                ro = planning_meta['routing']
                generation_meta.update({
                    'plan_routing_explicit': ro.get('explicit_count'),
                    'plan_routing_derived': ro.get('derived_count'),
                    'plan_routing_total': ro.get('total_planned'),
                    'plan_routing_weight_rows': ro.get('weight_rows'),
                    'plan_routing_count_rows': ro.get('count_rows'),
                    'plan_routing_weight_sum': ro.get('weight_sum'),
                })
            if 'vulnerabilities' in planning_meta:
                vu = planning_meta['vulnerabilities']
                generation_meta.update({
                    'plan_vuln_explicit': vu.get('explicit_count'),
                    'plan_vuln_derived': vu.get('derived_count'),
                    'plan_vuln_total': vu.get('total_planned'),
                    'plan_vuln_weight_rows': vu.get('weight_rows'),
                    'plan_vuln_count_rows': vu.get('count_rows'),
                    'plan_vuln_weight_sum': vu.get('weight_sum'),
                })
    except Exception:
        pass
    # Pre-parse vulnerabilities to plan docker-compose assignments mapped to host slots
    docker_slot_plan: dict | None = None
    try:
        vuln_density, vuln_items = parse_vulnerabilities_info(args.xml, args.scenario)
        catalog = load_vuln_catalog(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        total_hosts = sum(role_counts.values())  # total allocated hosts (base + additive)
        slot_names = [f"slot-{i+1}" for i in range(total_hosts)]
        logging.info("Vulnerabilities config: density=%.3f, items=%d (total_hosts=%d)", float(vuln_density or 0.0), len(vuln_items or []), total_hosts)
        assignments_slots = assign_compose_to_nodes(
            slot_names,
            vuln_density or 0.0,
            vuln_items or [],
            catalog,
            out_base="/tmp/vulns",
            require_pulled=False,
            base_host_pool=density_base,
        )
        if assignments_slots:
            docker_slot_plan = assignments_slots
            logging.info("Planned %d docker-compose assignments over %d host slots", len(assignments_slots), len(slot_names))
            try:
                logging.debug("Docker slot keys: %s", ", ".join(sorted(assignments_slots.keys())))
            except Exception:
                pass
        else:
            cnt_items = [it for it in (vuln_items or []) if (it.get('v_metric') == 'Count') or (it.get('selected') == 'Specific' and it.get('v_count'))]
            w_items = [it for it in (vuln_items or []) if it not in cnt_items]
            logging.info("No docker-compose assignments planned (density=%.3f, count_items=%d, weight_items=%d, catalog=%d)", float(vuln_density or 0.0), len(cnt_items), len(w_items), len(catalog or []))
        # Stats
        try:
            cnt_total = 0
            for it in (vuln_items or []):
                if (it.get('v_metric') == 'Count') or (it.get('selected') == 'Specific' and it.get('v_count')):
                    try:
                        vc = int(it.get('v_count') or 0)
                    except Exception:
                        vc = 0
                    if vc > 0:
                        cnt_total += vc
            generation_meta["vuln_density_fraction"] = float(vuln_density or 0.0)
            try:
                import math as _math
                generation_meta["vuln_density_target"] = int(_math.floor((vuln_density or 0.0) * (density_base or 0) + 1e-9))
            except Exception:
                generation_meta["vuln_density_target"] = int(round((vuln_density or 0.0) * density_base))  # fallback
            generation_meta["vuln_count_items_total"] = cnt_total
            generation_meta["vuln_total_planned_additive"] = generation_meta["vuln_density_target"] + cnt_total
            generation_meta["vuln_docker_assignments"] = len(assignments_slots or {})
        except Exception:
            pass
    except Exception as e:
        logging.exception("Vulnerability planning skipped or failed: %s", e)

    # Log DOCKER availability in this CORE wrapper
    try:
        from core.api.grpc.wrappers import NodeType as _NT
        logging.info("CORE Docker node type available: %s", hasattr(_NT, 'DOCKER'))
    except Exception:
        pass
    # If any routing item carries abs_count>0, we should build a segmented topology even if density==0
    has_routing_counts = any(getattr(ri, 'abs_count', 0) and int(getattr(ri, 'abs_count', 0)) > 0 for ri in (routing_items or []))
    if (routing_density and routing_density > 0) or has_routing_counts:
        session, routers, hosts, service_assignments, router_protocols, docker_by_name = build_segmented_topology(
            core,
            role_counts,
            routing_density=routing_density,
            routing_items=routing_items,
            base_host_pool=density_base,
            services=services,
            ip4_prefix=args.prefix,
            ip_mode=args.ip_mode,
            ip_region=args.ip_region,
            layout_density=args.layout_density,
            docker_slot_plan=docker_slot_plan,
            router_mesh_style=args.router_mesh,
        )
        # Merge topo stats if present
        try:
            ts = getattr(session, 'topo_stats', None)
            if isinstance(ts, dict):
                generation_meta.update(ts)
        except Exception:
            pass
    else:
        # Pure host topology (no routers requested)
        session, switches, hosts, service_assignments, docker_by_name = build_star_from_roles(
            core,
            role_counts,
            services=services,
            ip4_prefix=args.prefix,
            ip_mode=args.ip_mode,
            ip_region=args.ip_region,
            layout_density=args.layout_density,
            docker_slot_plan=docker_slot_plan,
        )
        # Align function return signature with segmented path
        router_protocols = {}
        routers = []

    # Log which docker nodes were actually created by the builders
    try:
        if docker_by_name:
            logging.info("Docker nodes created: %d -> %s", len(docker_by_name), ", ".join(sorted(docker_by_name.keys())))
        else:
            logging.info("No docker nodes created by topology builders (either no assignments or NodeType.DOCKER unavailable)")
    except Exception:
        pass

    # Parse segmentation and apply policies/services
    seg_summary = None
    try:
        seg_density, seg_items = parse_segmentation_info(args.xml, args.scenario)
        logging.info("Segmentation config: density=%.3f, items=%d", float(seg_density or 0.0), len(seg_items or []))
        if seg_density and seg_density > 0 and seg_items:
            try:
                from .utils.segmentation import plan_and_apply_segmentation
                seg_summary = plan_and_apply_segmentation(
                    session,
                    routers if 'routers' in locals() else [],
                    hosts,
                    seg_density,
                    seg_items,
                    nat_mode=str(getattr(args, 'nat_mode', 'SNAT')).upper(),
                    include_hosts=bool(getattr(args, 'seg_include_hosts', False)),
                )
                logging.info("Applied segmentation rules: %d", len(seg_summary.get("rules", [])))
            except Exception as e:
                logging.warning("Failed applying segmentation: %s", e)
        else:
            logging.info("Segmentation disabled or unspecified; skipping")
    except Exception as e:
        logging.warning("Segmentation parse/apply error: %s", e)

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
            # Ensure firewall allows the generated traffic
            try:
                from .utils.segmentation import write_allow_rules_for_flows, write_dnat_for_flows
                write_allow_rules_for_flows(
                    session,
                    routers if 'routers' in locals() else [],
                    hosts,
                    os.path.join(traffic_out_dir, "traffic_summary.json"),
                    out_dir="/tmp/segmentation",
                    src_subnet_prob=max(0.0, min(1.0, float(getattr(args, 'allow_src_subnet_prob', 0.3)))),
                    dst_subnet_prob=max(0.0, min(1.0, float(getattr(args, 'allow_dst_subnet_prob', 0.3)))),
                    include_hosts=bool(getattr(args, 'seg_include_hosts', False)),
                )
                logging.info("Inserted allow rules for generated traffic")
                # Optional DNAT port-forwarding
                dnat_p = max(0.0, min(1.0, float(getattr(args, 'dnat_prob', 0.0))))
                if dnat_p > 0:
                    write_dnat_for_flows(
                        session,
                        routers if 'routers' in locals() else [],
                        hosts,
                        os.path.join(traffic_out_dir, "traffic_summary.json"),
                        out_dir="/tmp/segmentation",
                        dnat_prob=dnat_p,
                    )
                    logging.info("Inserted DNAT rules for some flows (prob=%.2f)", dnat_p)
            except Exception as e:
                logging.warning("Failed to insert allow rules for traffic: %s", e)

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
            # Log full traceback for diagnostics and attempt a safe fallback
            logging.exception("Failed generating traffic scripts: %s", e)
            try:
                # Map unknown kinds to TCP to avoid legacy KeyErrors; keep TCP/UDP/RANDOM/CUSTOM as-is
                safe_items = []
                for ti in (traffic_items or []):
                    kind_u = (ti.kind or "").upper()
                    if kind_u not in ("TCP", "UDP", "RANDOM", "CUSTOM"):
                        kind_u = "TCP"
                    # create a shallow clone with adjusted kind
                    from .types import TrafficInfo as _TI
                    safe_items.append(_TI(
                        kind=kind_u,
                        factor=ti.factor,
                        pattern=ti.pattern,
                        rate_kbps=ti.rate_kbps,
                        period_s=ti.period_s,
                        jitter_pct=ti.jitter_pct,
                        content_type=ti.content_type,
                    ))
                traffic_map = generate_traffic_scripts(hosts, traffic_density, safe_items, out_dir=traffic_out_dir)
                logging.warning("Traffic generation succeeded after fallback to safe kinds (unknown kinds -> TCP)")
            except Exception as e2:
                logging.warning("Fallback traffic generation also failed: %s", e2)
    else:
        logging.info("Traffic disabled or density is 0; skipping traffic generation and service enablement")

    # Write scenario report (Markdown) under ./reports/
    try:
        import time as _time
        from datetime import datetime as _dt
        # Always write reports under the repository root's ./reports directory
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        report_dir = os.path.join(repo_root, "reports")
        os.makedirs(report_dir, exist_ok=True)
        traffic_summary_path = os.path.join(traffic_out_dir, "traffic_summary.json")
        # Use a high-resolution timestamp to avoid same-second filename collisions across runs
        _ts = _dt.now().strftime("%Y%m%d-%H%M%S-%f")
        report_path = os.path.join(report_dir, f"scenario_report_{_ts}.md")
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
        # Vulnerabilities (load catalog locally to avoid dependency on earlier planning block)
        vuln_density, vuln_items = parse_vulnerabilities_info(args.xml, args.scenario)
        vulnerabilities_cfg = {"density": vuln_density, "items": vuln_items or []}
        try:
            _repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            catalog_local = load_vuln_catalog(_repo_root)
            selected_vulns = select_vulnerabilities(vuln_density or 0.0, vuln_items or [], catalog_local)
            if selected_vulns:
                logging.info("Selected %d vulnerabilities based on criteria", len(selected_vulns))
                results = process_vulnerabilities(selected_vulns, out_dir="/tmp/vulns")
                ok_count = sum(1 for _rec, _act, ok, _dir in results if ok)
                logging.info("Vulnerability processing done: %d/%d ok", ok_count, len(results))
                # Prepare per-node docker-compose files matching docker nodes created (by name)
                try:
                    # Collect mapping name->rec of docker nodes actually created by builders
                    name_to_vuln = {}
                    try:
                        # Prefer function returns when available via locals
                        if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                            name_to_vuln.update(docker_by_name)
                    except Exception:
                        pass
                    # Fallback: reconstruct from slot plan and current session nodes order if needed
                    if not name_to_vuln and docker_slot_plan:
                        try:
                            # Iterate session nodes in creation order if possible
                            # Note: this is best-effort and may not exactly match slot numbering
                            idx = 0
                            for ni in hosts:
                                try:
                                    node_obj = session.get_node(ni.node_id)
                                    nm = getattr(node_obj, 'name', None)
                                except Exception:
                                    nm = None
                                if nm:
                                    slot_key = f"slot-{idx+1}"
                                    if slot_key in docker_slot_plan:
                                        name_to_vuln[nm] = docker_slot_plan[slot_key]
                                    idx += 1
                        except Exception:
                            pass
                    if name_to_vuln:
                        created = prepare_compose_for_assignments(name_to_vuln, out_base="/tmp/vulns")
                        logging.info("Prepared per-node compose files: %d for %d docker nodes", len(created), len(name_to_vuln))
                        # Do not start compose stacks here; CORE will start docker nodes during session start
                        # This avoids container name conflicts when CORE brings up containers automatically.
                        # Write a small summary for web/ops
                        try:
                            import json as _json, time as _time
                            summary = {
                                'timestamp': int(_time.time()),
                                'assignments': { n: {'Name': r.get('Name'), 'Path': r.get('Path'), 'Vector': r.get('Vector') } for n, r in name_to_vuln.items() },
                                'files': created,
                            }
                            with open('/tmp/vulns/compose_assignments.json', 'w', encoding='utf-8') as f:
                                _json.dump(summary, f, indent=2)
                            logging.info("Compose assignments prepared for %d docker nodes; startup deferred to CORE session", len(created))
                        except Exception:
                            pass
                    else:
                        logging.info("No docker nodes present after build; skipping compose prep")
                except Exception as e2:
                    logging.debug("Per-node compose prepare/assign skipped or failed: %s", e2)
            else:
                logging.info("No vulnerabilities selected (empty catalog or criteria)")
        except Exception as e:
            logging.warning("Vulnerability processing failed: %s", e)
        seg_out_dir = "/tmp/segmentation"
        seg_summary_path = os.path.join(seg_out_dir, "segmentation_summary.json")
        segmentation_cfg = {
            "density": seg_density if 'seg_density' in locals() else None,
            "items": [{"name": i.name, "factor": i.factor} for i in (seg_items or [])] if 'seg_items' in locals() and seg_items else [],
        }
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
                segmentation_summary_path=seg_summary_path if os.path.exists(seg_summary_path) else None,
                metadata=generation_meta,
                routing_cfg=routing_cfg,
                traffic_cfg=traffic_cfg,
                services_cfg=services_cfg,
                segmentation_cfg=segmentation_cfg,
                vulnerabilities_cfg=vulnerabilities_cfg,
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
                segmentation_summary_path=seg_summary_path if os.path.exists(seg_summary_path) else None,
                metadata=generation_meta,
                routing_cfg=routing_cfg,
                traffic_cfg=traffic_cfg,
                services_cfg=services_cfg,
                segmentation_cfg=segmentation_cfg,
                vulnerabilities_cfg=vulnerabilities_cfg,
            )
        logging.info("Scenario report written to %s", report_path)
        # Also emit a plain stdout line for robust parsing by web frontends
        try:
            print(f"Scenario report written to {report_path}", flush=True)
        except Exception:
            pass
    except Exception as e:
        logging.exception("Failed to write scenario report: %s", e)

    # Start the CORE session only after all services (including Traffic) are applied
    try:
        # Emit session id in a parseable form for webapp backend to capture
        try:
            sid = getattr(session, 'id', None) or getattr(session, 'session_id', None)
            if sid is not None:
                logging.info("CORE_SESSION_ID: %s", sid)
        except Exception:
            pass
        # CORE client expects the session object (uses session.to_proto()).
        core.start_session(session)
        logging.info("CORE session started")
    except Exception as e:
        logging.exception("Failed to start CORE session: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

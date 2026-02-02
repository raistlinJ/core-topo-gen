from __future__ import annotations
import argparse
import datetime
import json
import logging
import random
import os
from xml.etree import ElementTree as ET
from typing import Any, Dict, Tuple

try:  # pragma: no cover - exercised indirectly via CLI subprocess tests
    from core.api.grpc import client  # type: ignore
    CORE_GRPC_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - fallback path executed in CI without CORE
    client = None  # type: ignore
    CORE_GRPC_AVAILABLE = False
from .types import NodeInfo
from .parsers.node_info import parse_node_info
from .parsers.routing import parse_routing_info
from .parsers.traffic import parse_traffic_info
from .parsers.segmentation import parse_segmentation_info
from .parsers.vulnerabilities import parse_vulnerabilities_info
from .parsers.planning_metadata import parse_planning_metadata
from .parsers.services import parse_services
from .parsers.hitl import parse_hitl_info
from .utils.segmentation import apply_preview_segmentation_rules
from .utils.allocation import compute_role_counts
from .builders.topology import build_star_from_roles, build_segmented_topology, build_multi_switch_topology
from .utils.traffic import generate_traffic_scripts
from .utils.report import write_report
from .utils.vuln_process import (
    load_vuln_catalog,
    select_vulnerabilities,
    process_vulnerabilities,
    prepare_compose_for_nodes,
    prepare_compose_for_assignments,
    assign_compose_to_nodes,
    detect_docker_conflicts_for_compose_files,
    remove_docker_conflicts,
)


def _flow_state_from_xml(xml_path: str, scenario_name: str | None) -> dict[str, Any] | None:
    if not xml_path or not os.path.exists(xml_path):
        return None
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return None
    scen_el = None
    try:
        scenarios = root.findall('.//Scenario')
        if scenario_name:
            for sc in scenarios:
                nm = (sc.get('name') or '').strip()
                if nm and nm == str(scenario_name).strip():
                    scen_el = sc
                    break
        if scen_el is None and scenarios:
            scen_el = scenarios[0]
    except Exception:
        scen_el = None
    if scen_el is None:
        return None
    try:
        flow_el = scen_el.find('.//FlagSequencing/FlowState')
        if flow_el is None:
            return None
        raw = (flow_el.text or '').strip()
        if not raw:
            return None
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _export_flow_assignments_to_env(xml_path: str, scenario_name: str | None) -> None:
    try:
        fs = _flow_state_from_xml(xml_path, scenario_name)
        assigns = fs.get('flag_assignments') if isinstance(fs, dict) else None
        if isinstance(assigns, list) and assigns:
            os.environ['CORETG_FLOW_ASSIGNMENTS_JSON'] = json.dumps(assigns, ensure_ascii=False)
    except Exception:
        pass
from .utils.services import ensure_service
from .utils.hitl import attach_hitl_rj45_nodes

# Ensure planning.full_preview is importable even if an older installed core_topo_gen shadows repo version
try:  # pragma: no cover
    from .planning.full_preview import build_full_preview  # noqa: F401
except ModuleNotFoundError:
    # Fallback not required in tests; skip if unavailable
    pass


def _load_preview_plan_from_xml(preview_plan_path: str, scenario_label: str | None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load a preview/flow plan from ScenarioEditor/PlanPreview embedded in XML."""
    if not os.path.exists(preview_plan_path):
        raise ValueError(f"preview plan XML not found: {preview_plan_path}")
    try:
        tree = ET.parse(preview_plan_path)
        root = tree.getroot()
    except Exception as exc:
        raise ValueError(f"failed to parse preview plan XML: {exc}")

    scenario_norm = (scenario_label or '').strip().lower()
    se_target = None
    try:
        if root.tag == 'ScenarioEditor':
            se_target = root
        elif root.tag == 'Scenario':
            se_target = root.find('ScenarioEditor')
        elif root.tag == 'Scenarios':
            for scen_el in root.findall('Scenario'):
                name = (scen_el.get('name') or '').strip()
                if scenario_norm and name.strip().lower() != scenario_norm:
                    continue
                se_target = scen_el.find('ScenarioEditor')
                if se_target is not None:
                    break
    except Exception:
        se_target = None

    if se_target is None:
        raise ValueError('ScenarioEditor not found in preview plan XML')
    plan_el = se_target.find('PlanPreview')
    raw = (plan_el.text or '').strip() if plan_el is not None else ''
    if not raw:
        raise ValueError('PlanPreview missing in preview plan XML')
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ValueError(f"PlanPreview invalid JSON: {exc}")
    if not isinstance(payload, dict):
        raise ValueError('preview plan must be a JSON object')

    full_preview = payload.get('full_preview')
    if isinstance(full_preview, dict):
        return payload, full_preview

    # Backward-compat: treat the whole JSON object as a full_preview payload.
    if any(k in payload for k in ('nodes', 'links', 'display_artifacts', 'flow', 'metadata')):
        wrapped = {'full_preview': payload, 'metadata': {}}
        return wrapped, payload

    raise ValueError('unrecognized preview plan format (expected {"full_preview": {...}})')


def _load_preview_plan(preview_plan_path: str, scenario_label: str | None = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load a persisted preview/flow plan JSON or embedded PlanPreview from XML."""
    if preview_plan_path.lower().endswith('.xml'):
        return _load_preview_plan_from_xml(preview_plan_path, scenario_label)
    with open(preview_plan_path, 'r', encoding='utf-8') as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError('preview plan must be a JSON object')

    full_preview = payload.get('full_preview')
    if isinstance(full_preview, dict):
        return payload, full_preview

    # Backward-compat: treat the whole JSON object as a full_preview payload.
    # Heuristic: full_preview is expected to have node/link collections and/or display artifacts.
    if any(k in payload for k in ('nodes', 'links', 'display_artifacts', 'flow', 'metadata')):
        wrapped = {'full_preview': payload, 'metadata': {}}
        return wrapped, payload

    raise ValueError('unrecognized preview plan format (expected {"full_preview": {...}})')


def _run_offline_report(
    args,
    role_counts: Dict[str, int],
    routing_items: list,
    services: list,
    orchestrated_plan: Dict[str, Any],
    generation_meta: Dict[str, Any],
):
    """Generate a report without contacting core-daemon.

    This path is used in CI where CORE gRPC is unavailable. It mirrors the
    report-writing branch and emits the canonical stdout line so web code can parse it.
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    # Build minimal configs from XML for inclusion in the report metadata
    try:
        routing_density, routing_items2 = parse_routing_info(args.xml, args.scenario)
    except Exception:
        routing_density, routing_items2 = None, []
    routing_cfg = {
        "density": routing_density,
        "items": [{
            "protocol": getattr(i, 'protocol', ''),
            "factor": getattr(i, 'factor', 0.0),
        } for i in (routing_items2 or [])],
    }

    try:
        traffic_density, traffic_items = parse_traffic_info(args.xml, args.scenario)
    except Exception:
        traffic_density, traffic_items = None, []
    traffic_cfg = {
        "density": traffic_density,
        "items": [{
            "kind": getattr(i, 'kind', ''),
            "factor": getattr(i, 'factor', 0.0),
            "pattern": getattr(i, 'pattern', ''),
            "rate_kbps": getattr(i, 'rate_kbps', 0.0),
            "period_s": getattr(i, 'period_s', 0.0),
            "jitter_pct": getattr(i, 'jitter_pct', 0.0),
            "content_type": getattr(i, 'content_type', ''),
        } for i in (traffic_items or [])],
    }

    try:
        services_list = parse_services(args.xml, args.scenario)
    except Exception:
        services_list = []
    services_cfg = [
        {"name": getattr(s, 'name', ''), "factor": getattr(s, 'factor', 0.0), "density": getattr(s, 'density', 0.0)}
        for s in (services_list or [])
    ]

    try:
        seg_density, seg_items = parse_segmentation_info(args.xml, args.scenario)
    except Exception:
        seg_density, seg_items = None, []
    segmentation_cfg = {
        "density": seg_density,
        "items": [
            {"name": getattr(i, 'name', ''), "factor": getattr(i, 'factor', 0.0)}
            for i in (seg_items or [])
        ] if seg_items else [],
    }

    try:
        vuln_density, vuln_items, vuln_flag_type = parse_vulnerabilities_info(args.xml, args.scenario)
    except Exception:
        vuln_density, vuln_items, vuln_flag_type = None, [], None
    vulnerabilities_cfg = {
        "density": vuln_density,
        "items": vuln_items or [],
        "flag_type": vuln_flag_type,
    }

    from datetime import datetime as _dt
    report_dir = os.path.join(repo_root, "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"scenario_report_{_dt.now().strftime('%Y%m%d-%H%M%S-%f')}.md")

    report_path, summary_path = write_report(
        report_path,
        args.scenario,
        routers=[],
        router_protocols={},
        switches=[],
        hosts=[],
        service_assignments={},
        traffic_summary_path=None,
        segmentation_summary_path=None,
        metadata=generation_meta,
        routing_cfg=routing_cfg,
        traffic_cfg=traffic_cfg,
        services_cfg=services_cfg,
        segmentation_cfg=segmentation_cfg,
        vulnerabilities_cfg=vulnerabilities_cfg,
    )

    logging.info("Scenario report written to %s", report_path)
    try:
        print(f"Scenario report written to {report_path}", flush=True)
    except Exception:
        pass
    if summary_path:
        logging.info("Scenario summary written to %s", summary_path)
        try:
            print(f"Scenario summary written to {summary_path}", flush=True)
        except Exception:
            pass
    return 0

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
    ap.add_argument("--preview", action="store_true", help="Parse and plan only; output plan summary JSON and exit 0")
    ap.add_argument("--preview-full", action="store_true", help="Generate a full dry-run plan (routers, hosts, IPs, services, vulnerabilities, segmentation) without contacting CORE; implies --preview style output")
    ap.add_argument("--plan-output", help="Path to write computed plan JSON (preview or build)")
    ap.add_argument("--preview-plan", help="Path to a persisted full preview JSON to reuse during build")
    # Preview always recomputes (plan reuse removed)
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
    ap.add_argument(
        "--seg-allow-docker-ports",
        action="store_true",
        help="Allow docker-compose container ports through host INPUT chains when segmentation enforces default-deny",
    )

    ap.add_argument(
        "--docker-check-conflicts",
        action="store_true",
        default=True,
        help="Check for existing Docker containers/images that could conflict with compose-based Docker nodes (default: on)",
    )
    ap.add_argument(
        "--no-docker-check-conflicts",
        dest="docker_check_conflicts",
        action="store_false",
        help="Disable Docker conflict checks",
    )
    ap.add_argument(
        "--docker-remove-conflicts",
        action="store_true",
        help="Automatically remove conflicting Docker containers/images instead of prompting",
    )
    args = ap.parse_args()

    preview_payload: Dict[str, Any] | None = None
    preview_full: Dict[str, Any] | None = None
    preview_plan_path: str | None = None
    if args.preview_plan:
        preview_plan_path = os.path.abspath(args.preview_plan)
        try:
            preview_payload, preview_full = _load_preview_plan(preview_plan_path, args.scenario)
            logging.getLogger(__name__).info("Loaded preview plan from %s", preview_plan_path)
        except Exception as e:
            logging.getLogger(__name__).error("Failed loading preview plan %s: %s", preview_plan_path, e)
            raise SystemExit(1)
        if args.seed is None:
            try:
                seed_candidate = preview_payload.get('metadata', {}).get('seed') if isinstance(preview_payload, dict) else None
            except Exception:
                seed_candidate = None
            if seed_candidate is None and isinstance(preview_full, dict):
                seed_candidate = preview_full.get('seed')
            if isinstance(seed_candidate, int):
                args.seed = seed_candidate

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    # Expose FlowState assignments so compose prep can overlay flow artifacts.
    try:
        _export_flow_assignments_to_env(args.xml, args.scenario)
    except Exception:
        pass

    if args.seed is not None:
        random.seed(args.seed)
        try:
            from .builders.topology import set_global_random_seed
            set_global_random_seed(args.seed)
        except Exception:
            pass

    # Single-pass planning/build
    logging.info("PHASE: Parse scenario inputs")

    # Unified planning via orchestrator (still parse node_info early for some legacy metadata requirements)
    density_base, weight_items, count_items, services = parse_node_info(args.xml, args.scenario)
    # Optional additive planning metadata (if XML produced by enhanced web UI)
    planning_meta = {}
    try:
        planning_meta = parse_planning_metadata(args.xml, args.scenario) or {}
    except Exception:
        planning_meta = {}
    try:
        hitl_config = parse_hitl_info(args.xml, args.scenario) or {"enabled": False, "interfaces": []}
    except Exception:
        hitl_config = {"enabled": False, "interfaces": []}
    scenario_key = args.scenario
    if not scenario_key:
        try:
            scenario_key = os.path.splitext(os.path.basename(args.xml))[0]
        except Exception:
            scenario_key = "__default__"
    hitl_config.setdefault("scenario_key", scenario_key)
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
    logging.info("PHASE: Role counts computed (hosts=%d)", effective_total)
    routing_density, routing_items = parse_routing_info(args.xml, args.scenario)
    # Derive R2R / R2S policy directly from the first routing item with a mode (no averaging)
    r2r_policy_plan = None
    r2s_policy_plan = None
    if routing_items:
        try:
            first_r2r = next((ri for ri in routing_items if getattr(ri,'r2r_mode',None)), None)
            if first_r2r:
                m = getattr(first_r2r, 'r2r_mode', '')
                if m == 'Exact' and getattr(first_r2r, 'r2r_edges', 0) > 0:
                    r2r_policy_plan = { 'mode': 'Exact', 'target_degree': int(getattr(first_r2r,'r2r_edges',0)) }
                elif m:
                    r2r_policy_plan = { 'mode': m }
            first_r2s = next((ri for ri in routing_items if getattr(ri,'r2s_mode',None)), None)
            if first_r2s:
                m2_raw = getattr(first_r2s, 'r2s_mode', '') or ''
                m2 = m2_raw.strip()
                m2_norm = m2.lower()
                edges_raw = getattr(first_r2s,'r2s_edges',0)
                try: edges_val = int(edges_raw)
                except Exception: edges_val = 0
                if m2_norm == 'exact' and edges_val > 0:
                    r2s_policy_plan = { 'mode': 'Exact', 'target_per_router': edges_val }
                elif m2:
                    r2s_policy_plan = { 'mode': m2 }
        except Exception:
            pass

    preview_router_count: int | None = None
    if preview_full:
        try:
            hosts_preview = preview_full.get('hosts') or []
            if isinstance(hosts_preview, list):
                preview_role_counts: Dict[str, int] = {}
                for h in hosts_preview:
                    role = (h.get('role') if isinstance(h, dict) else None) or 'Host'
                    preview_role_counts[role] = preview_role_counts.get(role, 0) + 1
                if preview_role_counts:
                    role_counts = preview_role_counts
                    effective_total = sum(preview_role_counts.values())
        except Exception as e_rc:
            logging.getLogger(__name__).warning("Preview plan role expansion failed: %s", e_rc)
        try:
            routers_preview = preview_full.get('routers') or []
            if isinstance(routers_preview, list):
                preview_router_count = len(routers_preview)
        except Exception:
            preview_router_count = None

    # Orchestrator full plan (centralized)
    logging.info("PHASE: Planning topology")
    from .planning.orchestrator import compute_full_plan
    orchestrated_plan = compute_full_plan(args.xml, scenario=args.scenario, seed=args.seed, include_breakdowns=True)
    if not args.scenario and isinstance(orchestrated_plan, dict):
        derived_key = orchestrated_plan.get("scenario_name") or orchestrated_plan.get("scenario_key")
        if derived_key:
            hitl_config["scenario_key"] = derived_key
    prelim_router_count = orchestrated_plan['routers_planned']
    if preview_router_count is not None and preview_router_count > 0:
        prelim_router_count = preview_router_count
        orchestrated_plan['routers_planned'] = preview_router_count
    service_plan = orchestrated_plan.get('service_plan') or {}
    vulnerabilities_plan = orchestrated_plan.get('vulnerability_plan')
    routing_plan = orchestrated_plan.get('breakdowns', {}).get('router', {}).get('simple_plan', {})
    router_plan_breakdown = orchestrated_plan.get('breakdowns', {}).get('router', {})
    seg_breakdown = orchestrated_plan.get('breakdowns', {}).get('segmentation', {}) if orchestrated_plan else {}
    seg_density_plan = seg_breakdown.get('density') if isinstance(seg_breakdown, dict) else None
    seg_items_serialized = seg_breakdown.get('raw_items_serialized') if isinstance(seg_breakdown, dict) else None
    traffic_plan_preview = orchestrated_plan.get('traffic_plan') if isinstance(orchestrated_plan, dict) else None
    if preview_full is None:
        try:
            preview_full = build_full_preview(
                role_counts=role_counts,
                routers_planned=prelim_router_count,
                services_plan=service_plan,
                vulnerabilities_plan=vulnerabilities_plan,
                r2r_policy=r2r_policy_plan,
                r2s_policy=r2s_policy_plan,
                routing_items=routing_items,
                routing_plan=routing_plan,
                segmentation_density=seg_density_plan,
                segmentation_items=seg_items_serialized,
                traffic_plan=traffic_plan_preview,
                seed=args.seed,
                ip4_prefix=args.prefix,
                ip_mode=args.ip_mode,
                ip_region=args.ip_region,
                base_scenario=orchestrated_plan.get('base_scenario'),
            )
        except Exception as auto_prev_exc:
            logging.getLogger(__name__).warning("Failed to generate automatic full preview: %s", auto_prev_exc)
    if preview_full and isinstance(router_plan_breakdown, dict):
        preview_full.setdefault('router_plan', router_plan_breakdown)
    logging.info(
        "PHASE: Planning complete (routers=%s hosts=%s)",
        prelim_router_count,
        effective_total,
    )
    try:
        from .planning.plan_builder import build_initial_pool
        from .planning.constraints import validate_pool_final
        # Vulnerabilities: reuse earlier parsing if available in generation_meta (planning_meta done above). We recompute minimally.
        try:
            from .parsers.vulnerabilities import parse_vulnerabilities_info
            from .planning.vulnerability_plan import VulnerabilityItem, compute_vulnerability_plan
            vuln_density, vuln_items_xml, _vuln_flag_type = parse_vulnerabilities_info(args.xml, args.scenario)
            vuln_items: list[VulnerabilityItem] = []
            for it in (vuln_items_xml or []):
                name = (it.get('selected') or '').strip() or 'Item'
                vm_raw = (it.get('v_metric') or '').strip()
                vm = vm_raw or ('Count' if (it.get('selected') or '').strip() == 'Specific' and (it.get('v_count') or '').strip() else 'Weight')
                abs_count = 0
                if vm.lower() == 'count':
                    try:
                        abs_count = int(it.get('v_count') or 0)
                    except Exception:
                        abs_count = 0
                try:
                    factor_val = float(it.get('factor') or 0.0)
                except Exception:
                    factor_val = 0.0
                kind = (it.get('selected') or name)
                vuln_items.append(VulnerabilityItem(name=name, density=vuln_density, abs_count=abs_count, kind=kind, factor=factor_val, metric=vm))
            vplan, vbreak = compute_vulnerability_plan(base_total, vuln_density, vuln_items)
            if vplan:
                vulnerabilities_plan = vplan
        except Exception:
            pass
        pool = build_initial_pool(role_counts, prelim_router_count, service_plan, routing_plan, router_breakdown=router_plan_breakdown, r2r_policy=r2r_policy_plan, vulnerabilities_plan=vulnerabilities_plan)
        if preview_full:
            try:
                pool.full_preview = preview_full
            except Exception:
                pass
        if args.preview or args.preview_full:
            import json, sys
            summary = pool.summarize()
            # Provide r2s/r2r placeholders if not yet populated by builders so UI/report
            # can render consistent sections.
            if 'r2r_policy' in summary and summary['r2r_policy'] is None:
                summary['r2r_policy'] = r2r_policy_plan
            if 'r2s_policy' not in summary or summary['r2s_policy'] is None:
                summary['r2s_policy'] = r2s_policy_plan
            # Resolved expansions (already added in summarize) but ensure deterministic ordering
            try:
                if isinstance(summary.get('role_assignment_preview'), list):
                    summary['role_assignment_preview'] = list(summary['role_assignment_preview'])
            except Exception:
                pass
            violations = validate_pool_final(summary)
            # Attach orchestrator plan for parity with web preview
            out = {"plan": summary, "violations": violations, "orchestrator_plan": orchestrated_plan}
            if args.preview_full:
                try:
                    if preview_full:
                        full_prev = preview_full
                    else:
                        # Derive r2s policy summary (mirror earlier plan pass) for preview fidelity
                        r2s_policy_plan = None
                        try:
                            first_r2s = next((ri for ri in routing_items if getattr(ri,'r2s_mode',None)), None)
                            if first_r2s:
                                m2_raw = getattr(first_r2s, 'r2s_mode', '') or ''
                                m2 = m2_raw.strip()
                                m2_norm = m2.lower()
                                edges_raw = getattr(first_r2s,'r2s_edges',0)
                                try: edges_val = int(edges_raw)
                                except Exception: edges_val = 0
                                if m2_norm == 'exact' and edges_val > 0:
                                    r2s_policy_plan = { 'mode': 'Exact', 'target_per_router': edges_val }
                                elif m2:
                                    r2s_policy_plan = { 'mode': m2 }
                        except Exception:
                            pass
                        full_prev = build_full_preview(
                            role_counts=role_counts,
                            routers_planned=prelim_router_count,
                            services_plan=service_plan,
                            vulnerabilities_plan=vulnerabilities_plan,
                            r2r_policy=r2r_policy_plan,
                            r2s_policy=r2s_policy_plan,
                            routing_items=routing_items,
                            routing_plan=routing_plan,
                            segmentation_density=orchestrated_plan.get('breakdowns', {}).get('segmentation', {}).get('density'),
                            segmentation_items=orchestrated_plan.get('breakdowns', {}).get('segmentation', {}).get('raw_items_serialized'),
                            seed=args.seed,
                            ip4_prefix=args.prefix,
                            ip_mode=args.ip_mode,
                            ip_region=args.ip_region,
                            base_scenario=orchestrated_plan.get('base_scenario'),
                        )
                    full_prev['router_plan'] = router_plan_breakdown
                    out['full_preview'] = full_prev
                except Exception as e:
                    out['full_preview_error'] = str(e)
            print(json.dumps(out, indent=2, sort_keys=True))
            if args.plan_output:
                try:
                    with open(args.plan_output, 'w', encoding='utf-8') as wf:
                        json.dump(out, wf, indent=2, sort_keys=True)
                except Exception as e:
                    print(f"WARN: failed to write plan file {args.plan_output}: {e}", file=sys.stderr)
            return
        else:
            if args.plan_output:
                try:
                    import json
                    with open(args.plan_output, 'w', encoding='utf-8') as wf:
                        json.dump({"plan": pool.summarize()}, wf, indent=2, sort_keys=True)
                except Exception:
                    pass
    except Exception:
        pass

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
        "hitl_enabled": bool(hitl_config.get("enabled")),
        "hitl_interface_count": len(hitl_config.get("interfaces") or []),
    }
    if preview_full:
        try:
            generation_meta['preview_router_count'] = len(preview_full.get('routers') or [])
            generation_meta['preview_host_total'] = len(preview_full.get('hosts') or [])
        except Exception:
            pass
    if preview_plan_path:
        generation_meta['preview_plan_path'] = preview_plan_path
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

    if not CORE_GRPC_AVAILABLE:
        return _run_offline_report(
            args,
            role_counts,
            routing_items,
            services,
            orchestrated_plan,
            generation_meta,
        )

    core = client.CoreGrpcClient(address=f"{args.host}:{args.port}")
    # Wrap with retry proxy to handle transient GOAWAY/ping_timeout errors
    try:
        from .utils.grpc_retry import wrap_core_client as wrap_core_client_retry
        core = wrap_core_client_retry(core, logging.getLogger("core_topo_gen.grpc"))
    except Exception:
        pass
    # Wrap with a logging proxy to trace all gRPC calls
    try:
        from .utils.grpc_logging import wrap_core_client as wrap_core_client_logging
        core = wrap_core_client_logging(core, logging.getLogger("core_topo_gen.grpc"))
    except Exception:
        pass
    logging.info("[grpc] CoreGrpcClient.connect() -> %s:%s", args.host, args.port)
    core.connect()
    try:
        from .utils.grpc_helpers import start_grpc_keepalive
        start_grpc_keepalive(core)
    except Exception:
        pass
    # Pre-parse vulnerabilities to plan docker-compose assignments mapped to host slots (reuse orchestrator raw)
    docker_slot_plan: dict | None = None
    preview_vuln_slots: list[str] = []
    seed_for_vuln = args.seed
    try:
        if seed_for_vuln is None and isinstance(preview_full, dict):
            seed_raw = preview_full.get('seed')
            if seed_raw is not None:
                seed_for_vuln = int(seed_raw)
    except Exception:
        seed_for_vuln = args.seed
    try:
        if isinstance(preview_full, dict):
            vbn = preview_full.get('vulnerabilities_by_node') or preview_full.get('vulnerabilities_preview') or {}
            host_ids: list[int] = []
            if isinstance(vbn, dict):
                for key in vbn.keys():
                    try:
                        host_ids.append(int(key))
                    except Exception:
                        continue
            if host_ids:
                hosts_preview = preview_full.get('hosts') or []
                if isinstance(hosts_preview, list):
                    ordered_hosts = sorted(hosts_preview, key=lambda h: (h.get('node_id', 0) if isinstance(h, dict) else 0))
                    slot_map: dict[int, str] = {}
                    for idx, h in enumerate(ordered_hosts):
                        try:
                            hid = int(h.get('node_id'))
                        except Exception:
                            continue
                        slot_map[hid] = f"slot-{idx+1}"
                    for hid in host_ids:
                        slot = slot_map.get(hid)
                        if slot:
                            preview_vuln_slots.append(slot)
    except Exception:
        preview_vuln_slots = []
    try:
        vuln_density = None
        vuln_items = []
        try:
            vuln_density = orchestrated_plan.get('breakdowns', {}).get('vulnerabilities', {}).get('density_input')
        except Exception:
            pass
        if not vuln_items:
            vuln_items = orchestrated_plan.get('vulnerability_items_raw') or []
        if not vuln_density:
            # fallback legacy parse
            vuln_density, vuln_items, vuln_flag_type = parse_vulnerabilities_info(args.xml, args.scenario)
        catalog = load_vuln_catalog(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        total_hosts = sum(role_counts.values())  # total allocated hosts (base + additive)
        slot_names = [f"slot-{i+1}" for i in range(total_hosts)]
        if preview_vuln_slots:
            seen = set()
            ordered_slots: list[str] = []
            for slot in preview_vuln_slots:
                if slot in slot_names and slot not in seen:
                    ordered_slots.append(slot)
                    seen.add(slot)
            for slot in slot_names:
                if slot not in seen:
                    ordered_slots.append(slot)
            slot_names = ordered_slots
            logging.info("Using preview vulnerability slot ordering (%d slots prioritized)", len(preview_vuln_slots))
        logging.info("Vulnerabilities config: density=%.3f, items=%d (total_hosts=%d)", float(vuln_density or 0.0), len(vuln_items or []), total_hosts)
        assignments_slots = assign_compose_to_nodes(
            slot_names,
            vuln_density or 0.0,
            vuln_items or [],
            catalog,
            out_base="/tmp/vulns",
            require_pulled=False,
            base_host_pool=density_base,
            seed=seed_for_vuln,
            shuffle_nodes=not bool(preview_vuln_slots),
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
        from core.api.grpc.wrappers import NodeType as _NT  # type: ignore
        logging.info("CORE Docker node type available: %s", hasattr(_NT, 'DOCKER'))
    except Exception:
        pass
    # If any routing item carries abs_count>0, we should build a segmented topology even if density==0
    has_routing_counts = any(getattr(ri, 'abs_count', 0) and int(getattr(ri, 'abs_count', 0)) > 0 for ri in (routing_items or []))
    # Always build directly from current scenario plan (phased path removed)
    logging.info("PHASE: Building topology")
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
            preview_plan=preview_full,
        )
        # Preview parity signal (authoritative when preview_full was provided)
        try:
            ts = getattr(session, 'topo_stats', None)
            realized = bool(ts.get('preview_realized')) if isinstance(ts, dict) else False
            logging.info("Preview parity: preview_attached=%s preview_realized=%s", bool(preview_full), realized)
            try:
                generation_meta['preview_attached'] = bool(preview_full)
                generation_meta['preview_realized'] = realized
            except Exception:
                pass
        except Exception:
            pass
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
        # Star topologies don't use preview realization, but log for consistency.
        try:
            logging.info("Preview parity: preview_attached=%s preview_realized=%s", bool(preview_full), False)
            try:
                generation_meta['preview_attached'] = bool(preview_full)
                generation_meta['preview_realized'] = False
            except Exception:
                pass
        except Exception:
            pass
        # Align function return signature with segmented path
        router_protocols = {}
        routers = []

    try:
        logging.info("PHASE: Topology built (routers=%d hosts=%d)", len(routers or []), len(hosts or []))
    except Exception:
        pass

    # Log which docker nodes were actually created by the builders
    try:
        if docker_by_name:
            logging.info("Docker nodes created: %d -> %s", len(docker_by_name), ", ".join(sorted(docker_by_name.keys())))
        else:
            logging.info("No docker nodes created by topology builders (either no assignments or NodeType.DOCKER unavailable)")
    except Exception:
        pass

    try:
        logging.info("PHASE: HITL attachment")
        hitl_summary = attach_hitl_rj45_nodes(session, routers, hosts, hitl_config)
        generation_meta["hitl_attachment"] = hitl_summary
        if hitl_summary.get("interfaces"):
            logging.info(
                "HITL: attached %d RJ45 node(s) to session", len(hitl_summary.get("interfaces", []))
            )
        elif hitl_summary.get("enabled"):
            logging.info("HITL: enabled but no RJ45 nodes created (see hitl_attachment metadata)")
    except Exception as exc:
        logging.warning("HITL attachment failed: %s", exc)

    # Parse segmentation config OR fallback to preview segmentation if available
    seg_summary = None
    try:
        logging.info("PHASE: Segmentation")
        seg_density = orchestrated_plan.get('breakdowns', {}).get('segmentation', {}).get('density')
        seg_items = orchestrated_plan.get('segmentation_items_raw')
        if seg_density is None:
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
                    allow_docker_ports=bool(getattr(args, 'seg_allow_docker_ports', False)),
                    docker_nodes=docker_by_name if isinstance(docker_by_name, dict) else None,
                )
                logging.info("Applied segmentation rules: %d", len(seg_summary.get("rules", [])))
            except Exception as e:
                logging.warning("Failed applying segmentation: %s", e)
        else:
            # Attempt preview injection if present
            logging.info("Segmentation disabled or unspecified; skipping")
    except Exception as e:
        logging.warning("Segmentation parse/apply error: %s", e)

    # Parse traffic and generate scripts for non-router hosts
    logging.info("PHASE: Traffic")
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
                # Flow verification artifact
                try:
                    from .utils.segmentation import verify_flows_allowed
                    verification = verify_flows_allowed(
                        os.path.join(traffic_out_dir, "traffic_summary.json"),
                        segmentation_summary_path="/tmp/segmentation/segmentation_summary.json",
                        out_path="/tmp/segmentation/allow_verification.json",
                    )
                    if verification.get('blocked_count'):
                        logging.warning("Flow verification: %d blocked flows remain", verification.get('blocked_count'))
                    else:
                        logging.info("Flow verification: all %d flows allowed", verification.get('flows_total', 0))
                except Exception as e_vf:
                    logging.warning("Flow verification failed: %s", e_vf)
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
        logging.info("PHASE: Vulnerabilities")
        try:
            vuln_density = orchestrated_plan.get('breakdowns', {}).get('vulnerabilities', {}).get('density_input')
        except Exception:
            vuln_density = None
        vuln_items = orchestrated_plan.get('vulnerability_items_raw')
        if vuln_density is None or vuln_items is None:
            vuln_density_fallback, vuln_items_fallback, _vuln_flag_type_fb = parse_vulnerabilities_info(args.xml, args.scenario)
            if vuln_density is None:
                vuln_density = vuln_density_fallback
            if vuln_items is None:
                vuln_items = vuln_items_fallback
        vulnerabilities_cfg = {"density": vuln_density, "items": vuln_items or [], "flag_type": vuln_flag_type}
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

                        # Ensure CORE docker nodes point at the per-node sanitized compose output.
                        # Without this, a node may still reference a downloaded compose (which can
                        # contain `${...}` and trigger Mako NameError in core-daemon).
                        try:
                            for ni in (hosts or []):
                                try:
                                    node_obj = session.get_node(ni.node_id)
                                    nm = getattr(node_obj, 'name', None)
                                except Exception:
                                    nm = None
                                if nm and nm in name_to_vuln:
                                    try:
                                        _apply_docker_compose_meta(node_obj, name_to_vuln[nm], session=session)
                                    except Exception:
                                        pass
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

        # Also prepare compose files for explicitly-added Docker role nodes (standard template).
        # These nodes are not tied to vulnerability selection and should still get the same docker-compose
        # sanitation + iproute2/ethtool wrapper workflow.
        try:
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            standard_compose = os.path.join(repo_root, 'scripts', 'standard-ubuntu-docker-core', 'docker-compose.yml')
            standard_compose = os.path.abspath(standard_compose)
            standard_nodes = {}
            try:
                if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                    for nm, rec in docker_by_name.items():
                        if not isinstance(rec, dict):
                            continue
                        if (rec.get('Type') or '').strip().lower() != 'docker-compose':
                            continue
                        path_val = os.path.abspath(str(rec.get('Path') or '')) if rec.get('Path') else ''
                        name_val = str(rec.get('Name') or '')
                        if name_val == 'standard-ubuntu-docker-core' or (path_val and path_val == standard_compose):
                            standard_nodes[nm] = rec
            except Exception:
                standard_nodes = {}

            def _load_enabled_flag_node_generators(repo_root_path: str) -> list[dict]:
                """Load enabled flag-node-generators from YAML manifests.

                Best-effort behavior:
                  - discovers manifests in repo + outputs/installed_generators
                  - filters out disabled installed generators when _packs_state.json is present
                """
                try:
                    from core_topo_gen.generator_manifests import discover_generator_manifests

                    gens, _plugins_by_id, errs = discover_generator_manifests(repo_root=repo_root_path, kind='flag-node-generator')
                    try:
                        if errs:
                            logging.debug("flag-node-generator manifest warnings: %d", len(errs))
                    except Exception:
                        pass

                    # Load disable map from installed generator packs state.
                    disabled: dict[tuple[str, str], bool] = {}
                    try:
                        installed_root = str(os.environ.get('CORETG_INSTALLED_GENERATORS_DIR') or '').strip()
                        if installed_root:
                            installed_root = os.path.abspath(os.path.expanduser(installed_root))
                        else:
                            installed_root = os.path.abspath(os.path.join(repo_root_path, 'outputs', 'installed_generators'))
                        state_path = os.path.join(installed_root, '_packs_state.json')
                        if os.path.exists(state_path):
                            with open(state_path, 'r', encoding='utf-8') as fh:
                                st = json.load(fh) or {}
                            packs = st.get('packs') if isinstance(st, dict) else None
                            if not isinstance(packs, list):
                                packs = []
                            for p in packs:
                                if not isinstance(p, dict):
                                    continue
                                pack_disabled = bool(p.get('disabled') is True)
                                for it in (p.get('installed') or []):
                                    if not isinstance(it, dict):
                                        continue
                                    gid = str(it.get('id') or '').strip()
                                    kind = str(it.get('kind') or '').strip()
                                    if not gid or not kind:
                                        continue
                                    item_disabled = bool(it.get('disabled') is True)
                                    disabled[(kind, gid)] = bool(pack_disabled or item_disabled)
                    except Exception:
                        disabled = {}

                    # Filter out disabled installed generators; keep non-installed generators.
                    out: list[dict] = []
                    for g in (gens or []):
                        if not isinstance(g, dict):
                            continue
                        gid = str(g.get('id') or '').strip()
                        if not gid:
                            continue
                        # Best-effort installed check: manifest path under installed_root.
                        is_installed = False
                        try:
                            mp = str(g.get('_source_path') or '').strip()
                            if mp and 'installed_root' in locals():
                                is_installed = os.path.commonpath([os.path.abspath(installed_root), os.path.abspath(mp)]) == os.path.abspath(installed_root)
                        except Exception:
                            is_installed = False
                        if is_installed and disabled.get(('flag-node-generator', gid)):
                            continue
                        out.append(g)
                    return out
                except Exception:
                    return []

            def _run_flag_node_generator(generator_id: str, *, out_dir: str, config: dict) -> tuple[bool, str]:
                """Best-effort run of scripts/run_flag_generator.py for flag-node-generators (manifest-based)."""
                try:
                    runner_path = os.path.join(repo_root, 'scripts', 'run_flag_generator.py')
                    if not os.path.exists(runner_path):
                        return False, 'runner script not found'
                    try:
                        docker_ok = bool(shutil.which('docker'))
                    except Exception:
                        docker_ok = False
                    if not docker_ok:
                        return False, 'docker not found'
                    cmd = [
                        sys.executable or 'python',
                        runner_path,
                        '--kind',
                        'flag-node-generator',
                        '--generator-id',
                        generator_id,
                        '--out-dir',
                        out_dir,
                        '--config',
                        json.dumps(config, ensure_ascii=False),
                        '--repo-root',
                        repo_root,
                    ]
                    p = subprocess.run(
                        cmd,
                        cwd=repo_root,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if p.returncode != 0:
                        err = (p.stderr or p.stdout or '').strip()
                        if err:
                            err = err[-800:]
                        return False, f'generator failed (rc={p.returncode}): {err}'
                    return True, 'ok'
                except subprocess.TimeoutExpired:
                    return False, 'generator timed out'
                except Exception as exc:
                    return False, f'generator exception: {exc}'

            if standard_nodes:
                # If any flag-node-generators are enabled, use them to generate per-node docker-compose
                # for the explicit Docker role nodes (these are DOCKER-type nodes, not vulnerability nodes).
                node_gens = _load_enabled_flag_node_generators(repo_root)
                usable = [g for g in (node_gens or []) if isinstance(g.get('compose'), dict)]

                if usable:
                    # Round-robin generator assignment across standard docker nodes.
                    usable.sort(key=lambda g: str(g.get('id') or ''))
                    try:
                        base_seed = int(getattr(args, 'seed', 0) or 0)
                    except Exception:
                        base_seed = 0
                    scenario_tag = str(os.getenv('CORETG_SCENARIO_TAG') or '').strip()
                    if not scenario_tag:
                        scenario_tag = str(getattr(args, 'scenario', '') or 'scenario').strip() or 'scenario'
                    scenario_tag = ''.join([c for c in scenario_tag if c.isalnum() or c in ('-', '_')])[:40] or 'scenario'

                    updated = {}
                    for idx, (nm, _rec) in enumerate(sorted(standard_nodes.items(), key=lambda x: str(x[0]))):
                        gen = usable[idx % max(1, len(usable))]
                        gen_id = str(gen.get('id') or '').strip()
                        if not gen_id:
                            continue
                        flow_run_id = datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:10]
                        out_dir = os.path.join('/tmp/vulns', 'flag_node_generators_runs', f"cli-{scenario_tag}-{nm}-{flow_run_id}")
                        try:
                            os.makedirs(out_dir, exist_ok=True)
                        except Exception:
                            pass
                        cfg = {
                            'seed': f"{base_seed}:{scenario_tag}:{nm}:{gen_id}",
                            'node_name': nm,
                        }
                        ok_run, note = _run_flag_node_generator(gen_id, out_dir=out_dir, config=cfg)
                        compose_src = os.path.join(out_dir, 'docker-compose.yml')
                        if ok_run and os.path.exists(compose_src):
                            updated[nm] = {
                                'Type': 'docker-compose',
                                'Name': str(gen.get('name') or gen_id),
                                'Path': compose_src,
                                'Vector': 'flag-nodegen',
                                'ScenarioTag': scenario_tag,
                            }
                        else:
                            logging.warning("Flag-node-generator failed for node=%s gen=%s: %s", nm, gen_id, note)

                    if updated:
                        # Replace the standard compose records for those nodes so compose prep uses the generated templates.
                        for nm, rec in updated.items():
                            standard_nodes[nm] = rec
                            try:
                                if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                                    docker_by_name[nm] = rec
                            except Exception:
                                pass

                # Ensure ScenarioTag is present so wrapper images are scoped.
                try:
                    for _nm, _rec in (standard_nodes or {}).items():
                        if isinstance(_rec, dict):
                            _rec.setdefault('ScenarioTag', scenario_tag)
                except Exception:
                    pass
                created = prepare_compose_for_assignments(standard_nodes, out_base="/tmp/vulns")
                logging.info("Prepared docker compose files for explicit Docker role nodes: %d for %d docker nodes", len(created), len(standard_nodes))

                # Best-effort: update compose_name on CORE nodes to reflect the record name.
                try:
                    for ni in (hosts or []):
                        try:
                            node_obj = session.get_node(ni.node_id)
                            nm = getattr(node_obj, 'name', None)
                        except Exception:
                            nm = None
                        if nm and nm in standard_nodes:
                            try:
                                _apply_docker_compose_meta(node_obj, standard_nodes[nm], session=session)
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception as e2:
            logging.debug("Standard docker compose prepare skipped or failed: %s", e2)

        # Finally, ensure docker-compose prep runs for any remaining docker nodes (e.g., Flow-injected flag packages).
        # This is safe to run even if some nodes were already prepared earlier.
        try:
            all_docker_nodes = {}
            if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                for nm, rec in docker_by_name.items():
                    if not isinstance(rec, dict):
                        continue
                    if (rec.get('Type') or '').strip().lower() != 'docker-compose':
                        continue
                    all_docker_nodes[nm] = rec
            if all_docker_nodes:
                # Ensure ScenarioTag is present so wrapper images are scoped.
                try:
                    _scenario_tag = str(os.getenv('CORETG_SCENARIO_TAG') or '').strip()
                    if not _scenario_tag:
                        _scenario_tag = str(getattr(args, 'scenario', '') or 'scenario').strip() or 'scenario'
                    _scenario_tag = ''.join([c for c in _scenario_tag if c.isalnum() or c in ('-', '_')])[:40] or 'scenario'
                    for _nm, _rec in all_docker_nodes.items():
                        if isinstance(_rec, dict):
                            _rec.setdefault('ScenarioTag', _scenario_tag)
                except Exception:
                    pass
                created = prepare_compose_for_assignments(all_docker_nodes, out_base="/tmp/vulns")
                logging.info("Prepared docker compose files (all docker nodes): %d for %d docker nodes", len(created), len(all_docker_nodes))

                # Sanity logging: show final per-node compose inputs and output file.
                # Keep detail at DEBUG to avoid noisy logs by default.
                try:
                    for nm, rec in sorted(all_docker_nodes.items(), key=lambda x: str(x[0])):
                        out_path = os.path.join('/tmp/vulns', f"docker-compose-{nm}.yml")
                        logging.debug(
                            "Docker node compose assignment node=%s Name=%s Path=%s Vector=%s out=%s exists=%s",
                            nm,
                            rec.get('Name'),
                            rec.get('Path'),
                            rec.get('Vector'),
                            out_path,
                            os.path.exists(out_path),
                        )
                except Exception:
                    pass
        except Exception as e2:
            logging.debug("All docker compose prepare skipped or failed: %s", e2)
        seg_out_dir = "/tmp/segmentation"
        seg_summary_path = os.path.join(seg_out_dir, "segmentation_summary.json")
        segmentation_cfg = {
            "density": seg_density if 'seg_density' in locals() else None,
            "items": [{"name": i.name, "factor": i.factor} for i in (seg_items or [])] if 'seg_items' in locals() and seg_items else [],
        }
        logging.info("PHASE: Report")
        if routing_density and routing_density > 0:
            # Inject XML/source classification metadata if available
            try:
                xml_path_meta = os.path.abspath(args.xml)
                generation_meta.setdefault('xml_path', xml_path_meta)
                # classification flags may have been computed upstream; if not, attempt lightweight detection
                if 'xml_schema_classification' not in generation_meta:
                    try:
                        import xml.etree.ElementTree as _ET
                        rt = _ET.parse(xml_path_meta).getroot()
                        tagl = rt.tag.lower()
                        if 'scenarios' in tagl:
                            generation_meta['xml_schema_classification'] = 'scenario'
                        elif 'session' in tagl:
                            generation_meta['xml_schema_classification'] = 'session'
                        else:
                            generation_meta['xml_schema_classification'] = 'unknown'
                        if rt.find('.//container') is not None:
                            generation_meta['xml_container_flag'] = True
                    except Exception:
                        pass
            except Exception:
                pass
            report_path, summary_path = write_report(
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
            try:
                xml_path_meta = os.path.abspath(args.xml)
                generation_meta.setdefault('xml_path', xml_path_meta)
                if 'xml_schema_classification' not in generation_meta:
                    try:
                        import xml.etree.ElementTree as _ET
                        rt = _ET.parse(xml_path_meta).getroot()
                        tagl = rt.tag.lower()
                        if 'scenarios' in tagl:
                            generation_meta['xml_schema_classification'] = 'scenario'
                        elif 'session' in tagl:
                            generation_meta['xml_schema_classification'] = 'session'
                        else:
                            generation_meta['xml_schema_classification'] = 'unknown'
                        if rt.find('.//container') is not None:
                            generation_meta['xml_container_flag'] = True
                    except Exception:
                        pass
            except Exception:
                pass
            report_path, summary_path = write_report(
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
        if summary_path:
            logging.info("Scenario summary written to %s", summary_path)
            try:
                print(f"Scenario summary written to {summary_path}", flush=True)
            except Exception:
                pass
    except Exception as e:
        logging.exception("Failed to write scenario report: %s", e)

    # Start the CORE session only after all services (including Traffic) are applied
    try:
        logging.info("PHASE: Start CORE session")
        # Preflight: check for conflicting Docker containers/images for any compose-based Docker nodes.
        # This prevents hard-to-debug failures when CORE attempts to start docker-compose nodes.
        try:
            if getattr(args, 'docker_check_conflicts', True):
                docker_names = []
                try:
                    if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                        for nm, rec in docker_by_name.items():
                            if not isinstance(rec, dict):
                                continue
                            if (rec.get('Type') or '').strip().lower() != 'docker-compose':
                                continue
                            docker_names.append(str(nm))
                except Exception:
                    docker_names = []
                docker_names = sorted(set([n for n in docker_names if n]))
                if docker_names:
                    compose_paths = [os.path.join('/tmp/vulns', f"docker-compose-{nm}.yml") for nm in docker_names]
                    compose_paths = [p for p in compose_paths if p and os.path.exists(p)]
                    # Detect conflicts from compose files (if present) AND from existing containers
                    # that match the docker node names themselves (CORE uses node name as container name).
                    conflicts: Dict[str, Any] = {'containers': [], 'images': []}
                    if compose_paths:
                        try:
                            conflicts = detect_docker_conflicts_for_compose_files(compose_paths)
                        except Exception:
                            conflicts = {'containers': [], 'images': []}
                    try:
                        import subprocess
                        import shutil as _sh
                        if _sh.which('docker'):
                            existing_named: list[str] = []
                            for nm in docker_names:
                                try:
                                    p2 = subprocess.run(
                                        ['docker', 'container', 'inspect', str(nm)],
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL,
                                    )
                                    if p2.returncode == 0:
                                        existing_named.append(str(nm))
                                except Exception:
                                    continue
                            if existing_named:
                                cur = conflicts.get('containers') if isinstance(conflicts, dict) else []
                                if not isinstance(cur, list):
                                    cur = []
                                conflicts['containers'] = list(dict.fromkeys([*cur, *existing_named]))
                    except Exception:
                        pass

                    # Also include any generic CORE-style host containers (hN) currently present
                    try:
                        import re as _re
                        import subprocess as _sp
                        import shutil as _sh
                        if _sh.which('docker'):
                            p = _sp.run(['docker', 'ps', '-a', '--format', '{{.Names}}'], stdout=_sp.PIPE, stderr=_sp.DEVNULL, text=True)
                            if p.returncode == 0:
                                names = [ln.strip() for ln in (p.stdout or '').splitlines() if ln.strip()]
                                pat = _re.compile(r'^(?i:h)\d+$')
                                generic = [n for n in names if pat.match(n)]
                                if generic:
                                    cur = conflicts.get('containers') if isinstance(conflicts, dict) else []
                                    if not isinstance(cur, list):
                                        cur = []
                                    conflicts['containers'] = list(dict.fromkeys([*cur, *generic]))
                    except Exception:
                        pass

                    c_cont = conflicts.get('containers') or []
                    c_imgs = conflicts.get('images') or []
                    if c_cont or c_imgs:
                        # Emit a machine-readable marker for web frontends to parse.
                        try:
                            print(f"DOCKER_CONFLICTS_JSON: {json.dumps({'containers': list(c_cont), 'images': list(c_imgs)})}", flush=True)
                        except Exception:
                            pass
                        logging.warning(
                            "Detected potential Docker conflicts: containers=%d images=%d",
                            len(c_cont),
                            len(c_imgs),
                        )
                        if getattr(args, 'docker_remove_conflicts', False):
                            rr = remove_docker_conflicts(conflicts)
                            logging.info(
                                "Removed Docker conflicts (best-effort): containers=%d images=%d",
                                len(rr.get('removed_containers') or []),
                                len(rr.get('removed_images') or []),
                            )
                        else:
                            import sys as _sys
                            if _sys.stdin.isatty():
                                try:
                                    print("\nDocker conflicts detected for compose-based Docker nodes:")
                                    if c_cont:
                                        print("- Existing containers:")
                                        for x in c_cont:
                                            print(f"  - {x}")
                                    if c_imgs:
                                        print("- Existing images:")
                                        for x in c_imgs:
                                            print(f"  - {x}")
                                    ans = input("Remove these now? [y/N] ").strip().lower()
                                except Exception:
                                    ans = ''
                                if ans in {'y', 'yes'}:
                                    rr = remove_docker_conflicts(conflicts)
                                    logging.info(
                                        "Removed Docker conflicts (best-effort): containers=%d images=%d",
                                        len(rr.get('removed_containers') or []),
                                        len(rr.get('removed_images') or []),
                                    )
                                else:
                                    logging.error("Aborting: Docker conflicts not removed")
                                    return 1
                            else:
                                logging.error(
                                    "Aborting: Docker conflicts detected but cannot prompt (non-interactive). Rerun with --docker-remove-conflicts or clean up Docker resources.",
                                )
                                return 1
        except Exception as _dock_exc:
            logging.debug("Docker conflict preflight skipped/failed: %s", _dock_exc)

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

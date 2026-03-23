from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Any, Callable, Optional

from flask import jsonify, render_template, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    normalize_scenario_label: Callable[[str], str],
    load_run_history: Callable[[], list[dict]],
    current_user_getter: Callable[[], Optional[dict]],
    scenario_catalog_for_user: Callable[..., tuple[list[str], dict[str, Any], Any]],
    resolve_scenario_display: Callable[[str, list[str], str], str],
    core_config_for_request: Callable[..., dict[str, Any]],
    uploads_dir: Callable[[], str],
    outputs_dir: Callable[[], str],
    grpc_save_current_session_xml_with_config: Callable[..., Optional[str]],
    select_existing_path: Callable[[Any], Optional[str]],
    summarize_planner_scenarios: Callable[[str], dict[str, Any]],
    validate_core_xml: Callable[[str], tuple[bool, Any]],
    analyze_core_xml: Callable[[str], Any],
    build_topology_graph_from_session_xml: Callable[[str], tuple[list[dict[str, Any]], list[dict[str, Any]], Any]],
    flow_state_from_latest_xml: Callable[[str], Optional[dict[str, Any]]],
    list_active_core_sessions: Callable[..., list[dict]],
    latest_session_xml_for_scenario_norm: Callable[[str], Optional[str]],
    builder_allowed_norms: Callable[[Optional[dict]], Optional[set[str]]],
    latest_preview_plan_for_scenario_norm: Callable[..., Optional[str]],
    load_preview_payload_from_path: Callable[..., Optional[dict[str, Any]]],
    build_topology_graph_from_preview_plan: Callable[[dict[str, Any]], tuple[list[dict[str, Any]], list[dict[str, Any]], Any]],
    core_host_default: str,
    core_port_default: int,
) -> None:
    if not begin_route_registration(app, 'core_details_routes'):
        return

    def _core_details_view():
        scenario_param = (request.args.get('scenario_name') or request.args.get('scenario') or '').strip()
        scenario_norm = normalize_scenario_label(scenario_param)
        history = load_run_history()
        current_user = current_user_getter()
        scenario_names, scenario_paths, _scenario_url_hints = scenario_catalog_for_user(history, user=current_user)
        scenario_label = resolve_scenario_display(scenario_norm, scenario_names, scenario_param)
        core_cfg = core_config_for_request(include_password=True)
        core_host = core_cfg.get('host', core_host_default)
        core_port = int(core_cfg.get('port', core_port_default))
        xml_param = request.args.get('path')
        xml_path = os.path.abspath(xml_param) if xml_param else None
        if xml_path:
            try:
                allowed_roots = [os.path.abspath(uploads_dir()), os.path.abspath(outputs_dir())]
                if not any(xml_path == root or xml_path.startswith(root + os.sep) for root in allowed_roots):
                    xml_path = None
            except Exception:
                xml_path = None
        if xml_path and not os.path.exists(xml_path):
            xml_path = None
        sid = request.args.get('session_id')
        xml_summary = None
        xml_valid = False
        errors = ''
        classification = None
        container_flag = False
        planner_bundle = False
        graph_nodes: list[dict[str, Any]] | None = None
        graph_links: list[dict[str, Any]] | None = None
        flow_meta: dict[str, Any] | None = None
        if not xml_path and sid:
            try:
                out_dir = os.path.join(outputs_dir(), 'core-sessions')
                os.makedirs(out_dir, exist_ok=True)
                saved = grpc_save_current_session_xml_with_config(core_cfg, out_dir, session_id=str(sid))
                if saved and os.path.exists(saved):
                    xml_path = saved
            except Exception:
                pass
        if not xml_path and scenario_norm:
            fallback = select_existing_path(scenario_paths.get(scenario_norm))
            if fallback:
                xml_path = fallback
                try:
                    app.logger.info('[core.details] Using scenario fallback %s for %s', xml_path, scenario_label or scenario_norm)
                except Exception:
                    pass
        if xml_path and os.path.exists(xml_path):
            try:
                with open(xml_path, 'rb') as handle:
                    data_head = handle.read(4096)
                try:
                    root = ET.fromstring(data_head + b'</dummy>')
                except Exception:
                    try:
                        tree = ET.parse(xml_path)
                        root = tree.getroot()
                    except Exception:
                        root = None
                if root is not None:
                    tag_lower = root.tag.lower()
                    if 'scenarios' in tag_lower:
                        if root.find('.//ScenarioEditor') is not None:
                            planner_bundle = True
                            classification = 'planner'
                        else:
                            classification = 'scenario'
                    elif 'session' in tag_lower:
                        classification = 'session'
                    else:
                        classification = 'unknown'
                    if root.find('.//container') is not None:
                        container_flag = True
                        if classification != 'scenario':
                            classification = 'session'
                if planner_bundle:
                    xml_valid = True
                    errors = ''
                    xml_summary = summarize_planner_scenarios(xml_path)
                else:
                    ok, errs = validate_core_xml(xml_path)
                    if ok:
                        xml_valid = True
                    else:
                        if classification == 'session':
                            xml_valid = True
                        else:
                            xml_valid = False
                            if errs and not errors:
                                errors = errs
                    try:
                        xml_summary = analyze_core_xml(xml_path)
                        if xml_summary is None:
                            xml_summary = {}
                        if classification == 'session':
                            xml_summary['__session_export'] = True
                        if not xml_valid:
                            xml_summary['__invalid'] = True
                    except Exception:
                        xml_summary = xml_summary or None
            except Exception as exc:
                errors = errors or f'XML inspection failed: {exc}'
        if xml_path and os.path.exists(xml_path) and classification == 'session':
            try:
                graph_nodes, graph_links, _adj = build_topology_graph_from_session_xml(xml_path)
            except Exception:
                graph_nodes, graph_links = None, None
        try:
            scenario_norm_for_flow = normalize_scenario_label(scenario_norm)
            if scenario_norm_for_flow:
                flow_meta = flow_state_from_latest_xml(scenario_norm_for_flow)
        except Exception:
            flow_meta = None
        session_info = None
        if sid:
            try:
                sid_int = int(sid)
                sessions = list_active_core_sessions(core_host, core_port, core_cfg)
                for session in sessions:
                    if int(session.get('id')) == sid_int:
                        session_info = session
                        break
            except Exception:
                session_info = None
        try:
            if xml_summary is not None:
                app.logger.debug(
                    '[core_details] xml_path=%s classification=%s valid=%s nodes=%s switch_nodes=%s links_detail=%s',
                    xml_path,
                    classification,
                    xml_valid,
                    len(xml_summary.get('nodes') or []),
                    len(xml_summary.get('switch_nodes') or []),
                    len(xml_summary.get('links_detail') or []),
                )
            else:
                app.logger.debug('[core_details] xml_path=%s classification=%s valid=%s (no summary)', xml_path, classification, xml_valid)
        except Exception:
            pass
        return render_template(
            'core_details.html',
            xml_path=xml_path,
            valid=xml_valid,
            errors=errors,
            summary=xml_summary,
            session=session_info,
            classification=classification,
            container_flag=container_flag,
            scenario_label=scenario_label,
            scenario_norm=scenario_norm,
            graph_nodes=graph_nodes,
            graph_links=graph_links,
            flow_meta=flow_meta,
        )

    def _api_core_details_topology_view():
        scenario_norm = normalize_scenario_label(request.args.get('scenario') or '')
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'Missing scenario.'}), 400
        try:
            allowed_norms = builder_allowed_norms(current_user_getter())
            if allowed_norms is not None and scenario_norm not in allowed_norms:
                return jsonify({'ok': False, 'error': 'Scenario not assigned.'}), 403
        except Exception:
            pass
        nodes: list[dict[str, Any]] = []
        links: list[dict[str, Any]] = []
        status = ''
        source = ''
        session_xml_path = latest_session_xml_for_scenario_norm(scenario_norm)
        if session_xml_path and os.path.exists(session_xml_path):
            try:
                nodes, links, _adj = build_topology_graph_from_session_xml(session_xml_path)
                status = 'ok'
                source = 'session_xml'
            except Exception as exc:
                status = f'Failed building session topology: {exc}'
                nodes, links = [], []
        if not nodes:
            try:
                plan_path = latest_preview_plan_for_scenario_norm(scenario_norm, prefer_flow=True)
            except Exception:
                plan_path = None
            if plan_path and os.path.exists(plan_path):
                try:
                    payload = load_preview_payload_from_path(plan_path, scenario_norm)
                    full_prev = None
                    if isinstance(payload, dict):
                        full_prev = payload.get('full_preview') if isinstance(payload.get('full_preview'), dict) else None
                        if full_prev is None and isinstance(payload.get('preview'), dict):
                            full_prev = payload.get('preview')
                    if isinstance(full_prev, dict):
                        nodes2, links2, _adj2 = build_topology_graph_from_preview_plan(full_prev)
                        for node in nodes2 or []:
                            if not isinstance(node, dict):
                                continue
                            if node.get('is_vulnerability') is None:
                                node['is_vulnerability'] = bool(node.get('is_vuln'))
                        nodes = nodes2 or []
                        links = links2 or []
                        status = 'ok'
                        source = 'preview_plan'
                    else:
                        status = 'Preview plan not embedded in XML.'
                except Exception as exc:
                    status = f'Failed building preview topology: {exc}'
        flow_meta: dict[str, Any] | None = None
        try:
            flow_meta = flow_state_from_latest_xml(scenario_norm)
        except Exception:
            flow_meta = None
        return jsonify({
            'ok': True,
            'scenario_norm': scenario_norm,
            'status': status,
            'source': source,
            'nodes': nodes,
            'links': links,
            'flow': flow_meta or None,
        })

    app.add_url_rule('/core/details', endpoint='core_details', view_func=_core_details_view, methods=['GET'])
    app.add_url_rule('/api/core-details/topology', endpoint='api_core_details_topology', view_func=_api_core_details_topology_view, methods=['GET'])
    mark_routes_registered(app, 'core_details_routes')
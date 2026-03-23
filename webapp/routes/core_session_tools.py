from __future__ import annotations

import os
from typing import Any, Callable, Optional

from flask import Response, jsonify, render_template, request, send_file

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    outputs_dir: Callable[[], str],
    core_config_for_request: Callable[..., dict[str, Any]],
    grpc_save_current_session_xml_with_config: Callable[..., Optional[str]],
    extract_session_id_from_core_path: Callable[[str], Optional[int]],
    load_run_history: Callable[[], list[dict]],
    current_user_getter: Callable[[], Optional[dict]],
    scenario_catalog_for_user: Callable[..., tuple[list[str], dict[str, set[str]], Any]],
    load_core_sessions_store: Callable[[], dict],
    migrate_core_sessions_store_with_core_targets: Callable[[dict, list[dict]], dict],
    filter_core_sessions_store_for_core: Callable[[dict, str, int], dict],
    session_store_scenario_for_session_id: Callable[..., Optional[str]],
    read_remote_session_scenario_meta: Callable[..., Optional[dict[str, Any]]],
    builder_allowed_norms: Callable[[Optional[dict]], Optional[set[str]]],
    resolve_scenario_display: Callable[[str, list[str], str], str],
    normalize_scenario_label: Callable[[str], str],
    list_active_core_sessions: Callable[..., list[dict]],
    validate_core_xml: Callable[[str], tuple[bool, Any]],
    analyze_core_xml: Callable[[str], Any],
    core_host_default: str,
    core_port_default: int,
) -> None:
    if not begin_route_registration(app, 'core_session_tools_routes'):
        return

    def _core_save_xml_view():
        sid = request.form.get('session_id')
        try:
            sid_int = int(sid) if sid is not None else None
        except Exception:
            sid_int = None
        out_dir = os.path.join(outputs_dir(), 'core-sessions')
        os.makedirs(out_dir, exist_ok=True)
        core_cfg = core_config_for_request(include_password=True)
        try:
            saved = grpc_save_current_session_xml_with_config(
                core_cfg,
                out_dir,
                session_id=str(sid_int) if sid_int is not None else None,
            )
            if not saved or not os.path.exists(saved):
                return Response('Failed to save session XML', status=500)
            return send_file(saved, as_attachment=True, download_name=os.path.basename(saved), mimetype='application/xml')
        except Exception as exc:
            return Response(f'Error saving session XML: {exc}', status=500)

    def _core_session_scenario_view():
        sid_raw = (request.args.get('sid') or '').strip()
        path_raw = (request.args.get('path') or '').strip()
        sid: int | None = None
        if sid_raw:
            try:
                sid = int(sid_raw)
            except Exception:
                sid = None
        if sid is None and path_raw:
            sid = extract_session_id_from_core_path(path_raw)
        if sid is None:
            return jsonify({'ok': False, 'error': 'Provide sid or path.'}), 400

        history = load_run_history()
        current_user = current_user_getter()
        scenario_names, scenario_paths, _scenario_url_hints = scenario_catalog_for_user(history, user=current_user)
        core_cfg = core_config_for_request(include_password=True)
        host = core_cfg.get('host', core_host_default)
        try:
            port = int(core_cfg.get('port', core_port_default))
        except Exception:
            port = core_port_default

        scenario_label: str | None = None
        try:
            store = load_core_sessions_store()
            store = migrate_core_sessions_store_with_core_targets(store, history)
            store = filter_core_sessions_store_for_core(store, host, port)
            scenario_label = session_store_scenario_for_session_id(store, int(sid), host=host, port=port)
        except Exception:
            scenario_label = None

        remote_meta: dict[str, Any] | None = None
        if not scenario_label:
            try:
                remote_meta = read_remote_session_scenario_meta(core_cfg, session_id=int(sid), logger=app.logger)
                if isinstance(remote_meta, dict):
                    scenario_label = (remote_meta.get('scenario_name') or '').strip() or None
            except Exception:
                remote_meta = None

        scenario_norm = normalize_scenario_label(scenario_label or '') if scenario_label else ''
        allowed_norms = builder_allowed_norms(current_user)
        if allowed_norms is not None and scenario_norm and scenario_norm not in allowed_norms:
            return jsonify({'ok': False, 'error': 'Scenario not assigned.'}), 403
        scenario_display = resolve_scenario_display(scenario_norm, scenario_names, scenario_label or '') if scenario_norm else ''
        return jsonify({
            'ok': True,
            'session_id': int(sid),
            'scenario_name': scenario_display or (scenario_label or ''),
            'scenario_norm': scenario_norm,
            'core_host': host,
            'core_port': port,
            'source': 'local_store' if scenario_label and not remote_meta else ('remote_meta' if remote_meta else 'unknown'),
        })

    def _core_session_view(sid: int):
        session_info = None
        xml_path = None
        core_cfg = core_config_for_request(include_password=True)
        try:
            sessions = list_active_core_sessions(
                core_cfg.get('host', core_host_default),
                int(core_cfg.get('port', core_port_default)),
                core_cfg,
            )
            for session in sessions:
                if int(session.get('id')) == int(sid):
                    session_info = session
                    xml_path = session.get('file')
                    break
        except Exception:
            session_info = None
        xml_valid = False
        errors = ''
        xml_summary = None
        if xml_path and os.path.exists(xml_path):
            ok, errs = validate_core_xml(xml_path)
            xml_valid = bool(ok)
            errors = errs if not ok else ''
            xml_summary = analyze_core_xml(xml_path) if ok else None
        return render_template('core_details.html', xml_path=xml_path, valid=xml_valid, errors=errors, summary=xml_summary, session=session_info)

    app.add_url_rule('/core/save_xml', endpoint='core_save_xml', view_func=_core_save_xml_view, methods=['POST'])
    app.add_url_rule('/core/session_scenario', endpoint='core_session_scenario', view_func=_core_session_scenario_view, methods=['GET'])
    app.add_url_rule('/core/session/<int:sid>', endpoint='core_session', view_func=_core_session_view, methods=['GET'])
    mark_routes_registered(app, 'core_session_tools_routes')
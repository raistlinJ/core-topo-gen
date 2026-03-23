from __future__ import annotations

import os
from typing import Any, Callable, Optional

from flask import jsonify, request, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    load_run_history: Callable[[], list[dict[str, Any]]],
    current_user_getter: Callable[[], Any],
    scenario_catalog_for_user: Callable[..., tuple[list[str], dict[str, Any], dict[str, Any]]],
    collect_scenario_participant_urls: Callable[[dict[str, Any], dict[str, Any]], dict[str, str]],
    normalize_scenario_label: Callable[[str], str],
    resolve_scenario_display: Callable[[str, list[str], str], str],
    select_core_config_for_page: Callable[..., dict[str, Any]],
    ensure_core_vm_metadata: Callable[[dict[str, Any]], dict[str, Any]],
    build_core_vm_summary: Callable[[dict[str, Any]], tuple[bool, dict[str, Any]]],
    list_active_core_sessions: Callable[..., list[dict[str, Any]]],
    scan_core_xmls: Callable[[], list[dict[str, Any]]],
    load_core_sessions_store: Callable[[], dict[str, Any]],
    migrate_core_sessions_store_with_core_targets: Callable[[dict[str, Any], list[dict[str, Any]]], dict[str, Any]],
    filter_core_sessions_store_for_core: Callable[[dict[str, Any], Any, Any], dict[str, Any]],
    build_session_scenario_labels: Callable[[dict[str, Any], list[str], dict[str, Any]], dict[int, str]],
    session_ids_for_scenario: Callable[[dict[str, Any], str, dict[str, Any]], set[int]],
    annotate_sessions_with_scenarios: Callable[..., None],
    read_remote_session_scenario_meta_bulk: Callable[..., dict[int, dict[str, Any]]],
    filter_sessions_by_scenario: Callable[..., tuple[list[dict[str, Any]], bool]],
    path_matches_scenario: Callable[[Any, str, dict[str, Any]], bool],
    session_store_updated_at_for_session_id: Callable[..., Optional[float]],
    scenario_timestamped_filename: Callable[[Optional[str], Optional[float]], str],
    attach_hitl_metadata_to_sessions: Callable[..., None],
    attach_participant_urls_to_sessions: Callable[..., None],
    session_store_entry_session_id: Callable[[Any], Optional[int]],
    filter_xmls_by_scenario: Callable[..., tuple[list[dict[str, Any]], bool]],
    current_core_ui_logs: Callable[[], list[Any]],
    core_host_default: Any,
    core_port_default: Any,
) -> None:
    if not begin_route_registration(app, 'core_data_routes'):
        return

    def _core_data_view():
        def _query_bool_param(name: str, default: bool) -> bool:
            raw = request.args.get(name)
            if raw is None:
                return default
            try:
                value = str(raw).strip().lower()
            except Exception:
                return default
            if value in ('1', 'true', 'yes', 'on'):
                return True
            if value in ('0', 'false', 'no', 'off'):
                return False
            return default

        include_xmls = _query_bool_param('include_xmls', True)

        history = load_run_history()
        current_user = current_user_getter()
        scenario_names, scenario_paths, scenario_url_hints = scenario_catalog_for_user(history, user=current_user)
        scenario_participant_urls = collect_scenario_participant_urls(scenario_paths, scenario_url_hints)
        participant_url_flags = {
            norm: bool(url)
            for norm, url in scenario_participant_urls.items()
            if isinstance(norm, str) and norm
        }
        scenario_query = request.args.get('scenario', '').strip()
        scenario_norm = normalize_scenario_label(scenario_query)
        if scenario_names:
            if not scenario_norm or not any(normalize_scenario_label(name) == scenario_norm for name in scenario_names):
                scenario_norm = normalize_scenario_label(scenario_names[0])
        scenario_display = resolve_scenario_display(scenario_norm, scenario_names, scenario_query)
        no_scenario_context = (not bool(scenario_names)) and (not bool(scenario_query))
        if no_scenario_context:
            payload: dict[str, Any] = {
                'sessions': [],
                'scenarios': [],
                'active_scenario': '',
                'participant_url_flags': participant_url_flags,
                'active_session_counts': {},
                'scenario_item_counts': {},
                'host': '',
                'port': None,
                'core_vm_configured': False,
                'core_vm_summary': {},
                'core_modal_href': url_for('index', core_modal=1),
                'errors': [],
                'grpc_command': '',
                'logs': current_core_ui_logs(),
                'daemon_status': 'idle',
                'no_scenario_context': True,
            }
            if include_xmls:
                payload['xmls'] = []
            return jsonify(payload)

        core_cfg = select_core_config_for_page(scenario_norm, history, include_password=True)
        core_cfg = ensure_core_vm_metadata(core_cfg)
        host = core_cfg.get('host', core_host_default)
        port = int(core_cfg.get('port', core_port_default))
        core_vm_configured, core_vm_summary = build_core_vm_summary(core_cfg)
        core_errors: list[str] = []
        app.logger.info(
            '[core.data] scenario=%s host=%s:%s ssh=%s@%s:%s',
            scenario_display or '<none>',
            host,
            port,
            (core_cfg.get('ssh_username') or '').strip() or '<none>',
            core_cfg.get('ssh_host'),
            core_cfg.get('ssh_port'),
        )
        session_meta: dict[str, Any] = {}
        sessions = list_active_core_sessions(host, port, core_cfg, errors=core_errors, meta=session_meta)
        grpc_command = session_meta.get('grpc_command')
        app.logger.info('[core.data] session_count=%d', len(sessions))
        xmls: Optional[list[dict[str, Any]]] = None
        if include_xmls:
            xmls = scan_core_xmls()
        mapping = load_core_sessions_store()
        mapping = migrate_core_sessions_store_with_core_targets(mapping, history)
        mapping = filter_core_sessions_store_for_core(mapping, host, port)
        session_label_map = build_session_scenario_labels(mapping, scenario_names, scenario_paths)
        scenario_session_ids = session_ids_for_scenario(mapping, scenario_norm, scenario_paths) if scenario_norm else set()
        annotate_sessions_with_scenarios(
            sessions,
            session_label_map,
            scenario_norm,
            scenario_names,
            scenario_paths,
            scenario_query,
            scenario_session_ids,
        )

        missing_sids: list[int] = []
        for session in sessions:
            try:
                scenario_name = (session.get('scenario_name') or '').strip()
                session_id = session.get('id')
                if session_id in (None, ''):
                    continue
                candidate_path = ''
                try:
                    candidate_path = str(session.get('file') or session.get('dir') or '').strip()
                except Exception:
                    candidate_path = ''
                is_pycore = False
                try:
                    normalized = candidate_path.replace('\\', '/')
                    if normalized.startswith('/tmp/pycore.') or '/tmp/pycore.' in normalized:
                        is_pycore = True
                except Exception:
                    is_pycore = False
                if is_pycore or (not scenario_name):
                    missing_sids.append(int(session_id))
            except Exception:
                continue

        remote_meta_by_sid: dict[int, dict[str, Any]] = {}
        if missing_sids:
            try:
                remote_meta_by_sid = read_remote_session_scenario_meta_bulk(core_cfg, session_ids=missing_sids, logger=app.logger)
            except Exception:
                remote_meta_by_sid = {}
        if remote_meta_by_sid:
            for session in sessions:
                try:
                    session_id = session.get('id')
                    session_id_int = int(session_id) if session_id not in (None, '') else None
                except Exception:
                    session_id_int = None
                if session_id_int is None:
                    continue
                try:
                    meta = remote_meta_by_sid.get(session_id_int) or {}
                    label = (meta.get('scenario_name') or '').strip() if isinstance(meta, dict) else ''
                    if not label:
                        continue
                    candidate_path = ''
                    try:
                        candidate_path = str(session.get('file') or session.get('dir') or '').strip()
                    except Exception:
                        candidate_path = ''
                    is_remote = False
                    try:
                        if candidate_path and (candidate_path.startswith('/tmp/pycore.') or candidate_path.startswith('\\tmp\\pycore.')):
                            is_remote = True
                    except Exception:
                        is_remote = False
                    if not is_remote:
                        try:
                            if candidate_path and (not os.path.exists(candidate_path)):
                                is_remote = True
                        except Exception:
                            is_remote = True
                    if is_remote or (not (session.get('scenario_name') or '').strip()):
                        session['scenario_name'] = label
                except Exception:
                    continue

        active_session_counts: dict[str, int] = {}
        try:
            norm_to_display: dict[str, str] = {}
            for name in scenario_names or []:
                try:
                    norm_to_display[normalize_scenario_label(name)] = str(name)
                except Exception:
                    continue
            for session in sessions:
                try:
                    label_norm = normalize_scenario_label((session.get('scenario_name') or '').strip())
                except Exception:
                    label_norm = ''
                if not label_norm:
                    continue
                display = norm_to_display.get(label_norm)
                if not display:
                    continue
                active_session_counts[display] = active_session_counts.get(display, 0) + 1
        except Exception:
            active_session_counts = {}

        scenario_item_counts: dict[str, int] = {}
        try:
            for name in scenario_names or []:
                try:
                    display = str(name)
                    norm = normalize_scenario_label(name)
                    paths = scenario_paths.get(norm) if isinstance(scenario_paths, dict) else None
                    scenario_item_counts[display] = len(paths or [])
                except Exception:
                    continue
        except Exception:
            scenario_item_counts = {}

        if scenario_norm:
            filtered: list[dict[str, Any]] = []
            matched = False
            for session in sessions:
                try:
                    label = normalize_scenario_label((session.get('scenario_name') or '').strip())
                except Exception:
                    label = ''
                if label and label == scenario_norm:
                    filtered.append(session)
                    matched = True
            if not matched:
                filtered, matched = filter_sessions_by_scenario(sessions, scenario_norm, scenario_paths, scenario_session_ids)
            sessions = filtered
            if not matched:
                app.logger.info('[core.data] scenario=%s produced no session matches', scenario_norm)

            for session in sessions:
                try:
                    session_id = session.get('id')
                    session_id_int = int(session_id) if session_id not in (None, '') else None
                except Exception:
                    session_id_int = None
                try:
                    is_owned = session_id_int is not None and session_id_int in (scenario_session_ids or set())
                except Exception:
                    is_owned = False
                try:
                    is_path_match = path_matches_scenario(session.get('file'), scenario_norm, scenario_paths) or path_matches_scenario(session.get('dir'), scenario_norm, scenario_paths)
                except Exception:
                    is_path_match = False
                if is_owned or is_path_match:
                    if session_id_int is not None:
                        try:
                            meta = remote_meta_by_sid.get(session_id_int) or {}
                            meta_label = (meta.get('scenario_name') or '').strip() if isinstance(meta, dict) else ''
                        except Exception:
                            meta_label = ''
                        if meta_label:
                            continue
                    try:
                        session['scenario_name'] = scenario_display or session.get('scenario_name') or ''
                    except Exception:
                        pass
            if include_xmls and xmls is not None:
                filtered_xmls, xml_matched = filter_xmls_by_scenario(xmls, scenario_norm, scenario_paths, mapping)
                if xml_matched:
                    xmls = filtered_xmls
                else:
                    app.logger.info('[core.data] scenario=%s produced no XML matches; showing all XMLs', scenario_norm)

        for session in sessions:
            try:
                session_id = session.get('id')
                session_id_int = int(session_id) if session_id not in (None, '') else None
            except Exception:
                session_id_int = None
            try:
                scenario_name = (session.get('scenario_name') or '').strip() or scenario_display or ''
                ts_epoch = None
                if session_id_int is not None and session_id_int in remote_meta_by_sid:
                    meta = remote_meta_by_sid.get(session_id_int) or {}
                    if isinstance(meta, dict) and meta.get('written_at_epoch') not in (None, ''):
                        try:
                            ts_epoch = float(meta.get('written_at_epoch'))
                        except Exception:
                            ts_epoch = None
                if ts_epoch is None and session_id_int is not None:
                    ts_epoch = session_store_updated_at_for_session_id(mapping, session_id_int, host=host, port=port)
                session['filename'] = scenario_timestamped_filename(scenario_name or None, ts_epoch)
            except Exception:
                pass

        attach_hitl_metadata_to_sessions(sessions, core_cfg, allow_remote_fetch=True, session_store=mapping)
        attach_participant_urls_to_sessions(sessions, mapping, scenario_paths, scenario_participant_urls)
        file_to_sid: dict[str, int] = {}
        for session in sessions:
            file_path = session.get('file')
            session_id = session.get('id')
            if file_path and session_id is not None:
                file_to_sid[os.path.abspath(file_path)] = int(session_id)
        for key, value in mapping.items():
            session_id = session_store_entry_session_id(value)
            if session_id is None:
                continue
            file_to_sid.setdefault(os.path.abspath(key), session_id)
        if include_xmls and xmls is not None:
            for xml in xmls:
                session_id = file_to_sid.get(xml['path'])
                xml['session_id'] = session_id
                xml['running'] = session_id is not None

        daemon_status = 'ok'
        if core_errors:
            for error in core_errors:
                if 'Connection refused' in error or '111' in error or 'Remote CORE session fetch failed' in error:
                    daemon_status = 'down'
                    break

        core_modal_href = url_for('index', core_modal=1, scenario=scenario_display) if scenario_display else url_for('index', core_modal=1)
        payload = {
            'sessions': sessions,
            'scenarios': scenario_names,
            'active_scenario': scenario_display,
            'participant_url_flags': participant_url_flags,
            'active_session_counts': active_session_counts,
            'scenario_item_counts': scenario_item_counts,
            'host': host,
            'port': port,
            'core_vm_configured': bool(core_vm_configured),
            'core_vm_summary': core_vm_summary or {},
            'core_modal_href': core_modal_href,
            'errors': core_errors,
            'grpc_command': grpc_command,
            'logs': current_core_ui_logs(),
            'daemon_status': daemon_status,
            'no_scenario_context': False,
        }
        if include_xmls:
            payload['xmls'] = xmls or []
        return jsonify(payload)

    app.add_url_rule('/core/data', endpoint='core_data', view_func=_core_data_view, methods=['GET'])
    mark_routes_registered(app, 'core_data_routes')
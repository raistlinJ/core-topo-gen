from __future__ import annotations

import os
from typing import Any, Callable, Optional

from flask import render_template, request

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
    filter_sessions_by_scenario: Callable[..., tuple[list[dict[str, Any]], bool]],
    filter_xmls_by_scenario: Callable[..., tuple[list[dict[str, Any]], bool]],
    read_remote_session_scenario_meta_bulk: Callable[..., dict[int, dict[str, Any]]],
    session_store_updated_at_for_session_id: Callable[..., Optional[float]],
    scenario_timestamped_filename: Callable[[Optional[str], Optional[float]], str],
    attach_hitl_metadata_to_sessions: Callable[..., None],
    attach_participant_urls_to_sessions: Callable[..., None],
    session_store_entry_session_id: Callable[[Any], Optional[int]],
    current_core_ui_logs: Callable[[], list[Any]],
    core_host_default: Any,
    core_port_default: Any,
) -> None:
    if not begin_route_registration(app, 'core_page_routes'):
        return

    def _core_page_view():
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
        active_scenario = resolve_scenario_display(scenario_norm, scenario_names, scenario_query)
        no_scenario_context = (not bool(scenario_names)) and (not bool(scenario_query))
        if no_scenario_context:
            return render_template(
                'core.html',
                sessions=[],
                xmls=[],
                host='',
                port='',
                scenarios=[],
                active_scenario='',
                core_errors=[],
                core_grpc_command='',
                core_vm_configured=False,
                core_vm_summary={},
                core_log_entries=current_core_ui_logs(),
                participant_url_flags=participant_url_flags,
                no_scenario_context=True,
            )

        core_cfg = select_core_config_for_page(scenario_norm, history, include_password=True)
        core_cfg = ensure_core_vm_metadata(core_cfg)
        host = core_cfg.get('host', core_host_default)
        port = int(core_cfg.get('port', core_port_default))
        core_vm_configured, core_vm_summary = build_core_vm_summary(core_cfg)
        core_errors: list[str] = []
        app.logger.info(
            '[core.page] scenario=%s host=%s:%s ssh=%s@%s:%s',
            active_scenario or '<none>',
            host,
            port,
            (core_cfg.get('ssh_username') or '').strip() or '<none>',
            core_cfg.get('ssh_host'),
            core_cfg.get('ssh_port'),
        )
        session_meta: dict[str, Any] = {}
        sessions = list_active_core_sessions(host, port, core_cfg, errors=core_errors, meta=session_meta)
        grpc_command = session_meta.get('grpc_command')
        app.logger.info('[core.page] session_count=%d', len(sessions))
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
        if scenario_norm:
            filtered_sessions, matched = filter_sessions_by_scenario(sessions, scenario_norm, scenario_paths, scenario_session_ids)
            sessions = filtered_sessions
            if not matched:
                app.logger.info('[core.page] scenario=%s produced no session matches', scenario_norm)
            filtered_xmls, xml_matched = filter_xmls_by_scenario(xmls, scenario_norm, scenario_paths, mapping)
            if xml_matched:
                xmls = filtered_xmls
            else:
                app.logger.info('[core.page] scenario=%s produced no XML matches; showing all XMLs', scenario_norm)
        try:
            all_sids: list[int] = []
            for session in sessions:
                try:
                    session_id = session.get('id')
                    if session_id in (None, ''):
                        continue
                    all_sids.append(int(session_id))
                except Exception:
                    continue
            meta_by_sid = read_remote_session_scenario_meta_bulk(core_cfg, session_ids=all_sids, logger=app.logger) if all_sids else {}
        except Exception:
            meta_by_sid = {}

        for session in sessions:
            try:
                session_id = session.get('id')
                session_id_int = int(session_id) if session_id not in (None, '') else None
            except Exception:
                session_id_int = None
            if session_id_int is not None:
                try:
                    meta = meta_by_sid.get(session_id_int) or {}
                    meta_label = (meta.get('scenario_name') or '').strip() if isinstance(meta, dict) else ''
                    if meta_label:
                        session['scenario_name'] = meta_label
                except Exception:
                    pass

            try:
                scenario_name = (session.get('scenario_name') or '').strip() or active_scenario or ''
                ts_epoch = None
                if session_id_int is not None:
                    try:
                        meta = meta_by_sid.get(session_id_int) or {}
                        if isinstance(meta, dict) and meta.get('written_at_epoch') not in (None, ''):
                            ts_epoch = float(meta.get('written_at_epoch'))
                    except Exception:
                        ts_epoch = None
                if ts_epoch is None and session_id_int is not None:
                    ts_epoch = session_store_updated_at_for_session_id(mapping, session_id_int, host=host, port=port)
                session['filename'] = scenario_timestamped_filename(scenario_name or None, ts_epoch)
            except Exception:
                pass

        attach_hitl_metadata_to_sessions(sessions, core_cfg, allow_remote_fetch=False, session_store=mapping)
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
        for xml in xmls:
            session_id = file_to_sid.get(xml['path'])
            xml['session_id'] = session_id
            xml['running'] = session_id is not None

        return render_template(
            'core.html',
            sessions=sessions,
            xmls=xmls,
            host=host,
            port=port,
            scenarios=scenario_names,
            active_scenario=active_scenario,
            core_errors=core_errors,
            core_grpc_command=grpc_command,
            core_vm_configured=core_vm_configured,
            core_vm_summary=core_vm_summary,
            core_log_entries=current_core_ui_logs(),
            participant_url_flags=participant_url_flags,
            no_scenario_context=False,
        )

    app.add_url_rule('/core', endpoint='core_page', view_func=_core_page_view, methods=['GET'])
    mark_routes_registered(app, 'core_page_routes')
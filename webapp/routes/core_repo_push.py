from __future__ import annotations

import os
from typing import Any, Callable, Optional

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    parse_scenarios_xml: Callable[[str], dict[str, Any]],
    merge_core_configs: Callable[..., dict[str, Any]],
    init_repo_push_progress: Callable[..., None],
    schedule_repo_push_to_remote: Callable[..., None],
    update_repo_push_progress: Callable[..., None],
    ssh_tunnel_error_type: type[BaseException],
    uuid_hex: Callable[[], str],
) -> None:
    if not begin_route_registration(app, 'core_repo_push_routes'):
        return

    def _core_push_repo_route_view():
        xml_path: Optional[str] = None
        scenario_name_hint: Optional[str] = None
        scenario_index_hint: Optional[int] = None
        core_override: Optional[dict[str, Any]] = None
        scenario_core_override: Optional[dict[str, Any]] = None

        if request.form:
            xml_path = request.form.get('xml_path') or None
            scenario_name_hint = request.form.get('scenario') or request.form.get('scenario_name') or None
            raw_index = request.form.get('scenario_index')
            if raw_index not in (None, ''):
                try:
                    scenario_index_hint = int(raw_index)
                except Exception:
                    scenario_index_hint = None
            core_json = request.form.get('core_json')
            if core_json:
                try:
                    core_override = __import__('json').loads(core_json)
                except Exception:
                    core_override = None
            hitl_core_json = request.form.get('hitl_core_json')
            if hitl_core_json:
                try:
                    scenario_core_override = __import__('json').loads(hitl_core_json)
                except Exception:
                    scenario_core_override = None
        else:
            payload = request.get_json(silent=True) or {}
            if isinstance(payload, dict):
                xml_path = payload.get('xml_path') or payload.get('scenario_xml_path') or xml_path
                scenario_name_hint = (
                    payload.get('scenario')
                    or payload.get('scenario_name')
                    or payload.get('active_scenario')
                    or scenario_name_hint
                )
                if 'scenario_index' in payload:
                    try:
                        scenario_index_hint = int(payload.get('scenario_index'))
                    except Exception:
                        scenario_index_hint = None
                if isinstance(payload.get('core'), dict):
                    core_override = payload.get('core')
                elif isinstance(payload.get('core_json'), str):
                    try:
                        core_override = __import__('json').loads(payload.get('core_json') or '{}')
                    except Exception:
                        core_override = None
                if isinstance(payload.get('hitl_core'), dict):
                    scenario_core_override = payload.get('hitl_core')
                elif isinstance(payload.get('hitl_core_json'), str):
                    try:
                        scenario_core_override = __import__('json').loads(payload.get('hitl_core_json') or '{}')
                    except Exception:
                        scenario_core_override = None

        payload_for_core: Optional[dict[str, Any]] = None
        scenario_payload: Optional[dict[str, Any]] = None
        if xml_path:
            xml_path = os.path.abspath(xml_path)
            if os.path.exists(xml_path):
                try:
                    payload_for_core = parse_scenarios_xml(xml_path)
                except Exception:
                    payload_for_core = None
            else:
                app.logger.warning('[core.push_repo] XML path not found: %s', xml_path)
        if payload_for_core:
            scen_list = payload_for_core.get('scenarios') or []
            if isinstance(scen_list, list) and scen_list:
                if scenario_name_hint:
                    for scen_entry in scen_list:
                        if isinstance(scen_entry, dict) and str(scen_entry.get('name') or '').strip() == str(scenario_name_hint).strip():
                            scenario_payload = scen_entry
                            break
                if scenario_payload is None and scenario_index_hint is not None:
                    if 0 <= scenario_index_hint < len(scen_list):
                        candidate = scen_list[scenario_index_hint]
                        if isinstance(candidate, dict):
                            scenario_payload = candidate
                if scenario_payload is None:
                    for scen_entry in scen_list:
                        if isinstance(scen_entry, dict):
                            scenario_payload = scen_entry
                            break
        scenario_core_saved = None
        if scenario_payload and isinstance(scenario_payload.get('hitl'), dict):
            scenario_core_saved = scenario_payload['hitl'].get('core')
        global_core_saved = payload_for_core.get('core') if (payload_for_core and isinstance(payload_for_core.get('core'), dict)) else None
        core_cfg = merge_core_configs(
            global_core_saved,
            scenario_core_saved,
            core_override if isinstance(core_override, dict) else None,
            scenario_core_override if isinstance(scenario_core_override, dict) else None,
            include_password=True,
        )
        progress_id = uuid_hex()
        init_repo_push_progress(progress_id, stage='queued', detail='Queued repository sync…', status='queued', percent=0.0)
        try:
            schedule_repo_push_to_remote(progress_id, core_cfg, logger=app.logger)
        except ssh_tunnel_error_type as exc:
            update_repo_push_progress(progress_id, status='error', stage='error', detail=str(exc))
            return jsonify({'error': str(exc)}), 400
        except Exception as exc:
            app.logger.exception('[core.push_repo] Failed syncing repo: %s', exc)
            update_repo_push_progress(progress_id, status='error', stage='error', detail=str(exc))
            return jsonify({'error': f'Failed pushing repo: {exc}', 'progress_id': progress_id}), 500
        return jsonify({'ok': True, 'progress_id': progress_id})

    app.add_url_rule('/core/push_repo', endpoint='core_push_repo_route', view_func=_core_push_repo_route_view, methods=['POST'])
    mark_routes_registered(app, 'core_repo_push_routes')
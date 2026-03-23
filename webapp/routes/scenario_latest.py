from __future__ import annotations

import os
from typing import Any, Callable

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    normalize_scenario_label: Callable[[str], str],
    latest_xml_path_for_scenario: Callable[[str], str | None],
    abs_path_or_original: Callable[[Any], str],
    parse_scenarios_xml: Callable[[str], dict[str, Any]],
    merge_hitl_hints_into_scenario_state: Callable[[dict[str, Any], str], dict[str, Any]],
    logger=None,
) -> None:
    if not begin_route_registration(app, 'scenario_latest_routes'):
        return

    def _latest_xml_view():
        scenario = (request.args.get('scenario') or '').strip()
        if not scenario:
            return jsonify({'ok': False, 'error': 'scenario required'}), 400
        try:
            scen_norm = normalize_scenario_label(scenario)
            xml_path = latest_xml_path_for_scenario(scen_norm)
            if not xml_path:
                return jsonify({'ok': False, 'error': 'No XML found'}), 404
            return jsonify({'ok': True, 'scenario': scenario, 'xml_path': xml_path})
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500

    def _latest_state_view():
        scenario = (request.args.get('scenario') or '').strip()
        if not scenario:
            return jsonify({'ok': False, 'error': 'scenario required'}), 400
        try:
            scen_norm = normalize_scenario_label(scenario)
            requested_xml_path = (request.args.get('xml_path') or '').strip()
            xml_path = ''
            if requested_xml_path:
                requested_abs = abs_path_or_original(requested_xml_path)
                if not requested_abs or not os.path.exists(requested_abs):
                    return jsonify({'ok': False, 'error': 'requested xml_path not found'}), 404
                xml_path = requested_abs
            if not xml_path:
                xml_path = latest_xml_path_for_scenario(scen_norm) or ''
            if not xml_path:
                return jsonify({'ok': False, 'error': 'No XML found'}), 404

            parsed = parse_scenarios_xml(xml_path)
            scen_list = parsed.get('scenarios') if isinstance(parsed, dict) else None
            if not isinstance(scen_list, list) or not scen_list:
                return jsonify({'ok': False, 'error': 'XML has no scenarios'}), 404

            selected = None
            for scen in scen_list:
                if not isinstance(scen, dict):
                    continue
                nm = str(scen.get('name') or '').strip()
                if normalize_scenario_label(nm) == scen_norm:
                    selected = scen
                    break

            if selected is None:
                return jsonify({'ok': False, 'error': 'Scenario not found in XML'}), 404

            try:
                selected = merge_hitl_hints_into_scenario_state(selected, scen_norm)
            except Exception:
                pass

            core_payload = parsed.get('core') if isinstance(parsed.get('core'), dict) else None
            try:
                xml_mtime = float(os.path.getmtime(xml_path))
            except Exception:
                xml_mtime = 0.0

            try:
                fs_dbg = selected.get('flow_state') if isinstance(selected, dict) and isinstance(selected.get('flow_state'), dict) else {}
                chain_dbg = fs_dbg.get('chain_ids') if isinstance(fs_dbg.get('chain_ids'), list) else []
                if logger is not None:
                    logger.info(
                        '[flow.latest_state] scenario=%s requested_xml=%s resolved_xml=%s mtime=%s flow_chain_len=%s flow_enabled=%s',
                        scen_norm,
                        (requested_xml_path or ''),
                        xml_path,
                        xml_mtime,
                        len(chain_dbg),
                        (fs_dbg.get('flow_enabled') if isinstance(fs_dbg, dict) else None),
                    )
            except Exception:
                pass

            return jsonify({
                'ok': True,
                'scenario': scenario,
                'scenario_norm': scen_norm,
                'xml_path': xml_path,
                'xml_mtime': xml_mtime,
                'scenario_state': selected,
                'core': core_payload,
            })
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500

    app.add_url_rule('/api/scenario/latest_xml', endpoint='api_latest_xml_for_scenario', view_func=_latest_xml_view, methods=['GET'])
    app.add_url_rule('/api/scenario/latest_state', endpoint='api_latest_state_for_scenario', view_func=_latest_state_view, methods=['GET'])
    mark_routes_registered(app, 'scenario_latest_routes')
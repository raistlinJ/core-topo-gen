from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_state_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/save_flow_state_to_xml', methods=['POST'])
    def api_flow_save_flow_state_to_xml():
        payload = request.get_json(silent=True) or {}
        xml_path = str(payload.get('xml_path') or '').strip()
        scenario_label = str(payload.get('scenario') or '').strip()
        flow_state = payload.get('flow_state') if isinstance(payload.get('flow_state'), dict) else None
        clear_state = backend._coerce_bool(payload.get('clear'))

        if not xml_path:
            return jsonify({'ok': False, 'error': 'xml_path required'}), 400
        if (not flow_state) and (not clear_state):
            return jsonify({'ok': False, 'error': 'flow_state required'}), 400

        try:
            xml_path = backend.os.path.abspath(xml_path)
        except Exception:
            return jsonify({'ok': False, 'error': 'invalid xml_path'}), 400

        snap_before = backend._xml_trace_snapshot(xml_path, scenario_label)

        if clear_state:
            ok, message = backend._clear_flow_state_in_xml(xml_path, scenario_label)
        else:
            try:
                if (
                    isinstance(flow_state, dict)
                    and ('flow_enabled' in flow_state)
                    and (backend._coerce_bool(flow_state.get('flow_enabled')) is False)
                ):
                    flow_state = dict(flow_state)
                    flow_state['chain_ids'] = []
                    flow_state['length'] = 0
                    flow_state['flag_assignments'] = []
                    flow_state['flags_enabled'] = False
            except Exception:
                pass
            flow_state = backend._enrich_flow_state_with_artifacts(flow_state)
            ok, message = backend._update_flow_state_in_xml(xml_path, scenario_label, flow_state)
        if not ok:
            try:
                app.logger.warning(
                    '[flow.save_flow_state_to_xml] scenario=%s clear=%s ok=%s msg=%s before=%s',
                    backend._normalize_scenario_label(scenario_label),
                    bool(clear_state),
                    bool(ok),
                    message,
                    snap_before,
                )
            except Exception:
                pass
            return jsonify({'ok': False, 'error': message}), 422
        try:
            clear_plan_flow = bool(clear_state)
            if (
                (not clear_plan_flow)
                and isinstance(flow_state, dict)
                and ('flow_enabled' in flow_state)
                and (backend._coerce_bool(flow_state.get('flow_enabled')) is False)
            ):
                clear_plan_flow = True
            if clear_plan_flow:
                backend._clear_plan_preview_flow_metadata_in_xml(xml_path, scenario_label)
        except Exception:
            pass
        try:
            snap_after = backend._xml_trace_snapshot(xml_path, scenario_label)
            chain_len = None
            try:
                chain_len = len(flow_state.get('chain_ids') or []) if isinstance(flow_state, dict) else None
            except Exception:
                chain_len = None
            app.logger.info(
                '[flow.save_flow_state_to_xml] scenario=%s clear=%s requested_chain_len=%s before=%s after=%s',
                backend._normalize_scenario_label(scenario_label),
                bool(clear_state),
                chain_len,
                snap_before,
                snap_after,
            )
        except Exception:
            pass
        return jsonify({'ok': True, 'xml_path': xml_path})

    mark_routes_registered(app, 'flag_sequencing_state_routes')
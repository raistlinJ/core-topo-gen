from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_values_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/flag_values_for_node')
    def api_flow_flag_values_for_node():
        """Return realized flag value(s) for a sequenced node."""
        scenario_label = (request.args.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        node_id = str((request.args.get('node_id') or '').strip())
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400
        if not node_id:
            return jsonify({'ok': False, 'error': 'No node_id specified.'}), 400

        plan_path = None
        try:
            entry = backend._planner_get_plan(scenario_norm)
            if entry:
                plan_path = entry.get('plan_path') or plan_path
        except Exception:
            plan_path = plan_path
        if not plan_path:
            plan_path = backend._latest_preview_plan_for_scenario_norm_origin(scenario_norm, origin='planner')
        if not plan_path:
            plan_path = backend._latest_preview_plan_for_scenario_norm(scenario_norm, prefer_flow=True)
        if not plan_path or not backend.os.path.exists(plan_path):
            return jsonify({'ok': False, 'error': 'No preview plan found for this scenario.'}), 404

        try:
            payload = backend._load_preview_payload_from_path(plan_path, scenario_label or scenario_norm)
            if not isinstance(payload, dict):
                return jsonify({'ok': False, 'error': 'Preview plan not embedded in XML.'}), 404
            metadata = payload.get('metadata') if isinstance(payload, dict) else None
            flow = (metadata or {}).get('flow') if isinstance(metadata, dict) else None
            flag_assignments = flow.get('flag_assignments') if isinstance(flow, dict) else None
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed to load preview plan: {exc}'}), 500

        if not isinstance(flag_assignments, list) or not flag_assignments:
            return jsonify({'ok': True, 'scenario': scenario_label or scenario_norm, 'node_id': node_id, 'flags': []})

        matches = [
            assignment
            for assignment in flag_assignments
            if isinstance(assignment, dict) and str(assignment.get('node_id') or '').strip() == node_id
        ]
        out_flags: list[dict[str, Any]] = []
        for assignment in (matches or []):
            try:
                artifacts_dir = str(assignment.get('artifacts_dir') or assignment.get('run_dir') or '').strip()
                flag_value = backend._flow_read_flag_value_from_artifacts_dir(artifacts_dir) if artifacts_dir else ''
                out_flags.append(
                    {
                        'generator_id': str(assignment.get('id') or ''),
                        'generator_name': str(assignment.get('name') or ''),
                        'flag_value': flag_value,
                    }
                )
            except Exception:
                out_flags.append(
                    {
                        'generator_id': str(assignment.get('id') or ''),
                        'generator_name': str(assignment.get('name') or ''),
                        'flag_value': '',
                    }
                )

        return jsonify(
            {
                'ok': True,
                'scenario': scenario_label or scenario_norm,
                'node_id': node_id,
                'flags': out_flags,
            }
        )

    mark_routes_registered(app, 'flag_sequencing_values_routes')
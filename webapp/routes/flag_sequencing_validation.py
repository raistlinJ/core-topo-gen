from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_validation_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/test_core_connection', methods=['POST'])
    def api_flow_test_core_connection():
        payload = request.get_json(silent=True) or {}
        scenario_label = str(payload.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400
        try:
            xml_hint = str(payload.get('xml_path') or '').strip()
            xml_path_for_core = ''
            if xml_hint:
                try:
                    xml_path_for_core = backend.os.path.abspath(xml_hint)
                except Exception:
                    xml_path_for_core = xml_hint
            if not xml_path_for_core:
                xml_path_for_core = backend._latest_xml_path_for_scenario(scenario_norm) or ''
            if not xml_path_for_core:
                return jsonify({'ok': False, 'error': 'No XML found for this scenario.'}), 404
            flow_core_cfg = backend._core_config_from_xml_path(xml_path_for_core, scenario_norm, include_password=True)
            explicit_core_host = ''
            explicit_core_port = None
            if isinstance(flow_core_cfg, dict):
                explicit_core_host = str(flow_core_cfg.get('grpc_host') or flow_core_cfg.get('host') or '').strip()
                raw_port = flow_core_cfg.get('grpc_port') if flow_core_cfg.get('grpc_port') not in (None, '') else flow_core_cfg.get('port')
                try:
                    explicit_core_port = int(raw_port) if raw_port not in (None, '') else None
                except Exception:
                    explicit_core_port = None
            page_core_cfg = None
            try:
                page_core_cfg = backend._select_core_config_for_page(scenario_norm, include_password=True)
            except Exception:
                page_core_cfg = None
            if isinstance(page_core_cfg, dict) and page_core_cfg:
                if isinstance(flow_core_cfg, dict) and flow_core_cfg:
                    try:
                        flow_core_cfg = backend._merge_core_configs(page_core_cfg, flow_core_cfg, include_password=True)
                    except Exception:
                        merged = dict(page_core_cfg)
                        merged.update(flow_core_cfg)
                        flow_core_cfg = merged
                else:
                    flow_core_cfg = page_core_cfg
            if isinstance(flow_core_cfg, dict):
                flow_core_cfg = backend._apply_core_secret_to_config(flow_core_cfg, scenario_norm)
                if explicit_core_host:
                    flow_core_cfg['host'] = explicit_core_host
                    flow_core_cfg['grpc_host'] = explicit_core_host
                if explicit_core_port is not None and explicit_core_port > 0:
                    flow_core_cfg['port'] = explicit_core_port
                    flow_core_cfg['grpc_port'] = explicit_core_port
        except Exception:
            flow_core_cfg = None
        if not isinstance(flow_core_cfg, dict):
            return jsonify({'ok': False, 'error': 'No CoreConnection configured in XML for this scenario.'}), 404

        core_validated = False
        try:
            core_validated = backend._coerce_bool(flow_core_cfg.get('validated'))
            if not core_validated:
                status = str(flow_core_cfg.get('last_tested_status') or '').strip().lower()
                if status == 'success':
                    core_validated = True
            if not core_validated:
                try:
                    hv_map = backend._load_scenario_hitl_validation_from_disk()
                    hv = None
                    if isinstance(hv_map, dict):
                        hv = hv_map.get(scenario_norm)
                        if hv is None:
                            try:
                                key = backend._scenario_match_key(scenario_norm)
                            except Exception:
                                key = ''
                            if key:
                                for key_name, value in hv_map.items():
                                    try:
                                        if backend._scenario_match_key(key_name) == key:
                                            hv = value
                                            break
                                    except Exception:
                                        continue
                    hv_core = hv.get('core') if isinstance(hv, dict) else None
                    if isinstance(hv_core, dict):
                        if backend._coerce_bool(hv_core.get('validated')):
                            core_validated = True
                        else:
                            hv_status = str(hv_core.get('last_tested_status') or '').strip().lower()
                            if hv_status == 'success':
                                core_validated = True
                        if not core_validated and str(hv_core.get('core_secret_id') or '').strip():
                            core_validated = True
                except Exception:
                    pass
            if not core_validated:
                try:
                    secret_record = backend._select_latest_core_secret_record(scenario_norm or None)
                except Exception:
                    secret_record = None
                if secret_record and str(secret_record.get('identifier') or '').strip():
                    core_validated = True
        except Exception:
            core_validated = False
        if not core_validated:
            return jsonify({'ok': False, 'error': 'CORE VM is not validated. Validate in VM / Access and save XML, then retry.'}), 422

        try:
            if not backend._coerce_bool(flow_core_cfg.get('ssh_enabled')):
                return jsonify(
                    {
                        'ok': False,
                        'error': 'SSH is required for CORE VM access. Enable SSH in VM / Access and re-validate.',
                        'detail': 'ssh_enabled=false',
                    }
                ), 422
            flow_core_cfg = backend._require_core_ssh_credentials(flow_core_cfg)
            backend._ensure_core_daemon_listening(flow_core_cfg, timeout=5.0)
        except Exception as exc:
            target = f"{flow_core_cfg.get('host')}:{flow_core_cfg.get('port')}"
            return jsonify({'ok': False, 'error': f'CORE connection failed to {target}: {exc}', 'detail': str(exc)}), 502
        return jsonify({'ok': True, 'host': flow_core_cfg.get('host'), 'port': flow_core_cfg.get('port')})

    @app.route('/api/flag-sequencing/revalidate_flow', methods=['POST'])
    def api_flow_revalidate_flow():
        payload = request.get_json(silent=True) or {}
        scenario_label = str(payload.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        xml_hint = str(payload.get('xml_path') or '').strip()
        xml_path = ''
        if xml_hint:
            try:
                xml_path = backend.os.path.abspath(xml_hint)
            except Exception:
                xml_path = xml_hint
        if not xml_path:
            xml_path = backend._latest_xml_path_for_scenario(scenario_norm) or ''
        if not xml_path or not backend.os.path.exists(xml_path):
            return jsonify({'ok': False, 'error': 'No XML found for this scenario.'}), 404

        flow_state = backend._flow_state_from_xml_path(xml_path, scenario_norm)

        def _has_resolved_outputs(assignments: Any) -> bool:
            try:
                array = assignments if isinstance(assignments, list) else []
                for entry in array:
                    if not isinstance(entry, dict):
                        continue
                    resolved_outputs = entry.get('resolved_outputs')
                    if isinstance(resolved_outputs, dict) and resolved_outputs:
                        return True
                return False
            except Exception:
                return False

        xml_assigns: list[dict[str, Any]] = []
        try:
            if isinstance(flow_state, dict) and isinstance(flow_state.get('flag_assignments'), list):
                xml_assigns = [item for item in flow_state.get('flag_assignments') if isinstance(item, dict)]
        except Exception:
            xml_assigns = []

        request_assigns: list[dict[str, Any]] = []
        try:
            raw_req_assigns = payload.get('flag_assignments')
            if isinstance(raw_req_assigns, list):
                request_assigns = [item for item in raw_req_assigns if isinstance(item, dict)]
        except Exception:
            request_assigns = []

        if _has_resolved_outputs(xml_assigns):
            assigns = xml_assigns
        elif _has_resolved_outputs(request_assigns):
            assigns = request_assigns
        elif isinstance(flow_state, dict):
            return jsonify({'ok': False, 'error': 'No resolved outputs saved in XML. Run Generate and Save XML first.'}), 400
        else:
            return jsonify({'ok': False, 'error': 'No FlowState found in XML. Generate (or Save XML) first.'}), 400

        if not assigns:
            return jsonify({'ok': False, 'error': 'No FlowState artifacts to validate. Run Generate and Save XML first.'}), 400

        flow_core_cfg = backend._core_config_from_xml_path(xml_path, scenario_norm, include_password=True)
        if isinstance(flow_core_cfg, dict):
            flow_core_cfg = backend._apply_core_secret_to_config(flow_core_cfg, scenario_norm)
        if not isinstance(flow_core_cfg, dict):
            return jsonify({'ok': False, 'error': 'No CoreConnection configured in XML for this scenario.'}), 404

        try:
            flow_core_cfg = backend._require_core_ssh_credentials(flow_core_cfg)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Remote validation requires SSH credentials: {exc}'}), 400

        missing: list[str] = []
        present: list[str] = []
        container_present: list[str] = []
        container_missing: list[str] = []
        path_map: dict[str, str] = {}
        try:
            check_items: list[dict[str, Any]] = []
            for entry in assigns:
                if not isinstance(entry, dict):
                    continue
                check_items.append(
                    {
                        'node_id': entry.get('node_id') or entry.get('node_name'),
                        'node_name': entry.get('node_name') or ((entry.get('resolved_inputs') or {}).get('node_name') if isinstance(entry.get('resolved_inputs'), dict) else None),
                        'generator_id': entry.get('id') or entry.get('generator_id'),
                        'generator_name': entry.get('name'),
                        'generator_type': entry.get('type') or entry.get('generator_type'),
                        'run_dir': entry.get('run_dir') or entry.get('artifacts_dir'),
                        'artifacts_dir': entry.get('artifacts_dir'),
                        'inject_source_dir': entry.get('inject_source_dir'),
                        'outputs_manifest': entry.get('outputs_manifest'),
                        'inject_files_detail': entry.get('inject_files_detail'),
                        'inject_files': entry.get('inject_files'),
                    }
                )

            try:
                validation_script = backend._remote_flow_artifacts_validation_script(
                    check_items,
                    scenario_label=scenario_norm,
                    sudo_password=flow_core_cfg.get('ssh_password'),
                )
            except TypeError:
                validation_script = backend._remote_flow_artifacts_validation_script(
                    check_items,
                    scenario_label=scenario_norm,
                )

            validation_payload = backend._run_remote_python_json(
                flow_core_cfg,
                validation_script,
                logger=app.logger,
                label='flow.revalidate.artifacts',
                timeout=60.0,
            )
            items = validation_payload.get('items') if isinstance(validation_payload, dict) else None
            if not isinstance(items, list):
                return jsonify({'ok': False, 'error': 'Remote validation returned no items.'}), 500

            for item in items:
                if not isinstance(item, dict):
                    continue
                miss_out = item.get('outputs_missing') if isinstance(item.get('outputs_missing'), list) else []
                miss_inj = item.get('inject_missing') if isinstance(item.get('inject_missing'), list) else []
                chk_out = item.get('outputs_checked') if isinstance(item.get('outputs_checked'), list) else []
                chk_inj = item.get('inject_checked') if isinstance(item.get('inject_checked'), list) else []
                miss_container = item.get('container_missing') if isinstance(item.get('container_missing'), list) else []
                chk_container = item.get('container_checked') if isinstance(item.get('container_checked'), list) else []

                miss_set = {str(value) for value in (miss_out + miss_inj) if str(value).strip()}
                for path in chk_out + chk_inj:
                    value = str(path).strip()
                    if not value or value in miss_set:
                        continue
                    present.append(value)
                    path_map[value] = value
                for path in miss_set:
                    missing.append(str(path))

                container_miss_set = {str(value) for value in miss_container if str(value).strip()}
                for path in chk_container:
                    value = str(path).strip()
                    if not value or value in container_miss_set:
                        continue
                    container_present.append(value)
                for path in container_miss_set:
                    container_missing.append(str(path))
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Remote validation failed: {exc}'}), 500

        return jsonify(
            {
                'ok': True,
                'missing': sorted(set(missing)),
                'present': sorted(set(present)),
                'container_present': sorted(set(container_present)),
                'container_missing': sorted(set(container_missing)),
                'resolved_paths': path_map,
            }
        )

    mark_routes_registered(app, 'flag_sequencing_validation_routes')
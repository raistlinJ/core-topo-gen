from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_latest_preview_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/latest_preview_plan')
    def api_flow_latest_preview_plan():
        scenario_label = (request.args.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        xml_hint = (request.args.get('xml_path') or '').strip()
        xml_path_for_core = ''
        try:
            if xml_hint:
                xml_path_for_core = backend.os.path.abspath(xml_hint)
        except Exception:
            xml_path_for_core = xml_hint
        if not xml_path_for_core:
            xml_path_for_core = backend._latest_xml_path_for_scenario(scenario_norm) or ''

        flow_run_remote = False
        flow_remote_forced = False
        flow_core_cfg: dict[str, Any] | None = None
        args = request.args
        try:
            if 'run_remote' in args:
                flow_run_remote = backend._coerce_bool(args.get('run_remote'))
                flow_remote_forced = flow_run_remote
            if 'run_local' in args and backend._coerce_bool(args.get('run_local')):
                flow_run_remote = False
                flow_remote_forced = False
        except Exception:
            pass
        if not flow_run_remote:
            try:
                selected_cfg = backend._core_config_from_xml_path(xml_path_for_core, scenario_norm, include_password=True)
                if isinstance(selected_cfg, dict):
                    selected_cfg = backend._apply_core_secret_to_config(selected_cfg, scenario_norm)
                if isinstance(selected_cfg, dict) and backend._coerce_bool(selected_cfg.get('ssh_enabled')):
                    flow_core_cfg = selected_cfg
                    flow_run_remote = True
            except Exception:
                flow_core_cfg = None
        if flow_run_remote and not flow_core_cfg:
            try:
                selected_cfg = backend._core_config_from_xml_path(xml_path_for_core, scenario_norm, include_password=True)
                if isinstance(selected_cfg, dict):
                    flow_core_cfg = backend._apply_core_secret_to_config(selected_cfg, scenario_norm)
            except Exception:
                flow_core_cfg = None

        core_validated = False
        try:
            if isinstance(flow_core_cfg, dict):
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
                                    for map_key, value in hv_map.items():
                                        try:
                                            if backend._scenario_match_key(map_key) == key:
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

        def _flow_eligibility_from_payload(payload: dict) -> tuple[int, int, int, bool]:
            docker_count = 0
            vuln_count = 0
            docker_nonvuln_count = 0
            try:
                preview = payload.get('full_preview') if isinstance(payload, dict) else None
                if isinstance(preview, dict):
                    role_counts = preview.get('role_counts') if isinstance(preview.get('role_counts'), dict) else None
                    if isinstance(role_counts, dict):
                        try:
                            docker_count = int(role_counts.get('Docker') or 0)
                        except Exception:
                            docker_count = 0
                    hosts = preview.get('hosts') if isinstance(preview.get('hosts'), list) else []
                    if isinstance(hosts, list):
                        for host in hosts:
                            if not isinstance(host, dict):
                                continue
                            role = str(host.get('role') or '').strip().lower()
                            vulns = host.get('vulnerabilities') if isinstance(host.get('vulnerabilities'), list) else []
                            if role == 'docker':
                                docker_count += 1
                                if not vulns:
                                    docker_nonvuln_count += 1
                            if vulns:
                                vuln_count += 1
                    vuln_by_node = preview.get('vulnerabilities_by_node') if isinstance(preview.get('vulnerabilities_by_node'), dict) else None
                    if isinstance(vuln_by_node, dict):
                        vuln_count = max(vuln_count, len([key for key, value in vuln_by_node.items() if value]))
            except Exception:
                docker_count = docker_count
                vuln_count = vuln_count
                docker_nonvuln_count = docker_nonvuln_count
            flow_eligible = bool((docker_count or 0) > 0 or (vuln_count or 0) > 0)
            return docker_count, vuln_count, docker_nonvuln_count, flow_eligible

        def _flow_eligibility_details(payload: dict | None) -> dict[str, Any]:
            docker_count, vuln_count, docker_nonvuln_count, topology_eligible = _flow_eligibility_from_payload(payload or {})
            try:
                flag_generators, _ = backend._flag_generators_from_enabled_sources()
                flag_generator_count = len([generator for generator in (flag_generators or []) if isinstance(generator, dict)])
            except Exception:
                flag_generator_count = 0
            try:
                flag_node_generators, _ = backend._flag_node_generators_from_enabled_sources()
                flag_node_generator_count = len([generator for generator in (flag_node_generators or []) if isinstance(generator, dict)])
            except Exception:
                flag_node_generator_count = 0
            try:
                vuln_catalog_count = len(backend._load_backend_vuln_catalog_items() or [])
            except Exception:
                vuln_catalog_count = 0

            has_vuln_generator_path = bool(vuln_count > 0 and flag_generator_count > 0)
            has_node_generator_path = bool(docker_nonvuln_count > 0 and flag_node_generator_count > 0)
            flow_eligible = bool(core_validated and (has_vuln_generator_path or has_node_generator_path))

            reasons: list[str] = []
            if not core_validated:
                reasons.append('CORE VM must be validated in VM / Access.')
            if not topology_eligible:
                reasons.append('Topology must include Docker or vulnerability nodes.')
            if vuln_catalog_count <= 0:
                reasons.append('No vulnerabilities are available in the Vulnerability Catalog.')
            if vuln_count > 0 and flag_generator_count <= 0:
                reasons.append('No enabled flag-generators are available for vulnerability nodes.')
            if docker_nonvuln_count > 0 and flag_node_generator_count <= 0:
                reasons.append('No enabled flag-node-generators are available for non-vulnerability Docker nodes.')
            if topology_eligible and not has_vuln_generator_path and not has_node_generator_path and flag_generator_count <= 0 and flag_node_generator_count <= 0:
                reasons.append('No enabled generators are available for this topology.')

            return {
                'docker_count': docker_count,
                'vuln_count': vuln_count,
                'docker_nonvuln_count': docker_nonvuln_count,
                'flow_topology_eligible': topology_eligible,
                'flag_generator_count': flag_generator_count,
                'flag_node_generator_count': flag_node_generator_count,
                'vuln_catalog_count': vuln_catalog_count,
                'flow_eligible': flow_eligible,
                'flow_eligibility_reasons': reasons,
            }

        preview_payload: dict[str, Any] | None = None
        preview_path = ''
        preview_source = ''
        preview_meta: dict[str, Any] = {}

        if xml_hint:
            try:
                xml_abs = backend.os.path.abspath(xml_hint)
                if backend.os.path.exists(xml_abs) and xml_abs.lower().endswith('.xml'):
                    payload = backend._load_plan_preview_from_xml(xml_abs, scenario_label or scenario_norm)
                    if payload and isinstance(payload, dict):
                        metadata = payload.get('metadata') if isinstance(payload.get('metadata'), dict) else {}
                        scenario_check = str(metadata.get('scenario') or '').strip()
                        if not scenario_check or backend._normalize_scenario_label(scenario_check) == scenario_norm:
                            preview_payload = payload
                            preview_path = xml_abs
                            preview_source = 'xml'
                            preview_meta = metadata or {}
            except Exception:
                pass

        if preview_payload is None:
            try:
                xml_path = backend._latest_xml_path_for_scenario(scenario_norm)
                if xml_path:
                    payload = backend._load_plan_preview_from_xml(xml_path, scenario_label or scenario_norm)
                    if payload and isinstance(payload, dict):
                        preview_payload = payload
                        preview_path = xml_path
                        preview_source = 'xml'
                        preview_meta = payload.get('metadata') if isinstance(payload.get('metadata'), dict) else {}
            except Exception:
                pass

        if not core_validated:
            details = _flow_eligibility_details(preview_payload)
            return jsonify(
                {
                    'ok': False,
                    'error': 'Flag sequencing requires a validated CORE VM. Validate in VM / Access and save XML, then retry.',
                    'scenario': scenario_label or scenario_norm,
                    'preview_plan_path': preview_path,
                    'preview_source': preview_source,
                    'metadata': preview_meta,
                    'core_validated': False,
                    **details,
                }
            ), 422

        if preview_payload is not None:
            details = _flow_eligibility_details(preview_payload)
            return jsonify(
                {
                    'ok': True,
                    'scenario': scenario_label or scenario_norm,
                    'preview_plan_path': preview_path,
                    'preview_source': preview_source,
                    'metadata': preview_meta,
                    'core_validated': True,
                    **details,
                }
            )

        return jsonify({'ok': False, 'error': 'No XML found for this scenario. Save XML with a PlanPreview first.'}), 404

    mark_routes_registered(app, 'flag_sequencing_latest_preview_routes')
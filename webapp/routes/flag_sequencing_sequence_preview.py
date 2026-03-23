from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_sequence_preview_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/sequence_preview_plan', methods=['POST'])
    def api_flow_sequence_preview_plan():
        """Generate a Flow chain from an existing preview plan and persist sequence metadata."""
        payload_in = request.get_json(silent=True) or {}
        scenario_label = str(payload_in.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        preset = str(payload_in.get('preset') or '').strip()
        allow_node_duplicates = str(payload_in.get('allow_node_duplicates') or payload_in.get('allow_duplicates') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        length = 5
        try:
            length = int(payload_in.get('length') or 5)
        except Exception:
            length = 5
        preset_steps = backend._flow_preset_steps(preset)
        if preset_steps:
            length = len(preset_steps)
        length = max(1, min(length, 50))
        requested_length = length
        best_effort = bool(payload_in.get('best_effort'))

        flow_seed_param: int | None = None
        try:
            flow_seed_raw = payload_in.get('flow_seed')
            if flow_seed_raw is not None:
                flow_seed_param = int(flow_seed_raw)
        except (ValueError, TypeError):
            flow_seed_param = None

        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        def _validation_failure(message: str, **extra: Any):
            failure_payload = {'ok': False, 'error': message, 'validation_error': True}
            failure_payload.update(extra)
            return jsonify(failure_payload)

        preview_plan_path = str(payload_in.get('preview_plan') or '').strip() or None
        xml_hint = str(payload_in.get('xml_path') or '').strip()
        if preview_plan_path:
            try:
                preview_plan_path = backend.os.path.abspath(preview_plan_path)
                if (not preview_plan_path.lower().endswith('.xml')) or (not backend.os.path.exists(preview_plan_path)):
                    preview_plan_path = None
            except Exception:
                preview_plan_path = None

        if not preview_plan_path and xml_hint:
            try:
                xml_abs = backend.os.path.abspath(xml_hint)
                if backend.os.path.exists(xml_abs) and xml_abs.lower().endswith('.xml'):
                    payload_hint = backend._load_plan_preview_from_xml(xml_abs, scenario_norm)
                    if isinstance(payload_hint, dict):
                        meta_hint = payload_hint.get('metadata') if isinstance(payload_hint.get('metadata'), dict) else {}
                        scenario_hint = str(meta_hint.get('scenario') or '').strip()
                        if (not scenario_hint) or backend._normalize_scenario_label(scenario_hint) == scenario_norm:
                            preview_plan_path = xml_abs
            except Exception:
                pass

        if not preview_plan_path:
            preview_plan_path = backend._latest_xml_path_for_scenario(scenario_norm)

        if not preview_plan_path:
            return jsonify({'ok': False, 'error': 'No XML found for this scenario. Save XML with a PlanPreview first.'}), 404

        try:
            payload = backend._load_preview_payload_from_path(preview_plan_path, scenario_norm)
            if not isinstance(payload, dict):
                return jsonify({'ok': False, 'error': 'Preview plan not embedded in XML.'}), 422
            backend._canonicalize_payload_flow_from_xml(
                payload,
                xml_path=preview_plan_path,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed to load preview plan: {exc}'}), 422

        preview = payload.get('full_preview') if isinstance(payload, dict) else None
        if not isinstance(preview, dict):
            return jsonify({'ok': False, 'error': 'Preview plan is missing full_preview.'}), 422

        nodes, _links, adj = backend._build_topology_graph_from_preview_plan(preview)
        stats = backend._flow_compose_docker_stats(nodes)

        if preset_steps:
            chain_nodes = backend._pick_flag_chain_nodes_for_preset(nodes, adj, steps=preset_steps)
        else:
            if allow_node_duplicates:
                seed_val = backend._get_flow_seed(preview, flow_seed_param)
                chain_nodes = backend._pick_flag_chain_nodes_allow_duplicates(nodes, adj, length=length, seed=seed_val)
            else:
                chain_nodes = backend._pick_flag_chain_nodes(nodes, adj, length=length)

        if not chain_nodes:
            return _validation_failure(
                'No eligible nodes found in preview plan.',
                available=0,
                requested_length=requested_length,
                stats=stats,
            )

        warning: str | None = None

        if (not preset_steps) and (not allow_node_duplicates) and len(chain_nodes) < length:
            if best_effort:
                warning = f'Only {len(chain_nodes)} eligible nodes found; using chain length {len(chain_nodes)} instead of requested {length}.'
                length = len(chain_nodes)
            else:
                return _validation_failure(
                    'Not enough eligible nodes in preview plan to build the requested chain.',
                    available=len(chain_nodes),
                    requested_length=requested_length,
                    stats=stats,
                )

        host_by_id: dict[str, dict[str, Any]] = {}
        try:
            hosts = preview.get('hosts') if isinstance(preview, dict) else None
            if isinstance(hosts, list):
                for host in hosts:
                    if not isinstance(host, dict):
                        continue
                    host_id = str(host.get('node_id') or host.get('id') or '').strip()
                    if host_id:
                        host_by_id[host_id] = host
        except Exception:
            host_by_id = {}
        try:
            vuln_by_node = preview.get('vulnerabilities_by_node') if isinstance(preview, dict) else None
            if not isinstance(vuln_by_node, dict):
                vuln_by_node = {}
        except Exception:
            vuln_by_node = {}
        try:
            if host_by_id:
                for node in (chain_nodes or []):
                    if not isinstance(node, dict):
                        continue
                    node_id = str(node.get('id') or '').strip()
                    if not node_id:
                        continue
                    host = host_by_id.get(node_id)
                    if not isinstance(host, dict):
                        continue
                    ip_value = backend._preview_host_ip4_any(host)
                    if ip_value:
                        if not (node.get('ip4') or node.get('ipv4') or node.get('ip') or node.get('address')):
                            node['ip4'] = ip_value
                            node['ipv4'] = ip_value
                    interfaces = host.get('interfaces') if isinstance(host.get('interfaces'), list) else None
                    if interfaces and not node.get('interfaces'):
                        node['interfaces'] = interfaces
        except Exception:
            pass

        initial_facts_override = backend._flow_normalize_fact_override(payload_in.get('initial_facts'))
        goal_facts_override = backend._flow_normalize_fact_override(payload_in.get('goal_facts'))
        retry_index = 0
        try:
            retry_index = int(payload_in.get('retry_index') or 0)
        except Exception:
            retry_index = 0

        if preset_steps:
            flag_assignments, preset_err = backend._flow_compute_flag_assignments_for_preset(preview, chain_nodes, scenario_label or scenario_norm, preset)
            if preset_err:
                return _validation_failure(f'Error: {preset_err}', stats=stats)
        else:
            base_seed = backend._get_flow_seed(preview, flow_seed_param)
            seed_override = base_seed ^ (retry_index * 0x9E3779B1) if retry_index else flow_seed_param
            flag_assignments = backend._flow_compute_flag_assignments(
                preview,
                chain_nodes,
                scenario_label or scenario_norm,
                initial_facts_override=initial_facts_override,
                goal_facts_override=goal_facts_override,
                seed_override=seed_override,
                disallow_generator_reuse=(not allow_node_duplicates),
            )
            if (not flag_assignments) and (not allow_node_duplicates):
                return _validation_failure(
                    'Not enough unique generators for this chain length while duplicates are disabled. Reduce chain length or enable duplicates.',
                    scenario=scenario_label or scenario_norm,
                    length=len(chain_nodes or []),
                    chain=[{'id': str(node.get('id') or ''), 'name': str(node.get('name') or ''), 'type': str(node.get('type') or '')} for node in (chain_nodes or []) if isinstance(node, dict)],
                )

        try:
            ids = [str(node.get('id') or '').strip() for node in (chain_nodes or []) if isinstance(node, dict) and str(node.get('id') or '').strip()]
            has_dupes = len(set(ids)) != len(ids)
        except Exception:
            has_dupes = False

        if (not preset_steps) and (not has_dupes):
            try:
                debug_dag = bool(payload_in.get('debug_dag'))
            except Exception:
                debug_dag = False
            chain_nodes, flag_assignments, _dag_debug = backend._flow_reorder_chain_by_generator_dag(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
                return_debug=bool(debug_dag),
            )

        try:
            flow_valid, flow_errors = backend._flow_validate_chain_order_by_requires_produces(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            flow_valid, flow_errors = True, []

        if not allow_node_duplicates:
            try:
                generator_ids = [str(assignment.get('id') or assignment.get('generator_id') or '').strip() for assignment in (flag_assignments or []) if isinstance(assignment, dict)]
                generator_ids = [generator_id for generator_id in generator_ids if generator_id]
                if len(set(generator_ids)) != len(generator_ids):
                    return _validation_failure(
                        'Duplicate generators detected while duplicates are disabled. Reduce chain length or enable duplicates.',
                        scenario=scenario_label or scenario_norm,
                        length=len(chain_nodes or []),
                        chain=[{'id': str(node.get('id') or ''), 'name': str(node.get('name') or ''), 'type': str(node.get('type') or '')} for node in (chain_nodes or []) if isinstance(node, dict)],
                        flag_assignments=flag_assignments,
                    )
            except Exception:
                pass

        host_ip_map: dict[str, str] = {}
        try:
            for host_id, host in (host_by_id or {}).items():
                ip_value = backend._preview_host_ip4_any(host)
                if ip_value:
                    host_ip_map[str(host_id)] = ip_value
        except Exception:
            host_ip_map = {}

        chain_payload: list[dict[str, Any]] = []
        try:
            for node in (chain_nodes or []):
                if not isinstance(node, dict):
                    continue
                node_id = str(node.get('id') or '').strip()
                host = host_by_id.get(node_id) if node_id else None
                ip_value = backend._preview_host_ip4_any(host) if isinstance(host, dict) else ''
                if not ip_value:
                    ip_value = backend._first_valid_ipv4(node.get('ip4') or node.get('ipv4') or node.get('ip') or '')
                interfaces = None
                try:
                    interfaces = host.get('interfaces') if isinstance(host, dict) and isinstance(host.get('interfaces'), list) else None
                except Exception:
                    interfaces = None
                vulns: list[str] = []
                try:
                    if isinstance(host, dict) and isinstance(host.get('vulnerabilities'), list):
                        vulns = [str(v).strip() for v in (host.get('vulnerabilities') or []) if str(v).strip()]
                except Exception:
                    vulns = []
                if not vulns:
                    try:
                        if isinstance(node.get('vulnerabilities'), list):
                            vulns = [str(v).strip() for v in (node.get('vulnerabilities') or []) if str(v).strip()]
                    except Exception:
                        vulns = []
                if (not vulns) and node_id:
                    try:
                        raw_vulns = vuln_by_node.get(node_id)
                        if isinstance(raw_vulns, list):
                            vulns = [str(v).strip() for v in raw_vulns if str(v).strip()]
                    except Exception:
                        vulns = []
                is_vuln = bool(vulns) or bool(node.get('is_vuln')) or bool(node.get('is_vulnerability')) or bool(node.get('is_vulnerable'))
                chain_payload.append(
                    {
                        'id': str(node.get('id') or ''),
                        'name': str(node.get('name') or ''),
                        'type': str(node.get('type') or ''),
                        'is_vuln': bool(is_vuln),
                        'vulnerabilities': list(vulns or []),
                        'ip4': str(ip_value or ''),
                        'ipv4': str(ip_value or ''),
                        'interfaces': list(interfaces or []) if isinstance(interfaces, list) else [],
                    }
                )
        except Exception:
            chain_payload = [
                {
                    'id': str(node.get('id') or ''),
                    'name': str(node.get('name') or ''),
                    'type': str(node.get('type') or ''),
                    'is_vuln': bool(node.get('is_vuln')),
                }
                for node in (chain_nodes or [])
                if isinstance(node, dict)
            ]

        try:
            metadata = payload.get('metadata') if isinstance(payload, dict) else {}
            flow_meta = {
                'source_preview_plan_path': backend._abs_path_or_original(preview_plan_path),
                'scenario': scenario_label or scenario_norm,
                'length': len(chain_nodes),
                'requested_length': requested_length,
                'allow_node_duplicates': bool(allow_node_duplicates),
                'chain': list(chain_payload or []),
                'flag_assignments': backend._flow_strip_runtime_sensitive_fields(flag_assignments),
                'flags_enabled': bool(flow_valid),
                'flow_valid': bool(flow_valid),
                'flow_errors': list(flow_errors or []),
                'modified_at': backend._iso_now(),
            }
            if initial_facts_override:
                flow_meta['initial_facts'] = initial_facts_override
            if goal_facts_override:
                flow_meta['goal_facts'] = goal_facts_override
            if warning:
                flow_meta['warning'] = warning
            if isinstance(metadata, dict):
                metadata = dict(metadata)
                metadata['flow'] = flow_meta
            else:
                metadata = {'flow': flow_meta}
            payload['metadata'] = metadata
            if isinstance(preview, dict):
                preview.setdefault('metadata', {})
        except Exception:
            pass

        try:
            if isinstance(metadata, dict):
                metadata = dict(metadata)
                metadata['updated_at'] = backend._iso_now()
            xml_path_for_plan = None
            try:
                if preview_plan_path and str(preview_plan_path).lower().endswith('.xml'):
                    xml_path_for_plan = backend.os.path.abspath(preview_plan_path)
            except Exception:
                xml_path_for_plan = None
            if not xml_path_for_plan:
                try:
                    metadata_xml = str((metadata or {}).get('xml_path') or '').strip()
                    if metadata_xml:
                        xml_path_for_plan = backend.os.path.abspath(metadata_xml)
                except Exception:
                    xml_path_for_plan = None
            if not xml_path_for_plan and xml_hint:
                try:
                    xml_hint_abs = backend.os.path.abspath(xml_hint)
                    if xml_hint_abs.lower().endswith('.xml'):
                        xml_path_for_plan = xml_hint_abs
                except Exception:
                    xml_path_for_plan = None
            if not xml_path_for_plan:
                try:
                    xml_path_for_plan = backend._latest_xml_path_for_scenario(scenario_norm)
                except Exception:
                    xml_path_for_plan = None
            if not xml_path_for_plan or not backend.os.path.exists(xml_path_for_plan):
                return jsonify({'ok': False, 'error': 'Failed to persist sequence plan: XML path not found.'}), 500

            plan_payload = {
                'full_preview': preview,
                'metadata': metadata,
            }
            ok, err = backend._update_plan_preview_in_xml(xml_path_for_plan, scenario_label or scenario_norm, plan_payload)
            if not ok:
                return jsonify({'ok': False, 'error': f'Failed to persist sequence plan: {err}'}), 500
            try:
                backend._update_flow_state_in_xml(xml_path_for_plan, scenario_label or scenario_norm, flow_meta)
            except Exception:
                pass
            try:
                backend._planner_set_plan(scenario_norm, plan_path=xml_path_for_plan, xml_path=xml_path_for_plan, seed=(metadata or {}).get('seed'))
            except Exception:
                pass
            out_path = xml_path_for_plan
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed to persist sequence plan: {exc}'}), 500

        response_flow_seed = backend._get_flow_seed(preview, flow_seed_param)

        return jsonify(
            {
                'ok': True,
                'scenario': scenario_label or scenario_norm,
                'length': len(chain_nodes),
                'requested_length': requested_length,
                'stats': stats,
                'chain': list(chain_payload or []),
                'flag_assignments': flag_assignments,
                'flags_enabled': bool(flow_valid),
                'flow_valid': bool(flow_valid),
                'flow_errors': list(flow_errors or []),
                'flow_seed': response_flow_seed,
                'preview_plan_path': out_path,
                'base_preview_plan_path': preview_plan_path,
                **({'warning': warning} if warning else {}),
                **({'host_ip_map': host_ip_map} if host_ip_map else {}),
            }
        )

    mark_routes_registered(app, 'flag_sequencing_sequence_preview_routes')
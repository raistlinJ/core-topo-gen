from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_substitutions_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/save_flow_substitutions', methods=['POST'])
    def api_flow_save_flow_substitutions():
        """Persist a user-edited chain + generator assignments (no generator runs).

        This updates the single per-scenario plan file with metadata.flow.chain and
        metadata.flow.flag_assignments so future preview/prepare/execute honors the
        user's substitutions.
        """
        payload = request.get_json(silent=True) or {}
        warning: str | None = None
        scenario_label = str(payload.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        allow_node_duplicates = False
        try:
            allow_node_duplicates = str(payload.get('allow_node_duplicates') or '').strip().lower() in {
                '1', 'true', 't', 'yes', 'y', 'on'
            }
        except Exception:
            allow_node_duplicates = False

        chain_ids_in = payload.get('chain_ids')
        if not isinstance(chain_ids_in, list) or not chain_ids_in:
            return jsonify({'ok': False, 'error': 'Missing chain_ids.'}), 400
        chain_ids: list[str] = [str(item or '').strip() for item in chain_ids_in if str(item or '').strip()]
        if not chain_ids:
            return jsonify({'ok': False, 'error': 'Missing chain_ids.'}), 400

        base_plan_path = str(payload.get('preview_plan') or '').strip() or None
        if base_plan_path:
            base_plan_path = backend._existing_xml_path_or_none(base_plan_path)
        if not base_plan_path:
            try:
                entry = backend._planner_get_plan(scenario_norm)
                if entry:
                    base_plan_path = (
                        backend._existing_xml_path_or_none(entry.get('plan_path'))
                        or backend._existing_xml_path_or_none(entry.get('xml_path'))
                        or base_plan_path
                    )
            except Exception:
                base_plan_path = base_plan_path

        if not base_plan_path:
            base_plan_path = backend._latest_preview_plan_for_scenario_norm_origin(scenario_norm, origin='planner')

        if not base_plan_path:
            try:
                entry = backend._planner_get_plan(scenario_norm)
                if entry:
                    base_plan_path = entry.get('plan_path') or base_plan_path
            except Exception:
                base_plan_path = base_plan_path

        if not base_plan_path:
            base_plan_path = backend._latest_preview_plan_for_scenario_norm_origin(scenario_norm, origin='planner')

        if not base_plan_path:
            base_plan_path = backend._latest_preview_plan_for_scenario_norm(scenario_norm, prefer_flow=True)
        if not base_plan_path or not backend.os.path.exists(base_plan_path):
            return jsonify({'ok': False, 'error': 'No preview plan found for this scenario. Generate a Full Preview first.'}), 404

        try:
            preview_payload = backend._load_preview_payload_from_path(base_plan_path, scenario_norm)
            if not isinstance(preview_payload, dict):
                return jsonify({'ok': False, 'error': 'Preview plan not embedded in XML. Save XML with Preview first.'}), 404
            meta = preview_payload.get('metadata') if isinstance(preview_payload, dict) else {}
            preview = preview_payload.get('full_preview') if isinstance(preview_payload, dict) else None
            if not isinstance(preview, dict):
                return jsonify({'ok': False, 'error': 'Preview plan is missing full_preview.'}), 422
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed to load preview plan: {exc}'}), 500

        initial_facts_override = backend._flow_normalize_fact_override(payload.get('initial_facts'))
        goal_facts_override = backend._flow_normalize_fact_override(payload.get('goal_facts'))
        try:
            flow_existing = meta.get('flow') if isinstance(meta, dict) else None
            if initial_facts_override is None and isinstance(flow_existing, dict):
                initial_facts_override = backend._flow_normalize_fact_override(flow_existing.get('initial_facts'))
            if goal_facts_override is None and isinstance(flow_existing, dict):
                goal_facts_override = backend._flow_normalize_fact_override(flow_existing.get('goal_facts'))
        except Exception:
            pass

        try:
            nodes, _links, _adj = backend._build_topology_graph_from_preview_plan(preview)
        except Exception:
            nodes = []
        id_map = {
            str(node.get('id') or '').strip(): node
            for node in (nodes or [])
            if isinstance(node, dict) and str(node.get('id') or '').strip()
        }
        chain_nodes: list[dict[str, Any]] = []
        for chain_id in chain_ids:
            node = id_map.get(str(chain_id))
            if not isinstance(node, dict):
                return jsonify({'ok': False, 'error': f'Chain node not found in preview plan: {chain_id}'}), 422
            chain_nodes.append(node)

        fas_in = payload.get('flag_assignments')
        if not isinstance(fas_in, list) or len(fas_in) != len(chain_nodes):
            return jsonify({'ok': False, 'error': 'flag_assignments must be a list aligned to chain_ids (same length).'}), 400

        try:
            generators, _ = backend._flag_generators_from_enabled_sources()
        except Exception:
            generators = []
        try:
            node_generators, _ = backend._flag_node_generators_from_enabled_sources()
        except Exception:
            node_generators = []
        gen_by_id: dict[str, dict[str, Any]] = {}
        for generator in (generators or []):
            if not isinstance(generator, dict):
                continue
            generator_id = str(generator.get('id') or '').strip()
            if generator_id and generator_id not in gen_by_id:
                generator_copy = dict(generator)
                generator_copy['_flow_kind'] = 'flag-generator'
                generator_copy['_flow_catalog'] = 'flag_generators'
                gen_by_id[generator_id] = generator_copy
        for generator in (node_generators or []):
            if not isinstance(generator, dict):
                continue
            generator_id = str(generator.get('id') or '').strip()
            if generator_id and generator_id not in gen_by_id:
                generator_copy = dict(generator)
                generator_copy['_flow_kind'] = 'flag-node-generator'
                generator_copy['_flow_catalog'] = 'flag_node_generators'
                gen_by_id[generator_id] = generator_copy

        try:
            plugins_by_id = backend._flow_enabled_plugin_contracts_by_id()
        except Exception:
            plugins_by_id = {}

        id_to_name: dict[str, str] = {}
        for node in chain_nodes:
            try:
                node_id = str(node.get('id') or '').strip()
                node_name = str(node.get('name') or '').strip()
                if node_id:
                    id_to_name[node_id] = node_name or node_id
            except Exception:
                pass

        def _artifact_requires_of(generator: dict[str, Any]) -> set[str]:
            required: set[str] = set()
            try:
                plugin_id = str(generator.get('id') or '').strip()
                plugin = plugins_by_id.get(plugin_id)
                if isinstance(plugin, dict) and isinstance(plugin.get('requires'), list):
                    for item in (plugin.get('requires') or []):
                        value = str(item).strip()
                        if value:
                            required.add(value)
            except Exception:
                pass
            try:
                required = {value for value in required if value not in backend._flow_synthesized_inputs()}
            except Exception:
                pass
            return required

        def _artifact_produces_of(generator: dict[str, Any]) -> set[str]:
            provides: set[str] = set()
            try:
                plugin_id = str(generator.get('id') or '').strip()
                plugin = plugins_by_id.get(plugin_id)
                if isinstance(plugin, dict) and isinstance(plugin.get('produces'), list):
                    for item in (plugin.get('produces') or []):
                        if not isinstance(item, dict):
                            continue
                        artifact = str(item.get('artifact') or '').strip()
                        if artifact:
                            provides.add(artifact)
            except Exception:
                pass
            return provides

        def _required_input_fields_of(generator: dict[str, Any]) -> set[str]:
            required: set[str] = set()
            try:
                inputs = generator.get('inputs')
                if isinstance(inputs, list):
                    for input_item in inputs:
                        if not isinstance(input_item, dict):
                            continue
                        name = str(input_item.get('name') or '').strip()
                        if not name or input_item.get('required') is False:
                            continue
                        required.add(name)
            except Exception:
                pass
            return required

        def _all_input_fields_of(generator: dict[str, Any]) -> set[str]:
            fields: set[str] = set()
            try:
                inputs = generator.get('inputs')
                if isinstance(inputs, list):
                    for input_item in inputs:
                        if not isinstance(input_item, dict):
                            continue
                        name = str(input_item.get('name') or '').strip()
                        if name:
                            fields.add(name)
            except Exception:
                pass
            return fields

        def _output_fields_of(generator: dict[str, Any]) -> set[str]:
            out_fields: set[str] = set()
            try:
                outputs = generator.get('outputs')
                if isinstance(outputs, list):
                    for output_item in outputs:
                        if not isinstance(output_item, dict):
                            continue
                        name = str(output_item.get('name') or '').strip()
                        if name:
                            out_fields.add(name)
            except Exception:
                pass
            try:
                out_fields |= _artifact_produces_of(generator)
            except Exception:
                pass
            return out_fields

        def _provides_of(generator: dict[str, Any]) -> set[str]:
            provides: set[str] = set()
            try:
                provides |= _artifact_produces_of(generator)
            except Exception:
                pass
            try:
                provided = generator.get('provides')
                if isinstance(provided, list):
                    for item in provided:
                        value = str(item).strip()
                        if value:
                            provides.add(value)
            except Exception:
                pass
            try:
                provides |= _output_fields_of(generator)
            except Exception:
                pass
            return provides

        out_assignments: list[dict[str, Any]] = []
        for index, (chain_id, raw_assignment) in enumerate(zip(chain_ids, (fas_in or []))):
            if not isinstance(raw_assignment, dict):
                raw_assignment = {}

            generator_id = str(raw_assignment.get('id') or raw_assignment.get('generator_id') or '').strip()
            if not generator_id:
                return jsonify({'ok': False, 'error': f'Missing generator id for position {index}.'}), 400

            generator = gen_by_id.get(generator_id)
            if not isinstance(generator, dict):
                return jsonify({'ok': False, 'error': f'Generator not found/enabled: {generator_id}'}), 422

            assignment = dict(raw_assignment)
            assignment['node_id'] = str(chain_id)
            assignment['id'] = str(generator_id)
            assignment['name'] = str(generator.get('name') or '')
            assignment['description'] = str(generator.get('description') or '')
            assignment['type'] = str(generator.get('_flow_kind') or assignment.get('type') or 'flag-generator')
            assignment['flag_generator'] = str(generator.get('_source_name') or '').strip() or 'unknown'
            assignment['generator_catalog'] = str(generator.get('_flow_catalog') or assignment.get('generator_catalog') or 'flag_generators')
            assignment['language'] = str(generator.get('language') or '')

            hint_templates = backend._flow_hint_templates_from_generator(generator)
            assignment['hint_templates'] = hint_templates
            assignment['hint_template'] = str((hint_templates[0] if hint_templates else '') or '')

            try:
                next_id = chain_ids[index + 1] if (index + 1) < len(chain_ids) else ''
            except Exception:
                next_id = ''
            assignment['next_node_id'] = str(next_id)
            assignment['next_node_name'] = str(id_to_name.get(str(next_id)) or '')

            requires_artifacts = sorted(list(_artifact_requires_of(generator)))
            produces_artifacts = sorted(list(_artifact_produces_of(generator)))
            input_fields_required = sorted(list(_required_input_fields_of(generator)))
            input_fields_all = sorted(list(_all_input_fields_of(generator)))
            input_fields_optional = sorted([value for value in input_fields_all if value and value not in set(input_fields_required)])
            output_fields = sorted(list(_output_fields_of(generator)))

            allowed_override_keys: set[str] = set(input_fields_all)
            try:
                allowed_override_keys |= set(backend._flow_synthesized_inputs())
            except Exception:
                pass

            raw_overrides: Any = None
            overrides_present = False
            try:
                if 'config_overrides' in assignment:
                    overrides_present = True
                    raw_overrides = assignment.get('config_overrides')
                elif 'inputs_overrides' in assignment:
                    overrides_present = True
                    raw_overrides = assignment.get('inputs_overrides')
                elif 'input_overrides' in assignment:
                    overrides_present = True
                    raw_overrides = assignment.get('input_overrides')
            except Exception:
                overrides_present = False
                raw_overrides = None

            if overrides_present:
                if raw_overrides is None:
                    assignment.pop('config_overrides', None)
                elif isinstance(raw_overrides, dict):
                    config_overrides: dict[str, Any] = {}
                    for key, value in (raw_overrides or {}).items():
                        key_name = str(key or '').strip()
                        if not key_name or key_name not in allowed_override_keys:
                            continue
                        config_overrides[key_name] = value
                    if config_overrides:
                        assignment['config_overrides'] = dict(config_overrides)
                    else:
                        assignment.pop('config_overrides', None)
                else:
                    assignment.pop('config_overrides', None)

            assignment.pop('inputs_overrides', None)
            assignment.pop('input_overrides', None)

            assignment['requires'] = requires_artifacts
            assignment['produces'] = produces_artifacts
            assignment['input_fields'] = input_fields_all
            assignment['input_fields_required'] = input_fields_required
            assignment['input_fields_optional'] = input_fields_optional
            assignment['output_fields'] = output_fields

            assignment['inputs'] = sorted(list((_artifact_requires_of(generator) | set(_required_input_fields_of(generator)))))
            assignment['outputs'] = sorted(list(_provides_of(generator)))

            try:
                resolved_inputs: dict[str, Any] | None = None
                resolved_outputs: dict[str, Any] | None = None
                if 'resolved_inputs' in raw_assignment and isinstance(raw_assignment.get('resolved_inputs'), dict):
                    resolved_inputs = dict(raw_assignment.get('resolved_inputs') or {})
                if 'resolved_outputs' in raw_assignment and isinstance(raw_assignment.get('resolved_outputs'), dict):
                    resolved_outputs = dict(raw_assignment.get('resolved_outputs') or {})

                config_overrides = assignment.get('config_overrides') if isinstance(assignment, dict) else None
                if isinstance(config_overrides, dict) and config_overrides:
                    resolved_inputs = dict(resolved_inputs or {})
                    resolved_inputs.update(config_overrides)

                output_overrides = assignment.get('output_overrides') if isinstance(assignment, dict) else None
                if isinstance(output_overrides, dict) and output_overrides:
                    resolved_outputs = dict(resolved_outputs or {})
                    resolved_outputs.update(output_overrides)

                flag_value = None
                if isinstance(raw_assignment.get('flag_value'), str) and str(raw_assignment.get('flag_value') or '').strip():
                    flag_value = str(raw_assignment.get('flag_value') or '').strip()
                if isinstance(assignment.get('flag_override'), str) and str(assignment.get('flag_override') or '').strip():
                    flag_value = str(assignment.get('flag_override') or '').strip()
                if flag_value:
                    resolved_outputs = dict(resolved_outputs or {})
                    resolved_outputs['Flag(flag_id)'] = flag_value
                    assignment['flag_value'] = flag_value

                if isinstance(resolved_inputs, dict) and resolved_inputs:
                    assignment['resolved_inputs'] = resolved_inputs
                if isinstance(resolved_outputs, dict) and resolved_outputs:
                    assignment['resolved_outputs'] = resolved_outputs
            except Exception:
                pass

            out_assignments.append(assignment)

        try:
            out_assignments = backend._flow_enrich_saved_flag_assignments(
                out_assignments,
                chain_nodes,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            pass

        try:
            flow_valid, flow_errors = backend._flow_validate_chain_order_by_requires_produces(
                chain_nodes,
                out_assignments,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            flow_valid, flow_errors = True, []
        try:
            assign_ids = [str(item.get('id') or item.get('generator_id') or '').strip() for item in (out_assignments or []) if isinstance(item, dict)]
            chain_ids_dbg = [str(node.get('id') or '').strip() for node in (chain_nodes or []) if isinstance(node, dict) and str(node.get('id') or '').strip()]
            vuln_nodes_dbg = len([node for node in (chain_nodes or []) if isinstance(node, dict) and backend._flow_node_is_vuln(node)])
            docker_nodes_dbg = len([node for node in (chain_nodes or []) if isinstance(node, dict) and backend._flow_node_is_docker_role(node)])
            flow_errors_detail = (
                f"assignments={len(out_assignments or [])} "
                f"assignments_with_id={len([item for item in assign_ids if item])} "
                f"chain_nodes={len(chain_nodes or [])} "
                f"chain_vuln_nodes={vuln_nodes_dbg} "
                f"chain_docker_nodes={docker_nodes_dbg} "
                f"chain_ids={','.join(chain_ids_dbg)} "
                f"base_plan={backend.os.path.basename(str(base_plan_path or ''))}"
            )
        except Exception:
            flow_errors_detail = None
        try:
            app.logger.info(
                '[flow.save_flow_substitutions] scenario=%s flow_valid=%s flow_errors=%s detail=%s',
                scenario_norm,
                bool(flow_valid),
                (flow_errors or []),
                (flow_errors_detail or ''),
            )
        except Exception:
            pass
        flags_enabled = bool(flow_valid)

        try:
            persisted_flag_assignments = backend._flow_strip_runtime_sensitive_fields(out_assignments)
            flow_meta = {
                'source_preview_plan_path': backend._abs_path_or_original(base_plan_path),
                'scenario': scenario_label or scenario_norm,
                'length': len(chain_nodes),
                'requested_length': len(chain_nodes),
                'allow_node_duplicates': bool(allow_node_duplicates),
                'chain': [
                    {'id': str(node.get('id') or ''), 'name': str(node.get('name') or ''), 'type': str(node.get('type') or '')}
                    for node in chain_nodes
                ],
                'flag_assignments': persisted_flag_assignments,
                'flags_enabled': bool(flags_enabled),
                'flow_valid': bool(flow_valid),
                'flow_errors': list(flow_errors or []),
                'modified_at': backend._iso_now(),
            }
            if initial_facts_override:
                flow_meta['initial_facts'] = initial_facts_override
            if goal_facts_override:
                flow_meta['goal_facts'] = goal_facts_override
            if isinstance(meta, dict):
                meta2 = dict(meta)
                meta2['flow'] = flow_meta
            else:
                meta2 = {'flow': flow_meta}
        except Exception:
            meta2 = meta

        try:
            if isinstance(meta2, dict):
                meta2 = dict(meta2)
                meta2['updated_at'] = backend._iso_now()
            out_path = ''
            xml_target = backend._abs_path_or_original(str((meta2 or {}).get('xml_path') or '').strip())
            if not xml_target:
                xml_target = backend._abs_path_or_original(base_plan_path)
            if (not xml_target) or (not backend.os.path.exists(xml_target)):
                xml_target = backend._abs_path_or_original(backend._latest_xml_path_for_scenario(scenario_norm) or '')
            if not xml_target or not backend.os.path.exists(xml_target):
                return jsonify({'ok': False, 'error': 'Failed to persist flow-modified preview plan: XML path not found.'}), 500
            if isinstance(meta2, dict):
                meta2['xml_path'] = xml_target
            snap_before = backend._xml_trace_snapshot(xml_target, scenario_label or scenario_norm)
            out_payload = {'full_preview': preview, 'metadata': meta2}
            ok, err = backend._update_plan_preview_in_xml(xml_target, scenario_label or scenario_norm, out_payload)
            if not ok:
                return jsonify({'ok': False, 'error': f'Failed to persist flow-modified preview plan: {err}'}), 500
            try:
                backend._update_flow_state_in_xml(xml_target, scenario_label or scenario_norm, flow_meta)
            except Exception:
                pass
            out_path = xml_target
            try:
                backend._planner_set_plan(scenario_norm, plan_path=xml_target, xml_path=xml_target, seed=(meta2 or {}).get('seed'))
            except Exception:
                pass
            try:
                snap_after = backend._xml_trace_snapshot(xml_target, scenario_label or scenario_norm)
                app.logger.info(
                    '[flow.save_flow_substitutions.persist] scenario=%s before=%s after=%s',
                    scenario_norm,
                    snap_before,
                    snap_after,
                )
            except Exception:
                pass
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed to persist flow-modified preview plan: {exc}'}), 500

        try:
            stats = backend._flow_compose_docker_stats(nodes)
        except Exception:
            stats = {}

        host_ip_map: dict[str, str] = {}
        try:
            hosts = preview.get('hosts') if isinstance(preview, dict) else None
            if isinstance(hosts, list):
                for host in hosts:
                    if not isinstance(host, dict):
                        continue
                    host_id = str(host.get('node_id') or host.get('id') or '').strip()
                    if not host_id:
                        continue
                    ip_value = backend._preview_host_ip4_any(host)
                    if ip_value:
                        host_ip_map[host_id] = ip_value
        except Exception:
            host_ip_map = {}

        return jsonify(
            {
                'ok': True,
                'scenario': scenario_label or scenario_norm,
                'length': len(chain_nodes),
                'stats': stats,
                'chain': [
                    {
                        'id': str(node.get('id') or ''),
                        'name': str(node.get('name') or ''),
                        'type': str(node.get('type') or ''),
                        'is_vuln': bool(node.get('is_vuln')),
                        'ip4': str(node.get('ip4') or ''),
                        'ipv4': str(node.get('ipv4') or ''),
                        'interfaces': list(node.get('interfaces') or []) if isinstance(node.get('interfaces'), list) else [],
                    }
                    for node in chain_nodes
                ],
                'flag_assignments': out_assignments,
                'flags_enabled': bool(flags_enabled),
                'flow_valid': bool(flow_valid),
                'flow_errors': list(flow_errors or []),
                **({'flow_errors_detail': flow_errors_detail} if flow_errors_detail else {}),
                **({'host_ip_map': host_ip_map} if host_ip_map else {}),
                'preview_plan_path': backend._abs_path_or_original(out_path),
                'base_preview_plan_path': backend._abs_path_or_original(base_plan_path),
                'allow_node_duplicates': bool(allow_node_duplicates),
                **({'warning': warning} if warning else {}),
                **({'initial_facts': initial_facts_override} if initial_facts_override else {}),
                **({'goal_facts': goal_facts_override} if goal_facts_override else {}),
            }
        )

    mark_routes_registered(app, 'flag_sequencing_substitutions_routes')
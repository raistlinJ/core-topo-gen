from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_candidates_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/substitution_candidates', methods=['POST'])
    def api_flow_substitution_candidates():
        """Return candidate generators with per-position compatibility info."""
        payload = request.get_json(silent=True) or {}
        scenario_label = str(payload.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        index_raw = payload.get('index')
        try:
            index = int(index_raw)
        except Exception:
            return jsonify({'ok': False, 'error': 'Invalid index.'}), 400
        if index < 0:
            return jsonify({'ok': False, 'error': 'Invalid index.'}), 400

        chain_ids_in = payload.get('chain_ids')
        if not isinstance(chain_ids_in, list) or not chain_ids_in:
            return jsonify({'ok': False, 'error': 'Missing chain_ids.'}), 400
        chain_ids: list[str] = [str(item or '').strip() for item in chain_ids_in if str(item or '').strip()]
        if not chain_ids:
            return jsonify({'ok': False, 'error': 'Missing chain_ids.'}), 400
        if index >= len(chain_ids):
            return jsonify({'ok': False, 'error': 'Index out of range.'}), 400

        kind = str(payload.get('kind') or 'flag-generator').strip() or 'flag-generator'
        if kind not in {'flag-generator', 'flag-node-generator'}:
            kind = 'flag-generator'

        allow_node_duplicates = False
        try:
            allow_node_duplicates = str(payload.get('allow_node_duplicates') or '').strip().lower() in {
                '1', 'true', 't', 'yes', 'y', 'on'
            }
        except Exception:
            allow_node_duplicates = False

        base_plan_path = str(payload.get('preview_plan') or '').strip() or None
        if base_plan_path:
            base_plan_path = backend._existing_xml_path_or_none(base_plan_path)
        if not base_plan_path:
            base_plan_path = backend._latest_preview_plan_for_scenario_norm(scenario_norm, prefer_flow=True)
        if not base_plan_path or not backend.os.path.exists(base_plan_path):
            return jsonify({'ok': False, 'error': 'No preview plan found for this scenario. Generate a Full Preview first.'}), 404

        try:
            preview_payload = backend._load_preview_payload_from_path(base_plan_path, scenario_norm)
            if not isinstance(preview_payload, dict):
                return jsonify({'ok': False, 'error': 'Preview plan not embedded in XML. Save XML with Preview first.'}), 404
            preview = preview_payload.get('full_preview') if isinstance(preview_payload, dict) else None
            if not isinstance(preview, dict):
                return jsonify({'ok': False, 'error': 'Preview plan is missing full_preview.'}), 422
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed to load preview plan: {exc}'}), 500

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
        is_vuln_node = bool((chain_nodes[index] if index < len(chain_nodes) else {}).get('is_vuln'))
        if is_vuln_node:
            kind = 'flag-generator'

        def _node_is_docker_role(node: dict[str, Any]) -> bool:
            try:
                type_raw = str(node.get('type') or '')
                type_value = type_raw.strip().lower()
                return ('docker' in type_value) or (type_raw.strip().upper() == 'DOCKER') or bool(backend._flow_node_is_docker_role(node))
            except Exception:
                try:
                    return bool(backend._flow_node_is_docker_role(node))
                except Exception:
                    return False

        def _node_compatible_for_kind(node: dict[str, Any], desired_kind: str) -> tuple[bool, list[str]]:
            reasons: list[str] = []
            try:
                is_vuln = bool(node.get('is_vuln'))
                is_docker = _node_is_docker_role(node)
                if desired_kind == 'flag-node-generator':
                    if not is_docker:
                        reasons.append('requires docker-role node')
                    if is_vuln:
                        reasons.append('requires non-vulnerability node')
                    return (bool(is_docker) and (not is_vuln)), reasons
                if not is_vuln:
                    reasons.append('requires vulnerability node')
                    return False, reasons
                return True, []
            except Exception:
                return False, ['compatibility check failed']

        node_candidates: list[dict[str, Any]] = []
        try:
            current_node = chain_nodes[index] if index < len(chain_nodes) else None
            current_id = str((current_node or {}).get('id') or '').strip() if isinstance(current_node, dict) else ''
            used: set[str] = set()
            if not allow_node_duplicates:
                used = {str(chain_id).strip() for chain_id in (chain_ids or []) if str(chain_id).strip()}
                if current_id and current_id in used:
                    used.remove(current_id)

            desired_kind = kind
            if isinstance(current_node, dict) and bool(current_node.get('is_vuln')):
                desired_kind = 'flag-generator'

            if isinstance(current_node, dict) and current_id:
                compatible, blocked = _node_compatible_for_kind(current_node, desired_kind)
                node_candidates.append(
                    {
                        'id': current_id,
                        'name': str(current_node.get('name') or '').strip(),
                        'type': str(current_node.get('type') or '').strip(),
                        'is_vuln': bool(current_node.get('is_vuln')),
                        'is_docker': bool(_node_is_docker_role(current_node)),
                        'compatible': bool(compatible),
                        'blocked_by': blocked,
                        'current': True,
                    }
                )

            for node in (nodes or []):
                if not isinstance(node, dict):
                    continue
                node_id = str(node.get('id') or '').strip()
                if not node_id or node_id in used:
                    continue
                compatible, blocked = _node_compatible_for_kind(node, desired_kind)
                if not compatible:
                    continue
                node_candidates.append(
                    {
                        'id': node_id,
                        'name': str(node.get('name') or '').strip(),
                        'type': str(node.get('type') or '').strip(),
                        'is_vuln': bool(node.get('is_vuln')),
                        'is_docker': bool(_node_is_docker_role(node)),
                        'compatible': True,
                        'blocked_by': [],
                        'current': False,
                    }
                )

            def _node_sort_key(entry: dict[str, Any]) -> tuple[int, str, str]:
                return (
                    0 if bool(entry.get('current')) else 1,
                    str(entry.get('name') or '').lower(),
                    str(entry.get('id') or ''),
                )

            node_candidates.sort(key=_node_sort_key)
        except Exception:
            node_candidates = []

        flag_assignments_in = payload.get('flag_assignments')
        if not isinstance(flag_assignments_in, list) or len(flag_assignments_in) != len(chain_nodes):
            return jsonify({'ok': False, 'error': 'flag_assignments must be a list aligned to chain_ids (same length).'}), 400
        try:
            from core_topo_gen.utils.flow_substitution import flow_assignment_ids_by_position

            current_ids_by_position = flow_assignment_ids_by_position(flag_assignments_in)
        except Exception:
            current_ids_by_position = ['' for _ in range(len(chain_ids))]
            for position in range(len(chain_ids)):
                request_entry = flag_assignments_in[position] if position < len(flag_assignments_in) else {}
                if not isinstance(request_entry, dict):
                    continue
                generator_id = str(request_entry.get('id') or request_entry.get('generator_id') or '').strip()
                if generator_id:
                    current_ids_by_position[position] = generator_id

        candidate_ids_in = payload.get('candidate_ids')
        candidate_ids: list[str] = []
        if isinstance(candidate_ids_in, list) and candidate_ids_in:
            for item in candidate_ids_in:
                candidate_id = str(item or '').strip()
                if candidate_id:
                    candidate_ids.append(candidate_id)
        candidate_ids = list(dict.fromkeys(candidate_ids))

        try:
            generators, _ = backend._flag_generators_from_enabled_sources()
        except Exception:
            generators = []
        try:
            node_generators, _ = backend._flag_node_generators_from_enabled_sources()
        except Exception:
            node_generators = []

        generator_by_id: dict[str, dict[str, Any]] = {}
        for generator in (generators or []):
            if not isinstance(generator, dict):
                continue
            generator_id = str(generator.get('id') or '').strip()
            if generator_id and generator_id not in generator_by_id:
                generator_copy = dict(generator)
                generator_copy['_flow_kind'] = 'flag-generator'
                generator_by_id[generator_id] = generator_copy
        for generator in (node_generators or []):
            if not isinstance(generator, dict):
                continue
            generator_id = str(generator.get('id') or '').strip()
            if generator_id and generator_id not in generator_by_id:
                generator_copy = dict(generator)
                generator_copy['_flow_kind'] = 'flag-node-generator'
                generator_by_id[generator_id] = generator_copy

        try:
            plugins_by_id = backend._flow_enabled_plugin_contracts_by_id()
        except Exception:
            plugins_by_id = {}

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
            output_fields: set[str] = set()
            try:
                outputs = generator.get('outputs')
                if isinstance(outputs, list):
                    for output_item in outputs:
                        if not isinstance(output_item, dict):
                            continue
                        name = str(output_item.get('name') or '').strip()
                        if name:
                            output_fields.add(name)
            except Exception:
                pass
            try:
                output_fields |= _artifact_produces_of(generator)
            except Exception:
                pass
            return output_fields

        synthesized_fields = {
            'seed',
            'secret',
            'env_name',
            'challenge',
            'flag_prefix',
            'username_prefix',
            'key_len',
            'node_name',
        }
        have_artifacts: set[str] = set()
        have_fields: set[str] = set(synthesized_fields)

        for position in range(0, max(0, index)):
            generator_id = current_ids_by_position[position] if position < len(current_ids_by_position) else ''
            if not generator_id:
                continue
            generator = generator_by_id.get(generator_id)
            if not isinstance(generator, dict):
                continue
            try:
                have_artifacts |= _artifact_produces_of(generator)
            except Exception:
                pass
            try:
                have_fields |= _output_fields_of(generator)
            except Exception:
                pass

        def _blocked_reasons(generator: dict[str, Any]) -> tuple[bool, list[str]]:
            reasons: list[str] = []
            try:
                generator_kind = str(generator.get('_flow_kind') or '').strip() or 'flag-generator'
                if is_vuln_node and generator_kind != 'flag-generator':
                    reasons.append('Flag-Generator type')
            except Exception:
                pass
            required_artifacts = sorted([value for value in _artifact_requires_of(generator) if value])
            required_fields = sorted([value for value in _required_input_fields_of(generator) if value])

            try:
                all_inputs = _all_input_fields_of(generator)
                required_inputs = _required_input_fields_of(generator)
                optional_inputs = set(all_inputs) - set(required_inputs)
            except Exception:
                optional_inputs = set()
            effective_required_artifacts = [value for value in required_artifacts if value not in optional_inputs]

            missing_artifacts = [value for value in effective_required_artifacts if value not in have_artifacts]
            missing_fields = [value for value in required_fields if value not in have_fields and value not in synthesized_fields]
            if missing_artifacts:
                reasons.append('missing inputs (artifacts): ' + ', '.join(missing_artifacts))
            if missing_fields:
                reasons.append('missing inputs (fields): ' + ', '.join(missing_fields))
            return (len(reasons) == 0), reasons

        candidates: list[dict[str, Any]] = []
        ids_to_evaluate = candidate_ids if candidate_ids else list(generator_by_id.keys())
        for generator_id in ids_to_evaluate:
            generator = generator_by_id.get(str(generator_id))
            if not isinstance(generator, dict):
                continue
            generator_kind = str(generator.get('_flow_kind') or '').strip() or 'flag-generator'
            if generator_kind != kind:
                continue
            compatible, reasons = _blocked_reasons(generator)
            candidates.append(
                {
                    'id': str(generator.get('id') or ''),
                    'name': str(generator.get('name') or ''),
                    'type': generator_kind,
                    'source': str(generator.get('_source_name') or '').strip() or 'unknown',
                    'compatible': bool(compatible),
                    'blocked_by': reasons,
                }
            )

        candidates.sort(
            key=lambda entry: (
                0 if bool(entry.get('compatible')) else 1,
                str(entry.get('name') or '').lower(),
                str(entry.get('id') or ''),
            )
        )

        return jsonify(
            {
                'ok': True,
                'scenario': scenario_label or scenario_norm,
                'kind': kind,
                'index': index,
                'is_vuln': bool(is_vuln_node),
                'candidates': candidates,
                'node_candidates': node_candidates,
                'preview_plan_path': base_plan_path,
                'allow_node_duplicates': bool(allow_node_duplicates),
            }
        )

    mark_routes_registered(app, 'flag_sequencing_candidates_routes')
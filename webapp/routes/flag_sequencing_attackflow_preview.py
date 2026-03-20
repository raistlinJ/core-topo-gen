from __future__ import annotations

import os
from typing import Any
from typing import Optional

from flask import jsonify
from flask import request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_attackflow_preview_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/attackflow_preview')
    def api_flow_attackflow_preview():
        scenario_label = (request.args.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        preset = str(request.args.get('preset') or '').strip()
        mode = str(request.args.get('mode') or '').strip().lower()
        xml_hint = (request.args.get('xml_path') or '').strip()
        length_raw = request.args.get('length')
        try:
            length = int(length_raw) if length_raw is not None else 5
        except Exception:
            length = 5
        preset_steps = backend._flow_preset_steps(preset)
        if preset_steps:
            length = len(preset_steps)
        length = max(1, min(length, 50))
        requested_length = length

        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        prefer_preview = str(request.args.get('prefer_preview') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        force_preview = str(request.args.get('force_preview') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        prefer_flow = str(request.args.get('prefer_flow') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        best_effort_query = str(request.args.get('best_effort') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        allow_node_duplicates = str(request.args.get('allow_node_duplicates') or request.args.get('allow_duplicates') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        debug_mode = str(request.args.get('debug') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        ignore_saved_flow = bool(force_preview)
        selected_by = 'xml'

        preview_plan_path = (request.args.get('preview_plan') or '').strip() or None
        if preview_plan_path:
            try:
                preview_plan_path = os.path.abspath(preview_plan_path)
                if (not preview_plan_path.lower().endswith('.xml')) or (not os.path.exists(preview_plan_path)):
                    preview_plan_path = None
            except Exception:
                preview_plan_path = None

        if not preview_plan_path and xml_hint:
            try:
                xml_abs = os.path.abspath(xml_hint)
                if os.path.exists(xml_abs) and xml_abs.lower().endswith('.xml'):
                    payload_hint = backend._load_plan_preview_from_xml(xml_abs, scenario_norm)
                    if isinstance(payload_hint, dict):
                        meta_hint = payload_hint.get('metadata') if isinstance(payload_hint.get('metadata'), dict) else {}
                        scen_hint = str(meta_hint.get('scenario') or '').strip()
                        if (not scen_hint) or backend._normalize_scenario_label(scen_hint) == scenario_norm:
                            preview_plan_path = xml_abs
                            selected_by = 'xml_hint'
            except Exception:
                pass

        if not preview_plan_path:
            preview_plan_path = backend._latest_xml_path_for_scenario(scenario_norm)
            if preview_plan_path:
                selected_by = 'latest_xml'

        if not preview_plan_path:
            return jsonify({'ok': False, 'error': 'No XML found for this scenario. Save XML with a PlanPreview first.'}), 404

        payload = {}
        preview = None
        try:
            attempts = 0
            while attempts < 2:
                attempts += 1
                payload = backend._load_preview_payload_from_path(preview_plan_path, scenario_norm)
                if not isinstance(payload, dict):
                    return jsonify({'ok': False, 'error': 'Preview plan not embedded in XML.'}), 404
                meta_chk = payload.get('metadata') if isinstance(payload, dict) else None
                scen_chk = ''
                if isinstance(meta_chk, dict):
                    scen_chk = str(meta_chk.get('scenario') or '').strip()
                    flow_chk = meta_chk.get('flow') if isinstance(meta_chk.get('flow'), dict) else None
                    if not scen_chk and isinstance(flow_chk, dict):
                        scen_chk = str(flow_chk.get('scenario') or '').strip()
                scen_chk_norm = backend._normalize_scenario_label(scen_chk) if scen_chk else ''
                if scen_chk_norm and scen_chk_norm != scenario_norm:
                    preview_plan_path = backend._latest_preview_plan_for_scenario_norm_origin(scenario_norm, origin='planner')
                    if not preview_plan_path:
                        return jsonify({'ok': False, 'error': 'No preview plan found for this scenario. Generate a Full Preview first.'}), 404
                    continue
                break
            preview = payload.get('full_preview') if isinstance(payload, dict) else None
            if not isinstance(preview, dict):
                return jsonify({'ok': False, 'error': 'Preview plan is missing full_preview.'}), 422
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed to load preview plan: {exc}'}), 500

        def _docker_count_from_preview(full_preview: dict) -> int:
            try:
                hosts = full_preview.get('hosts') or []
            except Exception:
                hosts = []
            if not isinstance(hosts, list):
                return 0
            total = 0
            for host in hosts:
                if not isinstance(host, dict):
                    continue
                role = str(host.get('role') or '').strip().lower()
                if role == 'docker':
                    total += 1
            return total

        def _docker_count_from_editor_snapshot(snapshot: dict, scen_norm: str) -> int:
            try:
                scenarios = snapshot.get('scenarios') or []
            except Exception:
                scenarios = []
            if not isinstance(scenarios, list):
                return 0
            match = None
            for scen in scenarios:
                if not isinstance(scen, dict):
                    continue
                nm = backend._normalize_scenario_label(scen.get('name') or '')
                if nm and nm == scen_norm:
                    match = scen
                    break
            if not isinstance(match, dict):
                return 0
            section = (match.get('sections') or {}).get('Node Information')
            if not isinstance(section, dict):
                return 0
            items = section.get('items') or []
            if not isinstance(items, list):
                return 0
            total = 0
            for item in items:
                if not isinstance(item, dict):
                    continue
                metric = str(item.get('v_metric') or 'Weight').strip()
                if metric != 'Count':
                    continue
                sel = str(item.get('selected') or '').strip().lower()
                if sel != 'docker':
                    continue
                try:
                    total += max(0, int(item.get('v_count') or 0))
                except Exception:
                    continue
            return total

        def _plan_epoch_seconds(plan_path: str, plan_payload: dict) -> float:
            try:
                meta = plan_payload.get('metadata') if isinstance(plan_payload, dict) else None
                if isinstance(meta, dict):
                    ts = backend._parse_iso_ts(meta.get('created_at'))
                    if ts > 0:
                        return ts
            except Exception:
                pass
            try:
                return float(os.path.getmtime(plan_path))
            except Exception:
                return 0.0

        def _editor_snapshot_epoch_seconds(owner: Optional[dict]) -> float:
            try:
                snap_path = backend._editor_state_snapshot_path(owner)
                if os.path.exists(snap_path):
                    return float(os.path.getmtime(snap_path))
            except Exception:
                pass
            return 0.0

        try:
            backend._canonicalize_payload_flow_from_xml(
                payload,
                xml_path=preview_plan_path,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            pass

        nodes, _links, adj = backend._build_topology_graph_from_preview_plan(preview)
        stats = backend._flow_compose_docker_stats(nodes)

        runtime_ip_by_id: dict[str, str] = {}
        try:
            session_xml_path = backend._latest_session_xml_for_scenario_norm(scenario_norm)
        except Exception:
            session_xml_path = None
        try:
            if session_xml_path and os.path.exists(str(session_xml_path)):
                runtime_nodes, _runtime_links, _runtime_adj = backend._build_topology_graph_from_session_xml(str(session_xml_path))
                for runtime_node in (runtime_nodes or []):
                    if not isinstance(runtime_node, dict):
                        continue
                    rid = str(runtime_node.get('id') or runtime_node.get('node_id') or '').strip()
                    if not rid:
                        continue
                    rip = backend._first_valid_ipv4(
                        runtime_node.get('ip4') or runtime_node.get('ipv4') or runtime_node.get('ip') or runtime_node.get('ips') or runtime_node.get('ipv4s') or ''
                    )
                    if rip:
                        runtime_ip_by_id[rid] = rip
        except Exception:
            runtime_ip_by_id = {}

        chain_nodes: list[dict[str, Any]] = []
        used_saved_chain = False
        if (not ignore_saved_flow) and (not preset_steps):
            try:
                meta = payload.get('metadata') if isinstance(payload, dict) else None
                flow_meta = meta.get('flow') if isinstance(meta, dict) else None
                saved_chain = flow_meta.get('chain') if isinstance(flow_meta, dict) else None
                if (not isinstance(saved_chain, list)) or (not saved_chain):
                    chain_ids_xml = flow_meta.get('chain_ids') if isinstance(flow_meta, dict) else None
                    if isinstance(chain_ids_xml, list) and chain_ids_xml:
                        saved_chain = [{'id': str(x or '').strip()} for x in chain_ids_xml if str(x or '').strip()]
                saved_ids: list[str] = []
                if isinstance(saved_chain, list) and saved_chain:
                    for entry in saved_chain:
                        if not isinstance(entry, dict):
                            continue
                        cid = str(entry.get('id') or '').strip()
                        if cid:
                            saved_ids.append(cid)
                if saved_ids:
                    if (not allow_node_duplicates) and (len(set(saved_ids)) != len(saved_ids)):
                        saved_ids = []
                    id_map = {str(n.get('id') or '').strip(): n for n in (nodes or []) if isinstance(n, dict) and str(n.get('id') or '').strip()}
                    desired = saved_ids[:length]
                    chain_nodes = [id_map[cid] for cid in desired if cid in id_map]
                    if chain_nodes:
                        try:
                            for node in chain_nodes:
                                if not isinstance(node, dict):
                                    continue
                                t_raw = str(node.get('type') or '')
                                t = t_raw.strip().lower()
                                is_docker = ('docker' in t) or (t_raw.strip().upper() == 'DOCKER')
                                is_vuln = backend._flow_node_is_vuln(node)
                                if (not is_docker) and (not is_vuln):
                                    chain_nodes = []
                                    break
                        except Exception:
                            chain_nodes = []
                    if chain_nodes:
                        used_saved_chain = True
            except Exception:
                chain_nodes = []

        if not chain_nodes:
            if preset_steps:
                chain_nodes = backend._pick_flag_chain_nodes_for_preset(nodes, adj, steps=preset_steps)
            else:
                if allow_node_duplicates:
                    try:
                        seed_val = int((preview.get('seed') if isinstance(preview, dict) else None) or 0)
                    except Exception:
                        seed_val = 0
                    chain_nodes = backend._pick_flag_chain_nodes_allow_duplicates(nodes, adj, length=length, seed=seed_val)
                else:
                    chain_nodes = backend._pick_flag_chain_nodes(nodes, adj, length=length)

        warning: str | None = None
        if used_saved_chain:
            try:
                eff = len(chain_nodes)
                if eff > 0:
                    length = eff
            except Exception:
                pass
        if (not used_saved_chain) and (not preset_steps) and best_effort_query:
            try:
                available = len(chain_nodes)
            except Exception:
                available = 0
            if available > 0 and available < length:
                warning = f'Only {available} eligible nodes found; using chain length {available} instead of requested {length}.'
                length = available

        try:
            host_by_id: dict[str, dict[str, Any]] = {}
            hosts = preview.get('hosts') if isinstance(preview, dict) else None
            if isinstance(hosts, list):
                for host in hosts:
                    if not isinstance(host, dict):
                        continue
                    hid = str(host.get('node_id') or host.get('id') or '').strip()
                    if hid:
                        host_by_id[hid] = host
            if host_by_id:
                for node in (chain_nodes or []):
                    if not isinstance(node, dict):
                        continue
                    nid = str(node.get('id') or '').strip()
                    if not nid:
                        continue
                    host = host_by_id.get(nid)
                    if not isinstance(host, dict):
                        continue
                    try:
                        ip_val = runtime_ip_by_id.get(nid) or backend._preview_host_ip4_any(host)
                    except Exception:
                        ip_val = ''
                    if ip_val:
                        node['ip4'] = ip_val
                        node['ipv4'] = ip_val
                    try:
                        ifaces = host.get('interfaces') if isinstance(host.get('interfaces'), list) else None
                    except Exception:
                        ifaces = None
                    if ifaces and not node.get('interfaces'):
                        node['interfaces'] = ifaces
        except Exception:
            host_by_id = {}

        host_ip_map: dict[str, str] = {}
        try:
            for hid, host in (host_by_id or {}).items():
                ip_val = runtime_ip_by_id.get(str(hid)) or backend._preview_host_ip4_any(host)
                if ip_val:
                    host_ip_map[str(hid)] = ip_val
        except Exception:
            host_ip_map = {}

        flag_assignments: list[dict[str, Any]] = []
        flow_state_from_xml: dict[str, Any] | None = None
        try:
            if not ignore_saved_flow:
                flow_state_from_xml = backend._flow_state_from_xml_path(preview_plan_path, scenario_label or scenario_norm)
            if flow_state_from_xml and isinstance(flow_state_from_xml.get('chain_ids'), list):
                saved_ids = [str(x).strip() for x in (flow_state_from_xml.get('chain_ids') or []) if str(x).strip()]
                if saved_ids:
                    if (not allow_node_duplicates) and (len(set(saved_ids)) != len(saved_ids)):
                        saved_ids = []
                    id_map = {str(n.get('id') or '').strip(): n for n in (nodes or []) if isinstance(n, dict) and str(n.get('id') or '').strip()}
                    candidate_nodes = [id_map[cid] for cid in saved_ids if cid in id_map]
                    if candidate_nodes:
                        try:
                            invalid = any(
                                (not backend._flow_node_is_docker_role(node)) and (not backend._flow_node_is_vuln(node))
                                for node in candidate_nodes
                                if isinstance(node, dict)
                            )
                        except Exception:
                            invalid = True
                        if not invalid:
                            chain_nodes = candidate_nodes
                            fas = flow_state_from_xml.get('flag_assignments') if isinstance(flow_state_from_xml, dict) else None
                            if isinstance(fas, list) and fas:
                                ordered: list[dict[str, Any]] = []
                                for idx in range(len(chain_nodes)):
                                    assignment = fas[idx] if idx < len(fas) else {}
                                    if not isinstance(assignment, dict):
                                        ordered.append({})
                                        continue
                                    assignment_copy = dict(assignment)
                                    try:
                                        assignment_copy['node_id'] = str((chain_nodes[idx] or {}).get('id') or '').strip()
                                    except Exception:
                                        pass
                                    ordered.append(assignment_copy)
                                flag_assignments = ordered
                                try:
                                    flag_assignments = backend._flow_enrich_saved_flag_assignments(
                                        flag_assignments,
                                        chain_nodes,
                                        scenario_label=(scenario_label or scenario_norm),
                                    )
                                except Exception:
                                    pass
        except Exception:
            flow_state_from_xml = None
        try:
            pass
        except Exception:
            flag_assignments = []

        initial_facts_override: dict[str, list[str]] | None = None
        goal_facts_override: dict[str, list[str]] | None = None
        try:
            flow_for_facts = flow_state_from_xml if isinstance(flow_state_from_xml, dict) else None
            if isinstance(flow_for_facts, dict):
                initial_facts_override = backend._flow_normalize_fact_override(flow_for_facts.get('initial_facts'))
                goal_facts_override = backend._flow_normalize_fact_override(flow_for_facts.get('goal_facts'))
        except Exception:
            initial_facts_override = None
            goal_facts_override = None

        if not flag_assignments:
            if preset_steps and not used_saved_chain:
                preset_assignments, preset_err = backend._flow_compute_flag_assignments_for_preset(preview, chain_nodes, scenario_label or scenario_norm, preset)
                if preset_err:
                    return jsonify({'ok': False, 'error': f'Error: {preset_err}', 'stats': stats, 'preview_plan_path': preview_plan_path}), 422
                flag_assignments = preset_assignments
            else:
                flag_assignments = backend._flow_compute_flag_assignments(
                    preview,
                    chain_nodes,
                    scenario_label or scenario_norm,
                    initial_facts_override=initial_facts_override,
                    goal_facts_override=goal_facts_override,
                    disallow_generator_reuse=(not allow_node_duplicates),
                )
                if (not flag_assignments) and (not allow_node_duplicates):
                    flag_assignments = backend._flow_compute_flag_assignments(
                        preview,
                        chain_nodes,
                        scenario_label or scenario_norm,
                        initial_facts_override=initial_facts_override,
                        goal_facts_override=goal_facts_override,
                        disallow_generator_reuse=False,
                    )
                    if flag_assignments:
                        try:
                            warning = warning or 'Not enough unique generators for this chain length; generator reuse was enabled.'
                        except Exception:
                            pass

        if not flag_assignments and chain_nodes:
            try:
                gens_enabled, _ = backend._flag_generators_from_enabled_sources()
            except Exception:
                gens_enabled = []
            try:
                node_gens_enabled, _ = backend._flag_node_generators_from_enabled_sources()
            except Exception:
                node_gens_enabled = []
            try:
                gens_enabled = [g for g in (gens_enabled or []) if isinstance(g, dict) and str(g.get('id') or '').strip()]
                node_gens_enabled = [g for g in (node_gens_enabled or []) if isinstance(g, dict) and str(g.get('id') or '').strip()]
            except Exception:
                gens_enabled = []
                node_gens_enabled = []

            fallback: list[dict[str, Any]] = []
            if gens_enabled or node_gens_enabled:
                for node in (chain_nodes or []):
                    if not isinstance(node, dict):
                        continue
                    nid = str(node.get('id') or '').strip()
                    if not nid:
                        continue
                    is_vuln = backend._flow_node_is_vuln(node)
                    is_docker = backend._flow_node_is_docker_role(node)
                    if is_vuln and gens_enabled:
                        gen = gens_enabled[0]
                        fallback.append({
                            'node_id': nid,
                            'id': str(gen.get('id') or ''),
                            'name': str(gen.get('name') or ''),
                            'type': 'flag-generator',
                            'flag_generator': str(gen.get('_source_name') or gen.get('source') or '').strip() or 'unknown',
                            'generator_catalog': 'flag_generators',
                        })
                    elif (not is_vuln) and is_docker and node_gens_enabled:
                        gen = node_gens_enabled[0]
                        fallback.append({
                            'node_id': nid,
                            'id': str(gen.get('id') or ''),
                            'name': str(gen.get('name') or ''),
                            'type': 'flag-node-generator',
                            'flag_generator': str(gen.get('_source_name') or gen.get('source') or '').strip() or 'unknown',
                            'generator_catalog': 'flag_node_generators',
                        })
            if fallback and len(fallback) == len(chain_nodes):
                flag_assignments = fallback

        try:
            node_ids = [str(n.get('id') or '').strip() for n in (chain_nodes or []) if isinstance(n, dict) and str(n.get('id') or '').strip()]
            has_dupes = len(set(node_ids)) != len(node_ids)
        except Exception:
            has_dupes = False

        if (not used_saved_chain) and (not preset_steps) and (not has_dupes):
            debug_dag = str(request.args.get('debug_dag') or '').strip().lower() in ('1', 'true', 'yes', 'y')
            chain_nodes, flag_assignments, dag_debug = backend._flow_reorder_chain_by_generator_dag(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
                return_debug=bool(debug_dag),
            )
        else:
            debug_dag = str(request.args.get('debug_dag') or '').strip().lower() in ('1', 'true', 'yes', 'y')
            dag_debug = None

        try:
            if isinstance(flag_assignments, list) and isinstance(chain_nodes, list):
                desired_len = len(chain_nodes)
                if desired_len:
                    if len(flag_assignments) != desired_len:
                        flag_assignments = list(flag_assignments[:desired_len])
                        while len(flag_assignments) < desired_len:
                            flag_assignments.append({})
                    for idx in range(desired_len):
                        assignment = flag_assignments[idx]
                        if not isinstance(assignment, dict):
                            assignment = {}
                            flag_assignments[idx] = assignment
                        try:
                            nid = str((chain_nodes[idx] or {}).get('id') or '').strip()
                        except Exception:
                            nid = ''
                        if nid:
                            assignment.setdefault('node_id', nid)
        except Exception:
            pass

        try:
            for assignment in (flag_assignments or []):
                if not isinstance(assignment, dict):
                    continue
                existing = assignment.get('inject_files') if isinstance(assignment.get('inject_files'), list) else []
                if any(str(x or '').strip() for x in (existing or [])):
                    continue
                gid = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
                if not gid:
                    continue
                gen_def = backend._gen_by_id.get(gid) if isinstance(backend._gen_by_id, dict) else None
                if not isinstance(gen_def, dict):
                    continue
                inject_files = gen_def.get('inject_files')
                if isinstance(inject_files, list) and inject_files:
                    assignment['inject_files'] = [str(x or '').strip() for x in inject_files if str(x or '').strip()]
        except Exception:
            pass

        if not flag_assignments:
            flow_valid = False
            flow_errors = ['missing flag assignments']
            try:
                gens_enabled, _ = backend._flag_generators_from_enabled_sources()
            except Exception:
                gens_enabled = []
            try:
                node_gens_enabled, _ = backend._flag_node_generators_from_enabled_sources()
            except Exception:
                node_gens_enabled = []
            try:
                eligible_flag_gens = len([g for g in (gens_enabled or []) if isinstance(g, dict)])
            except Exception:
                eligible_flag_gens = 0
            try:
                eligible_node_gens = len([g for g in (node_gens_enabled or []) if isinstance(g, dict)])
            except Exception:
                eligible_node_gens = 0
            try:
                vuln_nodes = len([n for n in (chain_nodes or []) if isinstance(n, dict) and backend._flow_node_is_vuln(n)])
            except Exception:
                vuln_nodes = 0
            try:
                docker_nodes = len([n for n in (chain_nodes or []) if isinstance(n, dict) and backend._flow_node_is_docker_role(n)])
            except Exception:
                docker_nodes = 0
            flow_errors.extend([
                f'eligible_flag_generators={eligible_flag_gens}',
                f'eligible_flag_node_generators={eligible_node_gens}',
                f'chain_nodes={len(chain_nodes or [])}',
                f'chain_vuln_nodes={vuln_nodes}',
                f'chain_docker_nodes={docker_nodes}',
            ])
        else:
            flow_valid, flow_errors = backend._flow_validate_chain_order_by_requires_produces(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
            )
            try:
                assign_ids = [str(a.get('id') or a.get('generator_id') or '').strip() for a in (flag_assignments or []) if isinstance(a, dict)]
                chain_ids_dbg = [str(n.get('id') or '').strip() for n in (chain_nodes or []) if isinstance(n, dict) and str(n.get('id') or '').strip()]
                flow_errors_detail = (
                    f'assignments={len(flag_assignments or [])} '
                    f'assignments_with_id={len([x for x in assign_ids if x])} '
                    f'chain_nodes={len(chain_nodes or [])} '
                    f'chain_ids={",".join(chain_ids_dbg)}'
                )
            except Exception:
                flow_errors_detail = None

        try:
            gens_enabled, _ = backend._flag_generators_from_enabled_sources()
        except Exception:
            gens_enabled = []
        try:
            node_gens_enabled, _ = backend._flag_node_generators_from_enabled_sources()
        except Exception:
            node_gens_enabled = []
        enabled_ids: set[str] = set()
        for gen in (gens_enabled or []):
            if isinstance(gen, dict):
                gid = str(gen.get('id') or '').strip()
                if gid:
                    enabled_ids.add(gid)
        for gen in (node_gens_enabled or []):
            if isinstance(gen, dict):
                gid = str(gen.get('id') or '').strip()
                if gid:
                    enabled_ids.add(gid)

        missing_refs: list[str] = []
        try:
            for assignment in (flag_assignments or []):
                if not isinstance(assignment, dict):
                    continue
                gid = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
                if not gid:
                    continue
                if gid not in enabled_ids:
                    missing_refs.append(gid)
        except Exception:
            missing_refs = []

        missing_refs = sorted(list(dict.fromkeys(missing_refs)))
        if missing_refs:
            try:
                if not preset_steps:
                    flag_assignments = backend._flow_compute_flag_assignments(
                        preview,
                        chain_nodes,
                        scenario_label or scenario_norm,
                        initial_facts_override=initial_facts_override,
                        goal_facts_override=goal_facts_override,
                    )
                    missing_refs = []
                    try:
                        for assignment in (flag_assignments or []):
                            if not isinstance(assignment, dict):
                                continue
                            gid = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
                            if gid and gid not in enabled_ids:
                                missing_refs.append(gid)
                    except Exception:
                        missing_refs = []
                    missing_refs = sorted(list(dict.fromkeys(missing_refs)))
            except Exception:
                pass
        if missing_refs:
            flow_errors = list(flow_errors or []) + [f'generator not found/enabled: {gid}' for gid in missing_refs]
            flow_valid = False

        flags_enabled = bool(flow_valid)
        run_generators = bool(flags_enabled or (mode in {'resolve', 'resolve_hints', 'hint', 'hint_only'}))

        try:
            host_by_id = {}
            hosts = preview.get('hosts') if isinstance(preview, dict) else None
            if isinstance(hosts, list):
                for host in hosts:
                    if not isinstance(host, dict):
                        continue
                    hid = str(host.get('node_id') or '').strip()
                    if hid:
                        host_by_id[hid] = host
        except Exception:
            host_by_id = {}
        try:
            vuln_by_node = preview.get('vulnerabilities_by_node') if isinstance(preview, dict) else None
            if not isinstance(vuln_by_node, dict):
                vuln_by_node = {}
        except Exception:
            vuln_by_node = {}

        def _preview_host_ip4(host: dict) -> str:
            try:
                ip4 = host.get('ip4')
                if isinstance(ip4, str) and backend._first_valid_ipv4(ip4):
                    return backend._first_valid_ipv4(ip4)
            except Exception:
                pass
            for key in ('ipv4', 'ip', 'ip_addr', 'address'):
                try:
                    value = host.get(key)
                except Exception:
                    value = None
                ip_str = backend._first_valid_ipv4(value)
                if ip_str:
                    return ip_str
            try:
                for key in ('ips', 'addresses', 'ip4s', 'ipv4s'):
                    value = host.get(key)
                    ip_str = backend._first_valid_ipv4(value)
                    if ip_str:
                        return ip_str
            except Exception:
                pass
            try:
                ifaces = host.get('interfaces')
                if isinstance(ifaces, list):
                    for iface in ifaces:
                        if not isinstance(iface, dict):
                            continue
                        for key in ('ip4', 'ipv4', 'ip', 'ip_addr', 'address'):
                            ip_str = backend._first_valid_ipv4(iface.get(key))
                            if ip_str:
                                return ip_str
            except Exception:
                pass
            return ''

        try:
            for assignment in (flag_assignments or []):
                if not isinstance(assignment, dict):
                    continue
                nid = str(assignment.get('node_id') or '').strip()
                if not nid:
                    continue
                host = host_by_id.get(nid)
                preview_ip4 = runtime_ip_by_id.get(nid) or (_preview_host_ip4(host) if isinstance(host, dict) else '')
                if not preview_ip4:
                    try:
                        node = next((n for n in (chain_nodes or []) if isinstance(n, dict) and str(n.get('id') or '').strip() == nid), None)
                    except Exception:
                        node = None
                    if isinstance(node, dict):
                        preview_ip4 = backend._first_valid_ipv4(node.get('ip4') or node.get('ipv4') or node.get('ip') or '')
                if not preview_ip4:
                    continue
                resolved_inputs = assignment.get('resolved_inputs') if isinstance(assignment.get('resolved_inputs'), dict) else None
                if resolved_inputs is None:
                    resolved_inputs = {}
                    assignment['resolved_inputs'] = resolved_inputs
                resolved_inputs['Knowledge(ip)'] = preview_ip4
                resolved_inputs['target_ip'] = preview_ip4
                resolved_inputs['host_ip'] = preview_ip4
                resolved_inputs['ip4'] = preview_ip4
                resolved_inputs['ipv4'] = preview_ip4
        except Exception:
            pass

        if len(chain_nodes) < 1:
            return jsonify({'ok': False, 'error': 'No eligible nodes found in preview plan (vulnerability nodes only for flag-generators).', 'stats': stats, 'preview_plan_path': preview_plan_path}), 422
        if (not used_saved_chain) and (not allow_node_duplicates) and len(chain_nodes) < length:
            return jsonify({
                'ok': False,
                'error': f'Only {len(chain_nodes)} eligible nodes found for chain length {length}.',
                'available': len(chain_nodes),
                'stats': stats,
                'preview_plan_path': preview_plan_path,
            }), 422

        host_ip_map = {}
        try:
            for hid, host in (host_by_id or {}).items():
                ip_val = runtime_ip_by_id.get(str(hid)) or (_preview_host_ip4(host) if isinstance(host, dict) else '')
                if ip_val:
                    host_ip_map[str(hid)] = ip_val
        except Exception:
            host_ip_map = {}

        chain_out: list[dict[str, Any]] = []
        try:
            for node in (chain_nodes or []):
                if not isinstance(node, dict):
                    continue
                nid = str(node.get('id') or '').strip()
                host = host_by_id.get(nid) if nid else None
                ip_val = runtime_ip_by_id.get(nid) or (_preview_host_ip4(host) if isinstance(host, dict) else '')
                if not ip_val:
                    ip_val = backend._first_valid_ipv4(node.get('ip4') or node.get('ipv4') or node.get('ip') or '')
                ifaces = None
                try:
                    ifaces = host.get('interfaces') if isinstance(host, dict) and isinstance(host.get('interfaces'), list) else None
                except Exception:
                    ifaces = None
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
                if (not vulns) and nid:
                    try:
                        raw_v = vuln_by_node.get(nid)
                        if isinstance(raw_v, list):
                            vulns = [str(v).strip() for v in raw_v if str(v).strip()]
                    except Exception:
                        vulns = []
                is_vuln = bool(vulns) or bool(node.get('is_vuln')) or bool(node.get('is_vulnerability')) or bool(node.get('is_vulnerable'))
                chain_out.append({
                    'id': str(node.get('id') or ''),
                    'name': str(node.get('name') or ''),
                    'type': str(node.get('type') or ''),
                    'is_vuln': bool(is_vuln),
                    'vulnerabilities': list(vulns or []),
                    'ip4': str(ip_val or ''),
                    'ipv4': str(ip_val or ''),
                    'interfaces': list(ifaces or []) if isinstance(ifaces, list) else [],
                })
        except Exception:
            chain_out = [{'id': str(n.get('id') or ''), 'name': str(n.get('name') or ''), 'type': str(n.get('type') or ''), 'is_vuln': bool(n.get('is_vuln'))} for n in (chain_nodes or []) if isinstance(n, dict)]

        out = {
            'ok': True,
            'scenario': scenario_label or scenario_norm,
            'length': length,
            'requested_length': requested_length,
            'preview_plan_path': preview_plan_path,
            'chain': chain_out,
            'flag_assignments': flag_assignments,
            'stats': stats,
            'flow_valid': bool(flow_valid),
            'flow_errors': list(flow_errors or []),
            **({'flow_errors_detail': flow_errors_detail} if flow_errors_detail else {}),
            'flags_enabled': bool(flags_enabled),
            'allow_node_duplicates': bool(allow_node_duplicates),
            **({'host_ip_map': host_ip_map} if host_ip_map else {}),
        }
        if flow_errors_detail:
            out['flow_errors_detail'] = flow_errors_detail
        try:
            if not flow_valid:
                app.logger.warning('[flow.attackflow_preview] invalid flow: %s', (flow_errors_detail or (flow_errors or [])))
        except Exception:
            pass
        if initial_facts_override:
            out['initial_facts'] = initial_facts_override
        if goal_facts_override:
            out['goal_facts'] = goal_facts_override
        if warning:
            out['warning'] = warning
        if debug_mode:
            try:
                meta_dbg = payload.get('metadata') if isinstance(payload, dict) else None
            except Exception:
                meta_dbg = None
            out['debug'] = {
                'selected_by': selected_by,
                'prefer_preview': bool(prefer_preview),
                'force_preview': bool(force_preview),
                'ignore_saved_flow': bool(ignore_saved_flow),
                'used_saved_chain': bool(used_saved_chain),
                'preview_plan_path': preview_plan_path,
                'metadata': (meta_dbg if isinstance(meta_dbg, dict) else {}),
            }
        if debug_dag:
            out['sequencer_dag'] = dag_debug or {'ok': False, 'errors': ['not computed (saved chain)']}

        if (request.args.get('download') or '').strip() in {'1', 'true', 'yes'}:
            return jsonify({'ok': False, 'error': 'STIX bundle export has been removed. Use /api/flag-sequencing/afb_from_chain.'}), 410

        try:
            try:
                plan_basename = os.path.basename(str(preview_plan_path or ''))
            except Exception:
                plan_basename = str(preview_plan_path or '')
            try:
                preview_seed = (payload.get('metadata') or {}).get('seed') if isinstance(payload, dict) else None
            except Exception:
                preview_seed = None
            if preview_seed is None:
                try:
                    preview_seed = preview.get('seed') if isinstance(preview, dict) else None
                except Exception:
                    preview_seed = None
            app.logger.info(
                '[flow.attackflow_preview] scenario=%s chain_len=%s flow_valid=%s flow_errors=%s selected_by=%s plan=%s seed=%s',
                scenario_norm,
                len(chain_nodes or []),
                bool(flow_valid),
                (flow_errors or []),
                selected_by,
                plan_basename,
                preview_seed,
            )
        except Exception:
            pass

        return jsonify(out)

    mark_routes_registered(app, 'flag_sequencing_attackflow_preview_routes')
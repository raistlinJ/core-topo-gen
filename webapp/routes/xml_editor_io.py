from __future__ import annotations

import copy
import json
import os
import xml.etree.ElementTree as ET
from typing import Any, Callable

from flask import Response, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

try:
    from lxml import etree as LET  # type: ignore
except Exception:  # pragma: no cover
    LET = None  # type: ignore


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    allowed_file_func: Callable[[str], bool],
    parse_scenarios_xml: Callable[[str], dict[str, Any]],
    default_core_dict: Callable[[], dict[str, Any]],
    attach_base_upload: Callable[[dict[str, Any]], Any],
    hydrate_base_upload_from_disk: Callable[[dict[str, Any]], Any],
    enumerate_host_interfaces: Callable[[], list[dict[str, Any]]],
    save_base_upload_state: Callable[[dict[str, Any]], Any],
    prepare_payload_for_index: Callable[..., dict[str, Any]],
    persist_editor_state_snapshot: Callable[..., Any],
    load_editor_state_snapshot: Callable[..., dict[str, Any] | None],
    normalize_core_config: Callable[..., dict[str, Any]],
    normalize_scenario_names_strict: Callable[[list[Any]], Any],
    local_timestamp_safe: Callable[[], str],
    outputs_dir: Callable[[], str],
    sanitize_scenario_name_strict: Callable[[str, str], str],
    build_scenarios_xml: Callable[[dict[str, Any]], ET.ElementTree],
    persist_scenario_catalog: Callable[..., Any],
    ui_build_id: str,
    logger=None,
) -> None:
    """Register XML editor load/save/render routes extracted from app_backend."""

    log = logger or getattr(app, 'logger', None)

    def _concretize_scenarios_for_save(scenarios_payload: Any, *, seed: Any = None) -> list[Any]:
        from webapp import app_backend as backend

        return backend._concretize_scenarios_for_save(scenarios_payload, seed=seed)

    @app.route('/load_xml', methods=['POST'])
    def load_xml():
        user = current_user_getter()
        file = request.files.get('scenarios_xml')
        if not file or file.filename == '':
            flash('No file selected.')
            return redirect(url_for('index'))
        if not allowed_file_func(file.filename):
            flash('Invalid file type. Only XML allowed.')
            return redirect(url_for('index'))
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)
        try:
            payload = parse_scenarios_xml(filepath)
            if 'core' not in payload:
                payload['core'] = default_core_dict()
            payload['result_path'] = filepath
            attach_base_upload(payload)
            hydrate_base_upload_from_disk(payload)
            payload['host_interfaces'] = enumerate_host_interfaces()
            if payload.get('base_upload'):
                save_base_upload_state(payload['base_upload'])
            xml_text = ''
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    xml_text = f.read()
            except Exception:
                xml_text = ''
            payload = prepare_payload_for_index(payload, user=user)
            snapshot_source = dict(payload)
            snapshot_source['active_index'] = 0
            snapshot_source['project_key_hint'] = payload.get('result_path')
            persist_editor_state_snapshot(snapshot_source, user=user)
            snapshot = load_editor_state_snapshot(user)
            if snapshot:
                payload['editor_snapshot'] = snapshot
            return render_template('index.html', payload=payload, logs='', xml_preview=xml_text, ui_build_id=ui_build_id)
        except Exception as e:
            flash(f'Failed to parse XML: {e}')
            return redirect(url_for('index'))

    @app.route('/save_xml', methods=['POST'])
    def save_xml():
        data_str = request.form.get('scenarios_json')
        if not data_str:
            flash('No data received.')
            return redirect(url_for('index'))
        user = current_user_getter()
        try:
            data = json.loads(data_str)
        except Exception as e:
            flash(f'Invalid JSON: {e}')
            return redirect(url_for('index'))
        try:
            active_index = None
            try:
                active_index = int(data.get('active_index')) if 'active_index' in data else None
            except Exception:
                active_index = None
            core_meta = None
            try:
                core_str = request.form.get('core_json')
                if core_str:
                    core_meta = json.loads(core_str)
            except Exception:
                core_meta = None
            client_project_hint = (request.form.get('project_key_hint') or '').strip()
            client_scenario_query = (request.form.get('scenario_query') or '').strip()
            normalized_core = normalize_core_config(core_meta, include_password=True) if core_meta else None
            try:
                scenarios_list = data.get('scenarios') or []
                if isinstance(scenarios_list, list):
                    normalize_scenario_names_strict(scenarios_list)
                    scenarios_list = _concretize_scenarios_for_save(scenarios_list, seed=data.get('seed'))
                    data['scenarios'] = scenarios_list
            except Exception:
                pass
            scenario_count = len(data.get('scenarios') or []) if isinstance(data.get('scenarios'), list) else 0
            scenario_names_desc = []
            try:
                scenario_names_desc = [str((sc or {}).get('name') or '').strip() for sc in (data.get('scenarios') or []) if isinstance(sc, dict)]
            except Exception:
                scenario_names_desc = []
            username = (user or {}).get('username') if isinstance(user, dict) else None
            try:
                if log is not None:
                    log.info(
                        '[save_xml] user=%s scen_count=%s active_index=%s project_hint=%s scenario_query=%s names=%s',
                        username or 'anonymous',
                        scenario_count,
                        active_index if active_index is not None else 'none',
                        client_project_hint or '<none>',
                        client_scenario_query or '<none>',
                        ', '.join(name for name in scenario_names_desc if name) or '<unnamed>'
                    )
            except Exception:
                pass
            scenarios_list = data.get('scenarios') if isinstance(data.get('scenarios'), list) else []
            ts = local_timestamp_safe()
            out_dir = os.path.join(outputs_dir(), f'scenarios-{ts}')
            os.makedirs(out_dir, exist_ok=True)
            try:
                legacy_bundle = os.path.join(out_dir, 'scenarios.xml')
                if os.path.exists(legacy_bundle):
                    os.remove(legacy_bundle)
            except Exception:
                pass
            scenario_paths_map: dict[str, str] = {}
            active_out_path = None
            if scenarios_list:
                for idx, scen in enumerate(scenarios_list):
                    if not isinstance(scen, dict):
                        continue
                    raw_name = (scen.get('name') or '').strip()
                    display_name = sanitize_scenario_name_strict(raw_name, f'NewScenario{idx + 1}')
                    stem = secure_filename(display_name).strip('_-.') or f'Scenario_{idx + 1}'
                    out_path = os.path.join(out_dir, f'{stem}.xml')
                    if os.path.exists(out_path):
                        suffix = 2
                        base = stem
                        while os.path.exists(out_path):
                            stem = f'{base}-{suffix}'
                            out_path = os.path.join(out_dir, f'{stem}.xml')
                            suffix += 1
                    try:
                        tree = build_scenarios_xml({'scenarios': [scen], 'core': normalized_core})
                        raw = ET.tostring(tree.getroot(), encoding='utf-8')
                        if LET is not None:
                            lroot = LET.fromstring(raw)
                            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                            with open(out_path, 'wb') as f:
                                f.write(pretty)
                        else:
                            with open(out_path, 'wb') as f:
                                f.write(raw)
                    except Exception:
                        try:
                            tree = build_scenarios_xml({'scenarios': [scen], 'core': normalized_core})
                            tree.write(out_path, encoding='utf-8', xml_declaration=True)
                        except Exception:
                            continue
                    scenario_paths_map[display_name] = out_path
                    if active_index is not None and active_index == idx:
                        active_out_path = out_path
                if active_out_path is None and scenario_paths_map:
                    active_out_path = next(iter(scenario_paths_map.values()))
            else:
                out_path = None

            out_path = active_out_path
            try:
                if log is not None:
                    if scenario_paths_map:
                        log.info('[save_xml] wrote %s scenario xml files under %s', len(scenario_paths_map), out_dir)
                    else:
                        log.info('[save_xml] persisted empty scenario state with no xml output')
            except Exception:
                pass

            xml_text = ''
            if out_path:
                try:
                    with open(out_path, 'r', encoding='utf-8', errors='ignore') as f:
                        xml_text = f.read()
                except Exception:
                    xml_text = ''
            try:
                names_for_catalog = [name for name in scenario_names_desc if isinstance(name, str) and name.strip()]
                if names_for_catalog:
                    persist_scenario_catalog(names_for_catalog, source_path=scenario_paths_map or out_path)
            except Exception:
                pass
            if out_path:
                flash(f'Scenarios saved (per-scenario). Active XML: {os.path.basename(out_path)}')
            else:
                flash('Empty scenario state saved.')
            payload = {
                'scenarios': data.get('scenarios', []),
                'result_path': out_path,
                'core': normalize_core_config(normalized_core or {}, include_password=False) if normalized_core else default_core_dict(),
            }
            payload['host_interfaces'] = enumerate_host_interfaces()
            attach_base_upload(payload)
            hydrate_base_upload_from_disk(payload)
            if payload.get('base_upload'):
                save_base_upload_state(payload['base_upload'])
            payload = prepare_payload_for_index(payload, user=user)
            if client_project_hint:
                payload['project_key_hint'] = client_project_hint
            if client_scenario_query:
                payload['scenario_query'] = client_scenario_query
            snapshot_source = dict(payload)
            try:
                snapshot_source['scenarios'] = copy.deepcopy(data.get('scenarios') or [])
            except Exception:
                snapshot_source['scenarios'] = data.get('scenarios') or []
            snapshot_source['active_index'] = active_index
            if client_project_hint:
                snapshot_source['project_key_hint'] = client_project_hint
            elif payload.get('project_key_hint'):
                snapshot_source['project_key_hint'] = payload.get('project_key_hint')
            else:
                snapshot_source['project_key_hint'] = payload.get('result_path')
            if client_scenario_query:
                snapshot_source['scenario_query'] = client_scenario_query
            elif payload.get('scenario_query'):
                snapshot_source['scenario_query'] = payload.get('scenario_query')
            persist_editor_state_snapshot(snapshot_source, user=user)
            snapshot = load_editor_state_snapshot(user)
            if snapshot:
                payload['editor_snapshot'] = snapshot
            try:
                if log is not None:
                    log.info('[save_xml] success user=%s xml=%s scen_count=%s', username or 'anonymous', out_path, scenario_count)
            except Exception:
                pass
            return render_template('index.html', payload=payload, logs='', xml_preview=xml_text, ui_build_id=ui_build_id)
        except Exception as e:
            flash(f'Failed to save XML: {e}')
            return redirect(url_for('index'))

    @app.route('/save_xml_api', methods=['POST'])
    def save_xml_api():
        try:
            user = current_user_getter()
            data = request.get_json(silent=True) or {}
            scenarios = data.get('scenarios')
            clear_flow_preview = bool(data.get('clear_flow_preview'))
            core_meta = data.get('core')
            normalized_core = normalize_core_config(core_meta, include_password=True) if isinstance(core_meta, (dict, list)) or core_meta else None
            raw_project_hint = data.get('project_key_hint') if isinstance(data, dict) else None
            project_key_hint = raw_project_hint.strip() if isinstance(raw_project_hint, str) else ''
            raw_scenario_query = data.get('scenario_query') if isinstance(data, dict) else None
            scenario_query_hint = raw_scenario_query.strip() if isinstance(raw_scenario_query, str) else ''
            active_index = None
            try:
                active_index = int(data.get('active_index')) if 'active_index' in data else None
            except Exception:
                active_index = None

            def _norm_name(value: Any) -> str:
                try:
                    return ' '.join(str(value or '').strip().lower().split())
                except Exception:
                    return ''

            def _candidate_source_xml_paths(project_hint_path: str, scenario_name: str) -> list[str]:
                out: list[str] = []
                try:
                    p = str(project_hint_path or '').strip()
                    if p and os.path.isfile(p):
                        out.append(os.path.abspath(p))
                except Exception:
                    pass
                try:
                    p = str(project_hint_path or '').strip()
                    if p and os.path.exists(p):
                        base_dir = os.path.dirname(os.path.abspath(p))
                        stem = secure_filename(str(scenario_name or '').strip()).strip('_-.')
                        if stem:
                            candidate = os.path.join(base_dir, f'{stem}.xml')
                            if os.path.isfile(candidate):
                                out.append(os.path.abspath(candidate))
                        if os.path.isdir(base_dir):
                            target = _norm_name(scenario_name)
                            if target:
                                for name in os.listdir(base_dir):
                                    if not name.lower().endswith('.xml'):
                                        continue
                                    try:
                                        if _norm_name(os.path.splitext(name)[0]) == target:
                                            out.append(os.path.abspath(os.path.join(base_dir, name)))
                                    except Exception:
                                        continue
                except Exception:
                    pass
                # stable + de-dup
                uniq: list[str] = []
                seen: set[str] = set()
                for p in out:
                    if p in seen:
                        continue
                    seen.add(p)
                    uniq.append(p)
                return uniq

            def _has_meaningful_value(value: Any) -> bool:
                if value is None:
                    return False
                if isinstance(value, str):
                    return bool(value.strip())
                if isinstance(value, bool):
                    return value is True
                if isinstance(value, (int, float)):
                    return True
                if isinstance(value, list):
                    return len(value) > 0
                if isinstance(value, dict):
                    return any(_has_meaningful_value(v) for v in value.values())
                return False

            def _preserve_hitl_if_missing(scen: Any, project_hint_path: str, source_scen: Any = None) -> Any:
                if not isinstance(scen, dict):
                    return scen
                existing_hitl = scen.get('hitl') if isinstance(scen.get('hitl'), dict) else None

                def _merge_verified_hitl_fields(source_hitl: Any, incoming_hitl: Any) -> Any:
                    if not isinstance(source_hitl, dict):
                        return incoming_hitl
                    if not isinstance(incoming_hitl, dict):
                        return copy.deepcopy(source_hitl)

                    merged_hitl = copy.deepcopy(incoming_hitl)
                    source = copy.deepcopy(source_hitl)

                    try:
                        if bool(source.get('bridge_validated')) and not bool(merged_hitl.get('bridge_validated')):
                            merged_hitl['bridge_validated'] = True
                            if (not merged_hitl.get('bridge_validated_at')) and source.get('bridge_validated_at'):
                                merged_hitl['bridge_validated_at'] = source.get('bridge_validated_at')
                    except Exception:
                        pass

                    source_prox = source.get('proxmox') if isinstance(source.get('proxmox'), dict) else {}
                    merged_prox = merged_hitl.get('proxmox') if isinstance(merged_hitl.get('proxmox'), dict) else {}
                    merged_prox = dict(merged_prox)
                    try:
                        source_secret = str(source_prox.get('secret_id') or '').strip()
                        source_validated = bool(source_prox.get('validated'))
                        merged_secret = str(merged_prox.get('secret_id') or '').strip()
                        merged_validated = bool(merged_prox.get('validated'))
                        if source_validated and source_secret and (not merged_validated or not merged_secret):
                            merged_prox['secret_id'] = source_secret
                            merged_prox['validated'] = True
                            if (not merged_prox.get('last_validated_at')) and source_prox.get('last_validated_at'):
                                merged_prox['last_validated_at'] = source_prox.get('last_validated_at')
                        for key in ('url', 'port', 'verify_ssl', 'stored_at', 'last_message'):
                            if key not in merged_prox or merged_prox.get(key) in (None, ''):
                                if source_prox.get(key) not in (None, ''):
                                    merged_prox[key] = source_prox.get(key)
                    except Exception:
                        pass
                    if merged_prox:
                        merged_hitl['proxmox'] = merged_prox

                    source_core = source.get('core') if isinstance(source.get('core'), dict) else {}
                    merged_core = merged_hitl.get('core') if isinstance(merged_hitl.get('core'), dict) else {}
                    merged_core = dict(merged_core)
                    try:
                        source_core_secret = str(source_core.get('core_secret_id') or '').strip()
                        source_vm_key = str(source_core.get('vm_key') or '').strip()
                        source_validated = bool(source_core.get('validated'))
                        merged_core_secret = str(merged_core.get('core_secret_id') or '').strip()
                        merged_vm_key = str(merged_core.get('vm_key') or '').strip()
                        merged_validated = bool(merged_core.get('validated'))
                        if source_validated and source_core_secret and source_vm_key and (
                            (not merged_validated) or (not merged_core_secret) or (not merged_vm_key)
                        ):
                            merged_core['core_secret_id'] = source_core_secret
                            merged_core['vm_key'] = source_vm_key
                            merged_core['validated'] = True
                            if (not merged_core.get('last_validated_at')) and source_core.get('last_validated_at'):
                                merged_core['last_validated_at'] = source_core.get('last_validated_at')
                        for key in ('vm_name', 'vm_node', 'grpc_host', 'grpc_port', 'ssh_host', 'ssh_port', 'stored_at'):
                            if key not in merged_core or merged_core.get(key) in (None, ''):
                                if source_core.get(key) not in (None, ''):
                                    merged_core[key] = source_core.get(key)
                    except Exception:
                        pass
                    if merged_core:
                        merged_hitl['core'] = merged_core

                    return merged_hitl

                scenario_name = str(scen.get('name') or '').strip()
                target = _norm_name(scenario_name)
                if not target:
                    return scen

                # Fast path: if the parsed source scenario is already available, merge from it.
                try:
                    source_hitl = source_scen.get('hitl') if isinstance(source_scen, dict) else None
                    if isinstance(source_hitl, dict) and _has_meaningful_value(source_hitl):
                        out = dict(scen)
                        if isinstance(existing_hitl, dict) and _has_meaningful_value(existing_hitl):
                            out['hitl'] = _merge_verified_hitl_fields(source_hitl, existing_hitl)
                        else:
                            out['hitl'] = copy.deepcopy(source_hitl)
                        return out
                except Exception:
                    pass

                explicit_path = ''
                try:
                    explicit_path = str(scen.get('saved_xml_path') or '').strip()
                except Exception:
                    explicit_path = ''

                candidate_paths = []
                if explicit_path and os.path.isfile(explicit_path):
                    candidate_paths.append(os.path.abspath(explicit_path))
                candidate_paths.extend(_candidate_source_xml_paths(project_hint_path, scenario_name))

                seen: set[str] = set()
                deduped: list[str] = []
                for p in candidate_paths:
                    if not p or p in seen:
                        continue
                    seen.add(p)
                    deduped.append(p)

                for src in deduped:
                    try:
                        parsed = parse_scenarios_xml(src)
                        rows = parsed.get('scenarios') if isinstance(parsed, dict) else None
                        if isinstance(rows, list):
                            for row in rows:
                                if not isinstance(row, dict):
                                    continue
                                if _norm_name(row.get('name')) != target:
                                    continue
                                hitl = row.get('hitl') if isinstance(row.get('hitl'), dict) else None
                                if isinstance(hitl, dict) and _has_meaningful_value(hitl):
                                    out = dict(scen)
                                    if isinstance(existing_hitl, dict) and _has_meaningful_value(existing_hitl):
                                        out['hitl'] = _merge_verified_hitl_fields(hitl, existing_hitl)
                                        try:
                                            if log is not None:
                                                log.info('[save_xml_api] merged verified hitl fields for scenario=%s from source=%s', scenario_name, src)
                                        except Exception:
                                            pass
                                    else:
                                        out['hitl'] = copy.deepcopy(hitl)
                                        try:
                                            if log is not None:
                                                log.info('[save_xml_api] preserved hitl for scenario=%s from source=%s', scenario_name, src)
                                        except Exception:
                                            pass
                                    return out
                    except Exception:
                        pass

                    # Fallback for legacy/lowercase HITL tags not mapped by parser.
                    try:
                        tree = ET.parse(src)
                        root = tree.getroot()

                        def _lname(tag: Any) -> str:
                            try:
                                raw = str(tag or '')
                            except Exception:
                                raw = ''
                            if '}' in raw:
                                raw = raw.rsplit('}', 1)[-1]
                            return raw.strip().lower()

                        def _to_bool_if_known(key: str, value: Any) -> Any:
                            k = str(key or '').strip().lower()
                            if k in {'enabled', 'validated', 'verify_ssl', 'remember_credentials', 'ssh_enabled'}:
                                sval = str(value or '').strip().lower()
                                if sval in {'1', 'true', 'yes', 'on'}:
                                    return True
                                if sval in {'0', 'false', 'no', 'off'}:
                                    return False
                            return value

                        for scenario_el in list(root):
                            if _lname(getattr(scenario_el, 'tag', '')) != 'scenario':
                                continue
                            if _norm_name(scenario_el.get('name')) != target:
                                continue
                            editor = None
                            for child in list(scenario_el):
                                if _lname(getattr(child, 'tag', '')) == 'scenarioeditor':
                                    editor = child
                                    break
                            if editor is None:
                                continue
                            hitl_el = None
                            for child in list(editor):
                                if _lname(getattr(child, 'tag', '')) == 'hardwareinloop':
                                    hitl_el = child
                                    break
                            if hitl_el is None:
                                continue

                            hitl_dict: dict[str, Any] = {}
                            try:
                                enabled_raw = hitl_el.get('enabled')
                                if enabled_raw is not None:
                                    hitl_dict['enabled'] = _to_bool_if_known('enabled', enabled_raw)
                            except Exception:
                                pass

                            core_dict: dict[str, Any] = {}
                            prox_dict: dict[str, Any] = {}
                            for node in list(hitl_el):
                                node_name = _lname(getattr(node, 'tag', ''))
                                if node_name == 'coreconnection':
                                    for ak, av in dict(node.attrib or {}).items():
                                        core_dict[str(ak)] = _to_bool_if_known(str(ak), av)
                                elif node_name == 'proxmoxconnection':
                                    for ak, av in dict(node.attrib or {}).items():
                                        prox_dict[str(ak)] = _to_bool_if_known(str(ak), av)
                            if core_dict:
                                hitl_dict['core'] = core_dict
                            if prox_dict:
                                hitl_dict['proxmox'] = prox_dict

                            if _has_meaningful_value(hitl_dict):
                                out = dict(scen)
                                out['hitl'] = hitl_dict
                                try:
                                    if log is not None:
                                        log.info('[save_xml_api] preserved hitl (xml fallback) for scenario=%s from source=%s', scenario_name, src)
                                except Exception:
                                    pass
                                return out
                    except Exception:
                        continue
                return scen

            def _load_scenario_from_sources(scenario_name: str, project_hint_path: str) -> dict[str, Any] | None:
                target = _norm_name(scenario_name)
                if not target:
                    return None
                for src in _candidate_source_xml_paths(project_hint_path, scenario_name):
                    try:
                        parsed = parse_scenarios_xml(src)
                        rows = parsed.get('scenarios') if isinstance(parsed, dict) else None
                        if not isinstance(rows, list):
                            continue
                        for row in rows:
                            if not isinstance(row, dict):
                                continue
                            if _norm_name(row.get('name')) != target:
                                continue
                            return row
                    except Exception:
                        continue
                return None

            def _deep_merge_preserve_missing(source: Any, incoming: Any) -> Any:
                """Merge incoming over source while preserving fields missing in incoming.

                - Dicts merge recursively.
                - Lists/scalars replace when provided by incoming.
                - Missing keys in incoming stay untouched from source.
                """
                if isinstance(source, dict) and isinstance(incoming, dict):
                    merged: dict[str, Any] = copy.deepcopy(source)
                    for key, value in incoming.items():
                        if key in merged:
                            merged[key] = _deep_merge_preserve_missing(merged.get(key), value)
                        else:
                            merged[key] = copy.deepcopy(value)
                    return merged
                return copy.deepcopy(incoming)

            def _is_reduced_snapshot_payload(scen: Any) -> bool:
                """Detect reduced UI snapshots that should not clear section items."""
                if not isinstance(scen, dict):
                    return False
                sections = scen.get('sections') if isinstance(scen.get('sections'), dict) else None
                if not isinstance(sections, dict) or not sections:
                    return False

                has_summary_signal = False
                for key in ('scenario_total_nodes', 'base_nodes', 'combined_nodes', 'additional_nodes'):
                    try:
                        raw = scen.get(key)
                        if raw is not None and str(raw).strip() != '':
                            has_summary_signal = True
                            break
                    except Exception:
                        continue
                if not has_summary_signal:
                    return False

                for sec in sections.values():
                    if not isinstance(sec, dict):
                        continue
                    items = sec.get('items') if isinstance(sec.get('items'), list) else None
                    if isinstance(items, list) and len(items) > 0:
                        return False
                return True

            def _topology_signature(scen: Any) -> str:
                if not isinstance(scen, dict):
                    return ''
                sections = scen.get('sections') if isinstance(scen.get('sections'), dict) else {}
                if not isinstance(sections, dict):
                    sections = {}
                keys = (
                    'Node Information',
                    'Routing',
                    'Services',
                    'Traffic',
                    'Vulnerabilities',
                    'Segmentation',
                )
                picked: dict[str, Any] = {}
                for key in keys:
                    sec = sections.get(key)
                    if isinstance(sec, dict):
                        picked[key] = sec
                summary = {
                    'density_count': scen.get('density_count'),
                    'scenario_total_nodes': scen.get('scenario_total_nodes'),
                    'sections': picked,
                }
                try:
                    return json.dumps(summary, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
                except Exception:
                    return ''

            def _with_flow_state_dirty_if_topology_changed(scen: Any, src: Any) -> Any:
                if not isinstance(scen, dict):
                    return scen
                out = dict(scen)
                flow_state = out.get('flow_state') if isinstance(out.get('flow_state'), dict) else {}
                if not flow_state and isinstance(src, dict) and isinstance(src.get('flow_state'), dict):
                    flow_state = dict(src.get('flow_state') or {})
                if not isinstance(src, dict):
                    if flow_state:
                        out['flow_state'] = flow_state
                    return out
                try:
                    changed = _topology_signature(out) != _topology_signature(src)
                except Exception:
                    changed = False
                if changed:
                    flow_state = dict(flow_state or {})
                    # Topology/IP changes invalidate saved chain placement and resolved values.
                    # Keep the dirty marker but clear chain payload so Flag Sequencing starts clean.
                    flow_state['chain_ids'] = []
                    flow_state['length'] = 0
                    flow_state['flag_assignments'] = []
                    flow_state['flags_enabled'] = False
                    flow_state['topology_dirty'] = True
                    flow_state['topology_dirty_reason'] = 'topology_or_ip_changed'
                    flow_state['updated_at'] = local_timestamp_safe()
                    out['flow_state'] = flow_state
                elif flow_state:
                    out['flow_state'] = flow_state
                return out

            if not isinstance(scenarios, list):
                return jsonify({'ok': False, 'error': 'Invalid payload (scenarios list required)'}), 400

            source_by_norm: dict[str, dict[str, Any]] = {}
            if isinstance(scenarios, list):
                for scen in scenarios:
                    if not isinstance(scen, dict):
                        continue
                    name = str(scen.get('name') or '').strip()
                    norm = _norm_name(name)
                    if not norm or norm in source_by_norm:
                        continue
                    src = _load_scenario_from_sources(name, project_key_hint)
                    if isinstance(src, dict):
                        source_by_norm[norm] = src

            # Minimal patch semantics: merge incoming fields over source XML scenario.
            if isinstance(scenarios, list):
                merged_with_source: list[Any] = []
                for scen in scenarios:
                    if not isinstance(scen, dict):
                        merged_with_source.append(scen)
                        continue
                    norm = _norm_name(scen.get('name'))
                    src = source_by_norm.get(norm)
                    if isinstance(src, dict):
                        if _is_reduced_snapshot_payload(scen):
                            merged = dict(src)
                            for key, val in scen.items():
                                if key == 'sections':
                                    continue
                                merged[key] = val
                            merged_with_source.append(merged)
                        else:
                            merged_with_source.append(_deep_merge_preserve_missing(src, scen))
                    else:
                        merged_with_source.append(scen)
                scenarios = merged_with_source

            # If topology/IP-related fields changed compared to source XML, mark
            # FlowState as dirty so Flag Sequencing prompts a re-generate.
            if isinstance(scenarios, list):
                marked: list[Any] = []
                for scen in scenarios:
                    if not isinstance(scen, dict):
                        marked.append(scen)
                        continue
                    norm = _norm_name(scen.get('name'))
                    src = source_by_norm.get(norm)
                    marked.append(_with_flow_state_dirty_if_topology_changed(scen, src))
                scenarios = marked

            if isinstance(scenarios, list):
                preserved: list[Any] = []
                for scen in scenarios:
                    if not isinstance(scen, dict):
                        preserved.append(scen)
                        continue
                    norm = _norm_name(scen.get('name'))
                    preserved.append(_preserve_hitl_if_missing(scen, project_key_hint, source_scen=source_by_norm.get(norm)))
                scenarios = preserved

            if clear_flow_preview and isinstance(scenarios, list):
                cleaned: list[Any] = []
                for scen in scenarios:
                    if not isinstance(scen, dict):
                        cleaned.append(scen)
                        continue
                    scen2 = dict(scen)
                    for key in ('flow_state', 'plan_preview', 'full_preview', 'fullPreview', 'preview'):
                        try:
                            scen2.pop(key, None)
                        except Exception:
                            pass
                    cleaned.append(scen2)
                scenarios = cleaned
            try:
                normalize_scenario_names_strict(scenarios)
                scenarios = _concretize_scenarios_for_save(scenarios, seed=data.get('seed'))
            except Exception:
                pass
            scenario_names: list[str] = []
            try:
                scenario_names = [str((s or {}).get('name') or '').strip() for s in scenarios if isinstance(s, dict)]
            except Exception:
                scenario_names = []
            username = (user or {}).get('username') if isinstance(user, dict) else None
            try:
                if log is not None:
                    log.info(
                        '[save_xml_api] user=%s scen_count=%s active_index=%s project_hint=%s scenario_query=%s names=%s',
                        username or 'anonymous',
                        len(scenarios),
                        active_index if active_index is not None else 'none',
                        project_key_hint or '<none>',
                        scenario_query_hint or '<none>',
                        ', '.join(name for name in scenario_names if name) or '<unnamed>'
                    )
            except Exception:
                pass
            ts = local_timestamp_safe()
            out_dir = os.path.join(outputs_dir(), f'scenarios-{ts}')
            os.makedirs(out_dir, exist_ok=True)
            try:
                legacy_bundle = os.path.join(out_dir, 'scenarios.xml')
                if os.path.exists(legacy_bundle):
                    os.remove(legacy_bundle)
            except Exception:
                pass
            scenario_paths_map: dict[str, str] = {}
            scenario_paths_by_index: list[str | None] = []
            active_out_path = None
            if scenarios:
                for idx, scen in enumerate(scenarios):
                    if not isinstance(scen, dict):
                        scenario_paths_by_index.append(None)
                        continue
                    raw_name = (scen.get('name') or '').strip()
                    display_name = sanitize_scenario_name_strict(raw_name, f'NewScenario{idx + 1}')
                    stem_raw = display_name
                    stem = secure_filename(stem_raw).strip('_-.') or f'NewScenario{idx + 1}'
                    out_path = os.path.join(out_dir, f'{stem}.xml')
                    if os.path.exists(out_path):
                        suffix = 2
                        base = stem
                        while os.path.exists(out_path):
                            stem = f'{base}-{suffix}'
                            out_path = os.path.join(out_dir, f'{stem}.xml')
                            suffix += 1
                    try:
                        tree = build_scenarios_xml({'scenarios': [scen], 'core': normalized_core})
                        raw = ET.tostring(tree.getroot(), encoding='utf-8')
                        if LET is not None:
                            lroot = LET.fromstring(raw)
                            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                            with open(out_path, 'wb') as f:
                                f.write(pretty)
                        else:
                            with open(out_path, 'wb') as f:
                                f.write(raw)
                    except Exception:
                        try:
                            tree = build_scenarios_xml({'scenarios': [scen], 'core': normalized_core})
                            tree.write(out_path, encoding='utf-8', xml_declaration=True)
                        except Exception:
                            continue
                    try:
                        parsed = ET.parse(out_path)
                        root = parsed.getroot()
                        scenario_count = len(root.findall('Scenario'))
                        if scenario_count != 1:
                            tree = build_scenarios_xml({'scenarios': [scen], 'core': normalized_core})
                            tree.write(out_path, encoding='utf-8', xml_declaration=True)
                    except Exception:
                        pass
                    scenario_paths_map[display_name] = out_path
                    scenario_paths_by_index.append(out_path)
                    if active_index is not None and active_index == idx:
                        active_out_path = out_path
                if active_out_path is None and scenario_paths_map:
                    active_out_path = next(iter(scenario_paths_map.values()))
            else:
                active_out_path = None
            out_path = active_out_path
            try:
                if log is not None:
                    if scenario_paths_map:
                        log.info('[save_xml_api] wrote %s scenario xml files under %s', len(scenario_paths_map), out_dir)
                    else:
                        log.info('[save_xml_api] persisted empty scenario state with no xml output')
            except Exception:
                pass
            resp_core = normalize_core_config(normalized_core or core_meta or {}, include_password=False) if (normalized_core or core_meta) else default_core_dict()
            snapshot_source = {
                'scenarios': scenarios,
                'core': resp_core,
                'result_path': out_path,
                'active_index': active_index,
                'project_key_hint': project_key_hint or out_path,
            }
            try:
                snapshot_source['saved_xml_paths_by_index'] = scenario_paths_by_index
            except Exception:
                pass
            if scenario_query_hint:
                snapshot_source['scenario_query'] = scenario_query_hint
            try:
                if active_index is not None and 0 <= active_index < len(scenarios):
                    active_name = str((scenarios[active_index] or {}).get('name') or '').strip()
                    if active_name:
                        snapshot_source['result_path_scenario'] = active_name
            except Exception:
                pass
            persist_editor_state_snapshot(snapshot_source, user=user)
            try:
                if log is not None:
                    log.info('[save_xml_api] success user=%s xml=%s scen_count=%s', username or 'anonymous', out_path, len(scenarios))
            except Exception:
                pass
            try:
                names_for_catalog = [name for name in scenario_names if isinstance(name, str) and name.strip()]
                if names_for_catalog:
                    persist_scenario_catalog(names_for_catalog, source_path=scenario_paths_map or out_path)
            except Exception:
                pass
            response_payload = {'ok': True, 'result_path': out_path, 'core': resp_core}
            if scenario_paths_map:
                response_payload['scenario_paths'] = scenario_paths_map
            response_payload['scenario_paths_by_index'] = scenario_paths_by_index
            if active_index is not None and 0 <= active_index < len(scenarios):
                try:
                    active_name = str((scenarios[active_index] or {}).get('name') or '').strip()
                except Exception:
                    active_name = ''
                if active_name:
                    response_payload['active_scenario'] = active_name
            return jsonify(response_payload)
        except Exception as e:
            try:
                if log is not None:
                    log.exception('[save_xml_api] failed: %s', e)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': str(e)}), 500

    @app.route('/render_xml_api', methods=['POST'])
    def render_xml_api():
        """Render scenario XML for preview without persisting to disk."""
        try:
            data = request.get_json(silent=True) or {}
            scenarios = data.get('scenarios')
            core_meta = data.get('core')
            normalized_core = normalize_core_config(core_meta, include_password=True) if isinstance(core_meta, (dict, list)) or core_meta else None
            if not isinstance(scenarios, list):
                return jsonify({'ok': False, 'error': 'Invalid payload (scenarios list required)'}), 400
            tree = build_scenarios_xml({'scenarios': scenarios, 'core': normalized_core})
            try:
                raw = ET.tostring(tree.getroot(), encoding='utf-8')
                if LET is not None:
                    lroot = LET.fromstring(raw)
                    pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                    return Response(pretty, mimetype='application/xml')
                out = ET.tostring(tree.getroot(), encoding='utf-8', xml_declaration=True)
                return Response(out, mimetype='application/xml')
            except Exception:
                out = ET.tostring(tree.getroot(), encoding='utf-8', xml_declaration=True)
                return Response(out, mimetype='application/xml')
        except Exception as e:
            try:
                if log is not None:
                    log.exception('[render_xml_api] failed: %s', e)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': str(e)}), 500

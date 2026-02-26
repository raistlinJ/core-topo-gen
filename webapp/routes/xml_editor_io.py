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
                flash('No scenarios to save.')
                return redirect(url_for('index'))

            out_path = active_out_path
            try:
                if log is not None:
                    log.info('[save_xml] wrote %s scenario xml files under %s', len(scenario_paths_map) or 1, out_dir)
            except Exception:
                pass

            xml_text = ''
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
                flash('Scenarios saved (per-scenario).')
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
            if not isinstance(scenarios, list):
                return jsonify({'ok': False, 'error': 'Invalid payload (scenarios list required)'}), 400
            try:
                normalize_scenario_names_strict(scenarios)
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
                return jsonify({'ok': False, 'error': 'No scenarios to save'}), 400
            out_path = active_out_path
            try:
                if log is not None:
                    log.info('[save_xml_api] wrote %s scenario xml files under %s', len(scenario_paths_map) or 1, out_dir)
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
                if scenario_paths_by_index:
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
            if scenario_paths_by_index:
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

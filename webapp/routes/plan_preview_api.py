from __future__ import annotations

import os
import uuid
from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'plan_preview_api_routes'):
        return

    backend = backend_module

    def _api_plan_preview_full():
        try:
            payload = request.get_json(silent=True) or {}
            xml_path = payload.get('xml_path')
            scenarios_inline = payload.get('scenarios')
            core_inline = payload.get('core')
            scenario = payload.get('scenario') or None
            seed = payload.get('seed')
            r2s_hosts_min_list = payload.get('r2s_hosts_min_list') or []
            r2s_hosts_max_list = payload.get('r2s_hosts_max_list') or []
            try:
                if seed is not None:
                    seed = int(seed)
            except Exception:
                seed = None
            if not xml_path:
                if isinstance(scenarios_inline, list):
                    try:
                        normalized_core = backend._normalize_core_config(core_inline, include_password=True) if isinstance(core_inline, dict) else None
                        tree = backend._build_scenarios_xml({'scenarios': scenarios_inline, 'core': normalized_core})
                        ts = backend._local_timestamp_safe()
                        tag = str(uuid.uuid4())[:8]
                        out_dir = os.path.join(backend._outputs_dir(), f'tmp-preview-{ts}-{tag}')
                        os.makedirs(out_dir, exist_ok=True)
                        stem_raw = scenario or None
                        if not stem_raw:
                            try:
                                first_name = None
                                for sc in scenarios_inline:
                                    if isinstance(sc, dict) and sc.get('name'):
                                        first_name = sc.get('name')
                                        break
                                stem_raw = first_name or 'scenarios'
                            except Exception:
                                stem_raw = 'scenarios'
                        stem = backend.secure_filename(str(stem_raw)).strip('_-.') or 'scenarios'
                        xml_path = os.path.join(out_dir, f'{stem}.xml')
                        try:
                            from lxml import etree as LET  # type: ignore

                            raw = backend.ET.tostring(tree.getroot(), encoding='utf-8')
                            lroot = LET.fromstring(raw)
                            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                            with open(xml_path, 'wb') as handle:
                                handle.write(pretty)
                        except Exception:
                            tree.write(xml_path, encoding='utf-8', xml_declaration=True)
                    except Exception as exc:
                        return jsonify({'ok': False, 'error': f'Failed to render XML for preview: {exc}'}), 400
                else:
                    return jsonify({'ok': False, 'error': 'xml_path missing'}), 400
            xml_path = os.path.abspath(xml_path)
            if not os.path.exists(xml_path):
                return jsonify({'ok': False, 'error': f'XML not found: {xml_path}'}), 404
            try:
                payload_from_xml = backend._load_preview_payload_from_path(xml_path, scenario)
                if isinstance(payload_from_xml, dict):
                    embedded_preview = payload_from_xml.get('full_preview') if isinstance(payload_from_xml.get('full_preview'), dict) else None
                    if isinstance(embedded_preview, dict):
                        flow_meta = None
                        try:
                            flow_meta = backend._flow_state_from_xml_path(xml_path, scenario)
                            if not isinstance(flow_meta, dict):
                                flow_meta = backend._attach_latest_flow_into_full_preview(embedded_preview, scenario)
                            elif isinstance(flow_meta, dict):
                                try:
                                    repaired = backend._flow_repair_saved_flow_for_preview(embedded_preview, flow_meta)
                                    if isinstance(repaired, dict):
                                        flow_meta = repaired
                                    else:
                                        flow_meta = None
                                except Exception:
                                    flow_meta = None
                        except Exception:
                            flow_meta = None
                        return jsonify({'ok': True, 'full_preview': embedded_preview, 'plan': {}, 'breakdowns': None, 'flow_meta': flow_meta or {}})
            except Exception:
                pass
            if seed is None:
                try:
                    existing_payload = backend._load_preview_payload_from_path(xml_path, scenario)
                    if isinstance(existing_payload, dict):
                        existing_meta = existing_payload.get('metadata') if isinstance(existing_payload.get('metadata'), dict) else {}
                        raw_seed = None
                        if isinstance(existing_meta, dict):
                            raw_seed = existing_meta.get('seed')
                        if raw_seed is None and isinstance(existing_payload.get('full_preview'), dict):
                            raw_seed = existing_payload.get('full_preview', {}).get('seed')
                        if raw_seed is not None:
                            seed = int(raw_seed)
                except Exception:
                    seed = None
            from core_topo_gen.planning.orchestrator import compute_full_plan
            from core_topo_gen.planning.plan_cache import hash_xml_file

            xml_hash = hash_xml_file(xml_path)
            plan = compute_full_plan(xml_path, scenario=scenario, seed=seed, include_breakdowns=True)
            if seed is None:
                seed = plan.get('seed') or backend._derive_default_seed(xml_hash)
            full_prev = backend._build_full_preview_from_plan(plan, seed, r2s_hosts_min_list, r2s_hosts_max_list)
            xml_basename = os.path.splitext(os.path.basename(xml_path))[0]
            try:
                raw_hitl_config = backend.parse_hitl_info(xml_path, scenario)
            except Exception as hitl_exc:
                try:
                    app.logger.debug('[plan.preview_full] hitl parse failed: %s', hitl_exc)
                except Exception:
                    pass
                raw_hitl_config = {'enabled': False, 'interfaces': []}
            hitl_config = backend._sanitize_hitl_config(raw_hitl_config, scenario, xml_basename)
            try:
                backend._apply_hitl_config_to_full_preview(full_prev, hitl_config, scenario)
            except Exception:
                pass
            flow_meta = None
            try:
                flow_meta = backend._flow_state_from_xml_path(xml_path, scenario)
                if not isinstance(flow_meta, dict):
                    flow_meta = backend._attach_latest_flow_into_full_preview(full_prev, scenario)
                elif isinstance(flow_meta, dict):
                    try:
                        repaired = backend._flow_repair_saved_flow_for_preview(full_prev, flow_meta)
                        if isinstance(repaired, dict):
                            flow_meta = repaired
                        else:
                            flow_meta = None
                    except Exception:
                        flow_meta = None
            except Exception:
                flow_meta = None
            return jsonify({'ok': True, 'full_preview': full_prev, 'plan': plan, 'breakdowns': plan.get('breakdowns'), 'flow_meta': flow_meta or {}})
        except Exception as exc:
            app.logger.exception('[plan.preview_full] error: %s', exc)
            return jsonify({'ok': False, 'error': str(exc)}), 500

    def _api_plan_persist_flow_plan():
        try:
            payload = request.get_json(silent=True) or {}
            xml_path = (payload.get('xml_path') or '').strip()
            scenario = (payload.get('scenario') or '').strip() or None
            seed = payload.get('seed')
            try:
                if seed is not None:
                    seed = int(seed)
            except Exception:
                seed = None

            if not xml_path:
                return jsonify({'ok': False, 'error': 'xml_path missing'}), 400

            result = backend._planner_persist_flow_plan(xml_path=xml_path, scenario=scenario, seed=seed)
            return jsonify(
                {
                    'ok': True,
                    'xml_path': result.get('xml_path'),
                    'scenario': result.get('scenario'),
                    'seed': result.get('seed'),
                    'preview_plan_path': result.get('preview_plan_path'),
                }
            )
        except Exception as exc:
            try:
                app.logger.exception('[plan.persist_flow_plan] error: %s', exc)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': str(exc)}), 500

    app.add_url_rule('/api/plan/preview_full', endpoint='api_plan_preview_full', view_func=_api_plan_preview_full, methods=['POST'])
    app.add_url_rule('/api/plan/persist_flow_plan', endpoint='api_plan_persist_flow_plan', view_func=_api_plan_persist_flow_plan, methods=['POST'])

    mark_routes_registered(app, 'plan_preview_api_routes')
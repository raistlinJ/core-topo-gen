from __future__ import annotations

import datetime
import os
import time
from typing import Any

from flask import Response, flash, redirect, render_template, request, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'plan_preview_pages_routes'):
        return

    backend = backend_module

    def _plan_full_preview_page():
        try:
            embed_raw = request.args.get('embed') or request.form.get('embed') or ''
            embed = str(embed_raw).strip().lower() in ['1', 'true', 'yes', 'y', 'on']
            xml_path = request.form.get('xml_path')
            scenario = request.form.get('scenario') or None
            force_raw = request.form.get('force') or request.form.get('force_recompute') or ''
            force_recompute = str(force_raw).strip().lower() in ['1', 'true', 'yes', 'y', 'on']
            seed_raw = request.form.get('seed') or ''
            seed = None
            try:
                if seed_raw:
                    seed_value = int(seed_raw)
                    if seed_value > 0:
                        seed = seed_value
            except Exception:
                seed = None
            try:
                xml_path_abs = os.path.abspath(xml_path) if xml_path else ''
            except Exception:
                xml_path_abs = ''
            if xml_path_abs and os.path.exists(xml_path_abs):
                plan_path = xml_path_abs
            else:
                plan_path = None
            try:
                scen_norm = backend._normalize_scenario_label(scenario or '')
            except Exception:
                scen_norm = ''
            if (not plan_path) and scen_norm:
                try:
                    plan_path = backend._latest_flow_plan_for_scenario_norm(scen_norm)
                except Exception:
                    plan_path = plan_path
            if plan_path:
                try:
                    payload = backend._load_preview_payload_from_path(plan_path, scenario)
                    if isinstance(payload, dict):
                        full_prev = payload.get('full_preview') if isinstance(payload, dict) else None
                        meta = payload.get('metadata') if isinstance(payload, dict) else None
                        if isinstance(full_prev, dict):
                            if not isinstance(meta, dict):
                                meta = {}
                            xml_path0 = backend._abs_path_or_original(str(meta.get('xml_path') or ''))
                            if (not xml_path0) and plan_path and str(plan_path).lower().endswith('.xml'):
                                xml_path0 = backend._abs_path_or_original(plan_path)
                            scenario0 = str(meta.get('scenario') or '') or (scenario or None)
                            seed0 = meta.get('seed')
                            try:
                                seed0 = int(seed0) if seed0 is not None else full_prev.get('seed')
                            except Exception:
                                seed0 = full_prev.get('seed')
                            try:
                                requested_seed = int(seed) if seed is not None else None
                            except Exception:
                                requested_seed = None
                            if requested_seed is not None:
                                try:
                                    current_seed = int(seed0) if seed0 is not None else None
                                except Exception:
                                    current_seed = None
                                if current_seed != requested_seed:
                                    try:
                                        xml_for_compute = backend._abs_path_or_original(xml_path0) or backend._abs_path_or_original(plan_path)
                                        from core_topo_gen.planning.orchestrator import compute_full_plan

                                        plan2 = compute_full_plan(xml_for_compute, scenario=scenario0, seed=requested_seed, include_breakdowns=True)
                                        full_prev = backend._build_full_preview_from_plan(plan2, requested_seed, [], [])
                                        seed0 = full_prev.get('seed')
                                    except Exception:
                                        pass

                        flow_meta = None
                        try:
                            xml_for_flow = xml_path0 or (plan_path if plan_path and str(plan_path).lower().endswith('.xml') else '')
                            if xml_for_flow:
                                flow_meta = backend._flow_state_from_xml_path(xml_for_flow, scenario0 or scenario)
                        except Exception:
                            flow_meta = None
                        if not isinstance(flow_meta, dict):
                            try:
                                meta_flow = meta.get('flow') if isinstance(meta, dict) else None
                                if isinstance(meta_flow, dict):
                                    flow_meta = meta_flow
                            except Exception:
                                flow_meta = None

                        display_artifacts = full_prev.get('display_artifacts')
                        if not display_artifacts:
                            try:
                                display_artifacts = backend._attach_display_artifacts(full_prev)
                            except Exception:
                                display_artifacts = {
                                    'segmentation': {
                                        'rows': [],
                                        'table_rows': [],
                                        'tableRows': [],
                                        'json': {'rules_count': 0, 'types_summary': {}, 'rules': [], 'metadata': None},
                                    },
                                    '__version': backend.FULL_PREVIEW_ARTIFACT_VERSION,
                                }
                        segmentation_artifacts = (display_artifacts or {}).get('segmentation')

                        hitl_config = {
                            'enabled': bool(full_prev.get('hitl_enabled')),
                            'interfaces': full_prev.get('hitl_interfaces') or [],
                            'scenario_key': full_prev.get('hitl_scenario_key') or (scenario0 or None),
                        }
                        try:
                            if full_prev.get('hitl_core'):
                                hitl_config['core'] = full_prev.get('hitl_core')
                        except Exception:
                            pass

                        import json as _json

                        preview_json_str = _json.dumps(full_prev, indent=2, default=str)
                        xml_basename = None
                        try:
                            if xml_path0:
                                xml_basename = os.path.basename(xml_path0)
                        except Exception:
                            xml_basename = None

                        try:
                            plan_label = os.path.basename(plan_path)
                        except Exception:
                            plan_label = str(plan_path)
                        app.logger.info('[plan.full_preview_page] using plan=%s scenario=%s', plan_label, scen_norm or (scenario or ''))
                        return render_template(
                            'full_preview.html',
                            full_preview=full_prev,
                            preview_json=preview_json_str,
                            xml_path=backend._abs_path_or_original(xml_path0) or backend._abs_path_or_original(plan_path),
                            scenario=scenario0,
                            seed=seed0,
                            preview_source=str((meta or {}).get('preview_source') or 'embedded'),
                            flow_meta=flow_meta or {},
                            preview_plan_path=backend._abs_path_or_original(plan_path),
                            display_artifacts=display_artifacts,
                            segmentation_artifacts=segmentation_artifacts,
                            hitl_config=hitl_config,
                            xml_basename=xml_basename,
                            hide_chrome=embed,
                        )
                except Exception:
                    pass

                if embed:
                    return Response(
                        '<div style="font-family: system-ui; padding: 16px; color: #6c757d;">'
                        'Generate a Preview/Flow first to keep Preview in sync.'
                        '</div>',
                        mimetype='text/html',
                    )
                flash('Generate a Preview/Flow first to keep Preview in sync.')
                return redirect(url_for('scenarios_preview'))

            if embed:
                return Response(
                    '<div style="font-family: system-ui; padding: 16px; color: #6c757d;">'
                    'Select a scenario to load its Preview.'
                    '</div>',
                    mimetype='text/html',
                )
            flash('Select a scenario to load its Preview.')
            return redirect(url_for('scenarios_preview'))

            if not force_recompute:
                if embed:
                    return Response(
                        '<div style="font-family: system-ui; padding: 16px; color: #6c757d;">'
                        'Preview renders saved XML only. Generate a Preview first.'
                        '</div>',
                        mimetype='text/html',
                    )
                flash('Preview renders saved XML only. Generate a Preview first.')
                return redirect(url_for('scenarios_preview'))

            if not xml_path:
                if embed:
                    return Response(
                        '<div style="font-family: system-ui; padding: 16px; color: #6c757d;">'
                        'Save XML first to preview (missing xml_path).'
                        '</div>',
                        mimetype='text/html',
                    )
                flash('xml_path missing (full preview page)')
                return redirect(url_for('index'))
            xml_path = os.path.abspath(xml_path)
            xml_basename = os.path.splitext(os.path.basename(xml_path))[0] if xml_path else ''
            if not os.path.exists(xml_path) and '/outputs/' in xml_path:
                try:
                    alt = xml_path.replace('/app/outputs', '/app/webapp/outputs')
                    if alt != xml_path and os.path.exists(alt):
                        app.logger.info('[full_preview] remapped xml_path %s -> %s', xml_path, alt)
                        xml_path = alt
                except Exception:
                    pass
            if not os.path.exists(xml_path) and '/outputs/' in xml_path:
                try:
                    alt = xml_path.replace('/app/webapp/outputs', '/app/outputs')
                    if alt != xml_path and os.path.exists(alt):
                        app.logger.info('[full_preview] remapped xml_path %s -> %s', xml_path, alt)
                        xml_path = alt
                except Exception:
                    pass
            if not os.path.exists(xml_path):
                if embed:
                    safe = (xml_path or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    return Response(
                        '<div style="font-family: system-ui; padding: 16px; color: #6c757d;">'
                        'Save XML first to preview (XML not found):<br><code style="color:#495057;">'
                        + safe +
                        '</code></div>',
                        mimetype='text/html',
                    )
                flash(f'XML not found: {xml_path}')
                return redirect(url_for('index'))
            from core_topo_gen.planning.orchestrator import compute_full_plan
            from core_topo_gen.planning.plan_cache import hash_xml_file

            xml_hash = None
            try:
                xml_hash = hash_xml_file(xml_path)
            except Exception:
                xml_hash = None

            plan = compute_full_plan(xml_path, scenario=scenario, seed=seed, include_breakdowns=True)
            if seed is None:
                seed = plan.get('seed') or backend._derive_default_seed(xml_hash or hash_xml_file(xml_path))
            full_prev = backend._build_full_preview_from_plan(plan, seed, [], [])
            display_artifacts = full_prev.get('display_artifacts')
            if not display_artifacts:
                try:
                    display_artifacts = backend._attach_display_artifacts(full_prev)
                except Exception:
                    display_artifacts = {
                        'segmentation': {
                            'rows': [],
                            'table_rows': [],
                            'tableRows': [],
                            'json': {'rules_count': 0, 'types_summary': {}, 'rules': [], 'metadata': None},
                        },
                        '__version': backend.FULL_PREVIEW_ARTIFACT_VERSION,
                    }
            segmentation_artifacts = (display_artifacts or {}).get('segmentation')
            scenario_name = scenario or None
            if not scenario_name:
                try:
                    names_for_cli = backend._scenario_names_from_xml(xml_path)
                    if names_for_cli:
                        scenario_name = names_for_cli[0]
                except Exception:
                    pass
            try:
                raw_hitl_config = backend.parse_hitl_info(xml_path, scenario_name)
            except Exception as hitl_exc:
                try:
                    app.logger.debug('[plan.full_preview_page] hitl parse failed: %s', hitl_exc)
                except Exception:
                    pass
                raw_hitl_config = {'enabled': False, 'interfaces': []}
            hitl_config = backend._sanitize_hitl_config(raw_hitl_config, scenario_name, xml_basename)
            try:
                backend._apply_hitl_config_to_full_preview(full_prev, hitl_config, scenario_name)
            except Exception:
                pass
            flow_meta = None
            try:
                meta_flow = meta.get('flow') if isinstance(meta, dict) else None
                if isinstance(meta_flow, dict):
                    flow_meta = meta_flow
            except Exception:
                flow_meta = None
            if flow_meta is None:
                try:
                    flow_meta = backend._attach_latest_flow_into_full_preview(full_prev, scenario_name, repair=False)
                except Exception:
                    flow_meta = None
            preview_plan_path = xml_path
            import json as _json

            preview_json_str = _json.dumps(full_prev, indent=2, default=str)
            return render_template(
                'full_preview.html',
                full_preview=full_prev,
                preview_json=preview_json_str,
                xml_path=backend._abs_path_or_original(xml_path),
                scenario=scenario_name,
                seed=full_prev.get('seed'),
                preview_source='computed_from_xml',
                flow_meta=flow_meta or {},
                preview_plan_path=backend._abs_path_or_original(preview_plan_path),
                display_artifacts=display_artifacts,
                segmentation_artifacts=segmentation_artifacts,
                hitl_config=hitl_config,
                xml_basename=xml_basename,
                hide_chrome=embed,
            )
        except Exception as exc:
            app.logger.exception('[plan.full_preview_page] error: %s', exc)
            flash(f'Full preview page error: {exc}')
            return redirect(url_for('index'))

    def _plan_full_preview_from_plan():
        try:
            embed_raw = request.args.get('embed') or request.form.get('embed') or ''
            embed = str(embed_raw).strip().lower() in ['1', 'true', 'yes', 'y', 'on']
            plan_path = (request.form.get('preview_plan') or '').strip()
            if not plan_path:
                return redirect(url_for('index'))
            try:
                plan_path = os.path.abspath(plan_path)
                plans_dir = os.path.abspath(os.path.join(backend._outputs_dir(), 'plans'))
                if os.path.commonpath([plan_path, plans_dir]) != plans_dir:
                    flash('Invalid preview plan path')
                    return redirect(url_for('index'))
                if not os.path.exists(plan_path):
                    flash('Preview plan not found')
                    return redirect(url_for('index'))
            except Exception:
                flash('Invalid preview plan path')
                return redirect(url_for('index'))

            flash('Preview plans are embedded in XML now; use the XML preview endpoint.')
            return redirect(url_for('index'))
        except Exception as exc:
            app.logger.exception('[plan.full_preview_from_plan] error: %s', exc)
            flash(f'Full preview error: {exc}')
            return redirect(url_for('index'))

    def _plan_full_preview_from_xml():
        try:
            start_ts = time.time()
            embed_raw = request.args.get('embed') or request.form.get('embed') or ''
            embed = str(embed_raw).strip().lower() in ['1', 'true', 'yes', 'y', 'on']
            xml_path = (request.form.get('xml_path') or '').strip()
            scenario = (request.form.get('scenario') or '').strip() or None
            render_template_func = getattr(backend, 'render_template', render_template)
            if not xml_path:
                return redirect(url_for('index'))
            try:
                xml_path = os.path.abspath(xml_path)
                repo_root = os.path.abspath(backend._get_repo_root())
                if os.path.commonpath([xml_path, repo_root]) != repo_root:
                    flash('Invalid XML path')
                    return redirect(url_for('index'))
                if not os.path.exists(xml_path):
                    flash('XML not found')
                    return redirect(url_for('index'))
            except Exception:
                flash('Invalid XML path')
                return redirect(url_for('index'))

            payload = backend._load_preview_payload_from_path(xml_path, scenario)

            try:
                app.logger.info(
                    '[plan.full_preview_from_xml] initial lookup xml=%s scenario=%s hit=%s',
                    xml_path,
                    scenario or '',
                    bool(payload),
                )
            except Exception:
                pass

            preview_dirty = False
            try:
                flow_state = backend._flow_state_from_xml_path(xml_path, scenario)
                if isinstance(flow_state, dict) and backend._coerce_bool(flow_state.get('topology_dirty')):
                    preview_dirty = True
            except Exception:
                preview_dirty = False

            if preview_dirty:
                try:
                    recomputed = backend._planner_persist_flow_plan(
                        xml_path=xml_path,
                        scenario=scenario,
                        seed=None,
                        persist_plan_file=False,
                    )
                except Exception:
                    recomputed = None
                if isinstance(recomputed, dict) and isinstance(recomputed.get('full_preview'), dict):
                    payload = recomputed
                    try:
                        meta_re = payload.get('metadata') if isinstance(payload.get('metadata'), dict) else {}
                        if not isinstance(meta_re, dict):
                            meta_re = {}
                        meta_re['preview_source'] = 'recomputed_on_read'
                        payload['metadata'] = meta_re
                    except Exception:
                        pass
                    try:
                        app.logger.info(
                            '[plan.full_preview_from_xml] recomputed due to topology_dirty xml=%s scenario=%s',
                            xml_path,
                            scenario or '',
                        )
                    except Exception:
                        pass

            def _payload_matches_requested_scenario(payload_obj: Any, requested: str | None) -> bool:
                if not requested:
                    return True
                req_norm = backend._normalize_scenario_label(requested)
                if not req_norm:
                    return True
                try:
                    meta_obj = payload_obj.get('metadata') if isinstance(payload_obj, dict) else None
                    scen = str((meta_obj or {}).get('scenario') or '').strip() if isinstance(meta_obj, dict) else ''
                except Exception:
                    scen = ''
                return bool(scen and backend._normalize_scenario_label(scen) == req_norm)

            if not payload:
                try:
                    candidate = backend._load_preview_payload_from_path(xml_path, None)
                    payload = candidate if _payload_matches_requested_scenario(candidate, scenario) else None
                    try:
                        app.logger.info(
                            '[plan.full_preview_from_xml] fallback same-xml no-scenario xml=%s requested=%s candidate_match=%s',
                            xml_path,
                            scenario or '',
                            bool(payload),
                        )
                    except Exception:
                        pass
                except Exception:
                    payload = None
            if not payload and scenario:
                try:
                    scen_norm = backend._normalize_scenario_label(scenario)
                    latest_xml = backend._latest_xml_path_for_scenario(scen_norm) if scen_norm else None
                except Exception:
                    latest_xml = None
                if latest_xml:
                    try:
                        latest_xml_abs = os.path.abspath(latest_xml)
                    except Exception:
                        latest_xml_abs = latest_xml
                    if latest_xml_abs and os.path.exists(latest_xml_abs):
                        try:
                            payload = backend._load_preview_payload_from_path(latest_xml_abs, scenario)
                            selected_via = 'latest-xml+scenario' if payload else ''
                            if not payload:
                                candidate = backend._load_preview_payload_from_path(latest_xml_abs, None)
                                payload = candidate if _payload_matches_requested_scenario(candidate, scenario) else None
                                if payload:
                                    selected_via = 'latest-xml+no-scenario(match)'
                            if payload:
                                xml_path = latest_xml_abs
                            try:
                                app.logger.info(
                                    '[plan.full_preview_from_xml] fallback latest-xml requested=%s latest_xml=%s selected=%s via=%s',
                                    scenario or '',
                                    latest_xml_abs,
                                    bool(payload),
                                    selected_via,
                                )
                            except Exception:
                                pass
                        except Exception:
                            pass
            if not payload:
                try:
                    recomputed = backend._planner_persist_flow_plan(
                        xml_path=xml_path,
                        scenario=scenario,
                        seed=None,
                        persist_plan_file=False,
                    )
                except Exception:
                    recomputed = None
                if isinstance(recomputed, dict) and isinstance(recomputed.get('full_preview'), dict):
                    payload = recomputed
                    try:
                        meta_re = payload.get('metadata') if isinstance(payload.get('metadata'), dict) else {}
                        if not isinstance(meta_re, dict):
                            meta_re = {}
                        meta_re['preview_source'] = 'recomputed_on_read'
                        payload['metadata'] = meta_re
                    except Exception:
                        pass
                    try:
                        app.logger.info(
                            '[plan.full_preview_from_xml] recomputed planpreview xml=%s scenario=%s',
                            xml_path,
                            scenario or '',
                        )
                    except Exception:
                        pass
                else:
                    try:
                        payload = backend._load_preview_payload_from_path(xml_path, scenario) or backend._load_preview_payload_from_path(xml_path, None)
                    except Exception:
                        payload = None
            if not payload:
                flash('PlanPreview not found in XML')
                return redirect(url_for('index'))

            full_prev = payload.get('full_preview') if isinstance(payload, dict) else None
            if not isinstance(full_prev, dict):
                flash('PlanPreview missing full_preview')
                return redirect(url_for('index'))
            meta = payload.get('metadata') if isinstance(payload, dict) else None
            if not isinstance(meta, dict):
                meta = {}

            force_refresh = str(request.form.get('force') or '').strip().lower() in ['1', 'true', 'yes', 'y', 'on']
            if force_refresh:
                try:
                    plan_ts = None
                    updated_at = str(meta.get('updated_at') or meta.get('created_at') or '').strip()
                    if updated_at:
                        try:
                            if updated_at.endswith('Z'):
                                updated_at = updated_at[:-1] + '+00:00'
                            plan_ts = datetime.datetime.fromisoformat(updated_at).timestamp()
                        except Exception:
                            plan_ts = None
                    if plan_ts is not None:
                        xml_mtime = os.path.getmtime(xml_path)
                        if xml_mtime > plan_ts:
                            try:
                                app.logger.info('[plan.full_preview_from_xml] PlanPreview stale; recomputing for %s', xml_path)
                            except Exception:
                                pass
                            try:
                                recomputed = backend._planner_persist_flow_plan(
                                    xml_path=xml_path,
                                    scenario=scenario,
                                    seed=meta.get('seed'),
                                    persist_plan_file=False,
                                )
                                if isinstance(recomputed, dict) and isinstance(recomputed.get('full_preview'), dict):
                                    full_prev = recomputed.get('full_preview')
                                payload = backend._load_preview_payload_from_path(xml_path, scenario) or payload
                                meta = payload.get('metadata') if isinstance(payload, dict) else meta
                                if not isinstance(meta, dict):
                                    meta = {}
                            except Exception:
                                pass
                except Exception:
                    pass

            scenario_name = str(meta.get('scenario') or '') or scenario or None
            try:
                xml_basename_for_hitl = os.path.basename(xml_path)
            except Exception:
                xml_basename_for_hitl = None
            try:
                raw_hitl_config = backend.parse_hitl_info(xml_path, scenario_name)
            except Exception:
                raw_hitl_config = {'enabled': False, 'interfaces': []}
            try:
                hitl_cfg_live = backend._sanitize_hitl_config(raw_hitl_config, scenario_name, xml_basename_for_hitl)
            except Exception:
                hitl_cfg_live = {'enabled': False, 'interfaces': []}
            try:
                backend._apply_hitl_config_to_full_preview(full_prev, hitl_cfg_live, scenario_name)
            except Exception:
                pass
            seed_val = meta.get('seed')
            try:
                seed_val = int(seed_val) if seed_val is not None else full_prev.get('seed')
            except Exception:
                seed_val = full_prev.get('seed')

            flow_meta = None
            try:
                scen_norm = backend._normalize_scenario_label(scenario_name or '')
                if scen_norm:
                    parsed = backend._parse_scenarios_xml(xml_path)
                    scen_list = parsed.get('scenarios') if isinstance(parsed, dict) else None
                    if isinstance(scen_list, list):
                        for sc in scen_list:
                            if not isinstance(sc, dict):
                                continue
                            nm = str(sc.get('name') or '').strip()
                            if backend._normalize_scenario_label(nm) != scen_norm:
                                continue
                            fs = sc.get('flow_state')
                            if isinstance(fs, dict) and fs:
                                flow_meta = fs
                                break
            except Exception:
                flow_meta = None
            if not isinstance(flow_meta, dict) or not flow_meta:
                flow_meta = None

            hitl_config = {
                'enabled': bool(full_prev.get('hitl_enabled')),
                'interfaces': full_prev.get('hitl_interfaces') or [],
                'scenario_key': full_prev.get('hitl_scenario_key') or (scenario_name or None),
            }
            try:
                if full_prev.get('hitl_core'):
                    hitl_config['core'] = full_prev.get('hitl_core')
            except Exception:
                pass

            display_artifacts = full_prev.get('display_artifacts')
            if not display_artifacts:
                try:
                    display_artifacts = backend._attach_display_artifacts(full_prev)
                except Exception:
                    display_artifacts = {
                        'segmentation': {
                            'rows': [],
                            'table_rows': [],
                            'tableRows': [],
                            'json': {'rules_count': 0, 'types_summary': {}, 'rules': [], 'metadata': None},
                        },
                        '__version': backend.FULL_PREVIEW_ARTIFACT_VERSION,
                    }
            segmentation_artifacts = (display_artifacts or {}).get('segmentation')

            import json as _json

            preview_json_str = _json.dumps(full_prev, indent=2, default=str)
            xml_basename = None
            try:
                xml_basename = os.path.basename(xml_path)
            except Exception:
                xml_basename = None

            try:
                elapsed_ms = int((time.time() - start_ts) * 1000)
                app.logger.info('[plan.full_preview_from_xml] ok in %sms xml=%s scenario=%s', elapsed_ms, xml_path, scenario_name or '')
            except Exception:
                pass
            return render_template_func(
                'full_preview.html',
                full_preview=full_prev,
                preview_json=preview_json_str,
                xml_path=backend._abs_path_or_original(xml_path),
                scenario=scenario_name,
                seed=seed_val,
                preview_source=str((meta or {}).get('preview_source') or 'embedded'),
                flow_meta=flow_meta or {},
                preview_plan_path=backend._abs_path_or_original(xml_path),
                display_artifacts=display_artifacts,
                segmentation_artifacts=segmentation_artifacts,
                hitl_config=hitl_config,
                xml_basename=xml_basename,
                hide_chrome=embed,
            )
        except Exception as exc:
            try:
                elapsed_ms = int((time.time() - start_ts) * 1000) if 'start_ts' in locals() else None
                app.logger.exception('[plan.full_preview_from_xml] error after %sms: %s', elapsed_ms, exc)
            except Exception:
                app.logger.exception('[plan.full_preview_from_xml] error: %s', exc)
            flash(f'Full preview error: {exc}')
            return redirect(url_for('index'))

    app.add_url_rule('/plan/full_preview_page', endpoint='plan_full_preview_page', view_func=_plan_full_preview_page, methods=['POST'])
    app.add_url_rule('/plan/full_preview_from_plan', endpoint='plan_full_preview_from_plan', view_func=_plan_full_preview_from_plan, methods=['POST'])
    app.add_url_rule('/plan/full_preview_from_xml', endpoint='plan_full_preview_from_xml', view_func=_plan_full_preview_from_xml, methods=['POST'])

    mark_routes_registered(app, 'plan_preview_pages_routes')
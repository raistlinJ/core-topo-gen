from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from typing import Any
from typing import Dict

from flask import flash
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from werkzeug.utils import secure_filename

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'app_entry_routes'):
        return

    backend = backend_module

    def _index():
        current = backend._current_user()
        scenario_query = ''
        xml_query = ''
        try:
            scenario_query = (request.args.get('scenario') or '').strip()
            xml_query = (request.args.get('xml_path') or '').strip()
        except Exception:
            scenario_query = ''
            xml_query = ''
        if current and backend._is_participant_role(current.get('role')):
            target_args = {'scenario': scenario_query} if scenario_query else {}
            return redirect(url_for('participant_ui_page', **target_args))

        payload: Dict[str, Any] = {'result_path': None, 'core': backend._default_core_dict()}
        force_empty = False
        try:
            role = backend._normalize_role_value(current.get('role')) if current else ''
            force_empty = backend._scenario_catalog_force_empty()
            if role == 'admin' and not force_empty:
                scenario_names, _scenario_paths, _scenario_url_hints = backend._scenario_catalog_for_user(None, user=current)
                if scenario_names:
                    payload = backend._default_scenarios_payload_for_names(scenario_names)
                    payload['_catalog_stub'] = True
        except Exception:
            payload = {'result_path': None, 'core': backend._default_core_dict()}

        backend._attach_base_upload(payload)
        backend._hydrate_base_upload_from_disk(payload)
        payload['host_interfaces'] = backend._enumerate_host_interfaces()
        if payload.get('base_upload'):
            backend._save_base_upload_state(payload['base_upload'])
        payload = backend._prepare_payload_for_index(payload, user=current)
        if scenario_query:
            payload['scenario_query'] = scenario_query
        if payload.get('result_path') and not payload.get('project_key_hint'):
            payload['project_key_hint'] = payload['result_path']
        if force_empty:
            backend._delete_editor_state_snapshot(current)
        else:
            snapshot = backend._load_editor_state_snapshot(current)
            if snapshot:
                payload['editor_snapshot'] = snapshot
                if not payload.get('result_path') and isinstance(snapshot.get('scenarios'), list) and not snapshot.get('scenarios'):
                    payload['scenarios'] = []
                if snapshot.get('result_path') and not payload.get('result_path'):
                    payload['result_path'] = snapshot.get('result_path')
                if snapshot.get('project_key_hint') and not payload.get('project_key_hint'):
                    payload['project_key_hint'] = snapshot.get('project_key_hint')
                if snapshot.get('scenario_query') and not payload.get('scenario_query'):
                    payload['scenario_query'] = snapshot.get('scenario_query')

        try:
            def _best_xml_for_index() -> str:
                try:
                    if xml_query:
                        cand = os.path.abspath(xml_query)
                        if cand.lower().endswith('.xml') and os.path.exists(cand):
                            return cand
                except Exception:
                    pass
                try:
                    cand = str(payload.get('result_path') or '').strip()
                    if cand and cand.lower().endswith('.xml'):
                        cand_abs = os.path.abspath(cand)
                        if os.path.exists(cand_abs):
                            return cand_abs
                except Exception:
                    pass
                if scenario_query:
                    try:
                        cand = backend._latest_xml_path_for_scenario(backend._normalize_scenario_label(scenario_query)) or ''
                        if cand and os.path.exists(cand):
                            return cand
                    except Exception:
                        pass
                return ''

            xml_hint = _best_xml_for_index()
            if xml_hint and os.path.exists(xml_hint):
                parsed = backend._parse_scenarios_xml(xml_hint)
                if isinstance(parsed, dict) and isinstance(parsed.get('scenarios'), list) and parsed.get('scenarios'):
                    payload['scenarios'] = parsed.get('scenarios')
                    if isinstance(parsed.get('core'), dict):
                        payload['core'] = parsed.get('core')
                    payload['result_path'] = xml_hint
                    payload['project_key_hint'] = xml_hint
                    payload['_xml_forced'] = True
                    try:
                        app.logger.info('[index] forced scenarios from xml: %s', xml_hint)
                    except Exception:
                        pass
        except Exception:
            pass

        xml_text = ''
        try:
            result_path = payload.get('result_path') if isinstance(payload, dict) else None
            if isinstance(result_path, str) and result_path.strip() and result_path.lower().endswith('.xml'):
                rp = os.path.expanduser(result_path.strip())
                rp = os.path.normpath(rp)
                candidates = [rp]
                try:
                    repo_root = backend._get_repo_root()
                    if not os.path.isabs(rp):
                        candidates.append(os.path.abspath(os.path.join(repo_root, rp)))
                    if rp.startswith('outputs' + os.sep):
                        candidates.append(os.path.abspath(os.path.join(backend._outputs_dir(), rp.split(os.sep, 1)[-1])))
                except Exception:
                    pass
                chosen = next((p for p in candidates if p and os.path.exists(p)), None)
                if chosen:
                    with open(chosen, 'r', encoding='utf-8', errors='ignore') as handle:
                        xml_text = handle.read()

            if not xml_text:
                scenarios = payload.get('scenarios') if isinstance(payload, dict) else None
                if isinstance(scenarios, list) and scenarios:
                    core_meta = payload.get('core') if isinstance(payload.get('core'), dict) else None
                    tree = backend._build_scenarios_xml({'scenarios': scenarios, 'core': core_meta})
                    try:
                        from lxml import etree as LET  # type: ignore

                        raw = ET.tostring(tree.getroot(), encoding='utf-8')
                        lroot = LET.fromstring(raw)
                        pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                        xml_text = pretty.decode('utf-8', errors='ignore')
                    except Exception:
                        xml_text = ET.tostring(tree.getroot(), encoding='unicode')
        except Exception:
            xml_text = ''

        render_template_func = getattr(backend, 'render_template', render_template)
        return render_template_func(
            'index.html',
            payload=payload,
            logs='',
            xml_preview=xml_text,
            ui_build_id=backend._WEBUI_BUILD_ID,
        )

    def _run_cli():
        user = backend._current_user()
        xml_path = request.form.get('xml_path')
        if not xml_path:
            flash('XML path missing. Save XML first.')
            return redirect(url_for('index'))
        xml_path = os.path.abspath(xml_path)
        if not os.path.exists(xml_path) and '/outputs/' in xml_path:
            try:
                alt = xml_path.replace('/app/outputs', '/app/webapp/outputs')
                if alt != xml_path and os.path.exists(alt):
                    app.logger.info('[sync] Remapped XML path %s -> %s', xml_path, alt)
                    xml_path = alt
            except Exception:
                pass
        if not os.path.exists(xml_path):
            try:
                recovered = backend._try_resolve_latest_outputs_xml(xml_path)
                if recovered and os.path.exists(recovered):
                    app.logger.warning('[sync] XML path missing; recovered to newest match: %s -> %s', xml_path, recovered)
                    xml_path = recovered
            except Exception:
                pass
        if not os.path.exists(xml_path):
            flash(f'XML path not found: {xml_path}')
            return redirect(url_for('index'))

        preview_plan_path = request.form.get('preview_plan') or xml_path
        preview_plan_path = str(preview_plan_path or '').strip() or None
        if preview_plan_path:
            try:
                preview_plan_path = os.path.abspath(preview_plan_path)
            except Exception:
                preview_plan_path = xml_path
            if not os.path.exists(preview_plan_path):
                preview_plan_path = xml_path

        core_override = None
        try:
            core_json = request.form.get('core_json')
            if core_json:
                core_override = json.loads(core_json)
        except Exception:
            core_override = None
        scenario_core_override = None
        try:
            hitl_core_json = request.form.get('hitl_core_json')
            if hitl_core_json:
                scenario_core_override = json.loads(hitl_core_json)
        except Exception:
            scenario_core_override = None
        scenario_name_hint = request.form.get('scenario') or request.form.get('scenario_name') or None
        docker_cleanup_before_run = backend._coerce_bool(request.form.get('docker_cleanup_before_run'))
        docker_remove_all_containers = backend._coerce_bool(request.form.get('docker_remove_all_containers')) or backend._coerce_bool(request.form.get('docker_nuke_all'))
        if backend._webui_running_in_docker() and (docker_cleanup_before_run or docker_remove_all_containers):
            docker_cleanup_before_run = False
            docker_remove_all_containers = False
            try:
                app.logger.warning('[sync] Ignoring docker cleanup/restart toggles because web UI is running in Docker')
            except Exception:
                pass
        scenario_index_hint = None
        try:
            raw_index = request.form.get('scenario_index')
            if raw_index not in (None, ''):
                scenario_index_hint = int(raw_index)
        except Exception:
            scenario_index_hint = None
        payload_for_core: Dict[str, Any] | None = None
        try:
            payload_for_core = backend._parse_scenarios_xml(xml_path)
        except Exception:
            payload_for_core = None
        scenario_payload: Dict[str, Any] | None = None
        if payload_for_core:
            scen_list = payload_for_core.get('scenarios') or []
            if isinstance(scen_list, list) and scen_list:
                if scenario_name_hint:
                    for scen_entry in scen_list:
                        if not isinstance(scen_entry, dict):
                            continue
                        if str(scen_entry.get('name') or '').strip() == str(scenario_name_hint).strip():
                            scenario_payload = scen_entry
                            break
                if scenario_payload is None and scenario_index_hint is not None:
                    if 0 <= scenario_index_hint < len(scen_list):
                        candidate = scen_list[scenario_index_hint]
                        if isinstance(candidate, dict):
                            scenario_payload = candidate
                if scenario_payload is None:
                    for scen_entry in scen_list:
                        if isinstance(scen_entry, dict):
                            scenario_payload = scen_entry
                            break
        scenario_for_plan = None
        try:
            scenario_for_plan = str(scenario_name_hint or '').strip() or None
        except Exception:
            scenario_for_plan = None
        if not scenario_for_plan:
            try:
                if isinstance(scenario_payload, dict):
                    scenario_for_plan = str(scenario_payload.get('name') or '').strip() or None
            except Exception:
                scenario_for_plan = None
        log_path = ''
        log_f = None
        scenario_core_saved = None
        if scenario_payload and isinstance(scenario_payload.get('hitl'), dict):
            scenario_core_saved = scenario_payload['hitl'].get('core')
        global_core_saved = payload_for_core.get('core') if (payload_for_core and isinstance(payload_for_core.get('core'), dict)) else None
        scenario_core_public: Dict[str, Any] | None = None
        candidate_scenario_core = scenario_core_override if isinstance(scenario_core_override, dict) else None
        if not candidate_scenario_core and isinstance(scenario_core_saved, dict):
            candidate_scenario_core = scenario_core_saved
        if candidate_scenario_core:
            scenario_core_public = backend._scrub_scenario_core_config(candidate_scenario_core)
        core_cfg = backend._merge_core_configs(
            global_core_saved,
            scenario_core_saved,
            core_override,
            scenario_core_override,
            include_password=True,
        )
        try:
            request_provided_core = bool(
                (isinstance(core_override, dict) and core_override)
                or (isinstance(scenario_core_override, dict) and scenario_core_override)
            )
            history = backend._load_run_history()
            scenario_for_secret = None
            try:
                scenario_for_secret = backend._normalize_scenario_label(str(scenario_name_hint or '').strip())
            except Exception:
                scenario_for_secret = None
            if not scenario_for_secret:
                try:
                    if isinstance(scenario_payload, dict) and isinstance(scenario_payload.get('name'), str):
                        scenario_for_secret = backend._normalize_scenario_label(str(scenario_payload.get('name') or '').strip())
                except Exception:
                    scenario_for_secret = None

            selected_cfg = None
            if scenario_for_secret:
                selected_cfg = backend._select_core_config_for_page(scenario_for_secret, history, include_password=True)

            pw_raw = core_cfg.get('ssh_password') if isinstance(core_cfg, dict) else None
            pw_ok = bool(str(pw_raw).strip()) if pw_raw not in (None, '') else False

            if selected_cfg:
                merged_core_cfg = dict(core_cfg) if isinstance(core_cfg, dict) else {}
                if not pw_ok:
                    selected_pw = selected_cfg.get('ssh_password') if isinstance(selected_cfg, dict) else None
                    if selected_pw not in (None, ''):
                        merged_core_cfg['ssh_password'] = selected_pw
                def _is_loopback_host(value):
                    try:
                        text = str(value or '').strip().lower()
                    except Exception:
                        return False
                    return text in {'localhost', '127.0.0.1', '::1'}

                for field in ('ssh_username', 'ssh_port', 'venv_bin', 'core_secret_id', 'vm_key', 'vm_name', 'vm_node', 'vmid', 'proxmox_secret_id', 'proxmox_target', 'validated', 'last_tested_status'):
                    if merged_core_cfg.get(field) in (None, '', 0, {}):
                        value = selected_cfg.get(field)
                        if value not in (None, '', 0, {}):
                            merged_core_cfg[field] = value

                selected_ssh_host = selected_cfg.get('ssh_host') if isinstance(selected_cfg, dict) else None
                if selected_ssh_host not in (None, ''):
                    current_ssh_host = merged_core_cfg.get('ssh_host')
                    if current_ssh_host in (None, '') or _is_loopback_host(current_ssh_host):
                        merged_core_cfg['ssh_host'] = selected_ssh_host

                if request_provided_core and isinstance(core_cfg, dict):
                    for field in ('host', 'port', 'grpc_host', 'grpc_port'):
                        if core_cfg.get(field) not in (None, '', 0):
                            merged_core_cfg[field] = core_cfg.get(field)

                core_cfg = merged_core_cfg
        except Exception:
            pass
        try:
            core_cfg = backend._require_core_ssh_credentials(core_cfg)
        except backend._SSHTunnelError as exc:
            flash(str(exc))
            return redirect(url_for('index'))
        core_host = core_cfg.get('host', '127.0.0.1')
        try:
            core_port = int(core_cfg.get('port', 50051))
        except Exception:
            core_port = 50051
        remote_desc = f'{core_host}:{core_port}'
        app.logger.info('[sync] Preparing CLI run against CORE remote=%s (ssh_enabled=%s), xml=%s', remote_desc, core_cfg.get('ssh_enabled'), xml_path)
        preferred_cli_venv = backend._sanitize_venv_bin_path(core_cfg.get('venv_bin'))
        venv_is_explicit = backend._venv_is_explicit(core_cfg, preferred_cli_venv)
        if venv_is_explicit and preferred_cli_venv:
            cli_venv_bin = backend._resolve_cli_venv_bin(preferred_cli_venv, allow_fallback=False)
            if not cli_venv_bin:
                flash(
                    f"Remote CORE venv bin '{preferred_cli_venv}' is not accessible from this host. "
                    'Mount that directory or adjust the path before running the CLI.',
                )
                return redirect(url_for('index'))
        else:
            cli_venv_bin = backend._resolve_cli_venv_bin(preferred_cli_venv, allow_fallback=True)
        try:
            try:
                pre_dir = os.path.join(os.path.dirname(xml_path) or backend._outputs_dir(), 'core-pre')
                pre_saved = backend._grpc_save_current_session_xml_with_config(core_cfg, pre_dir)
                if pre_saved:
                    flash(f'Captured current CORE session XML: {os.path.basename(pre_saved)}')
                    app.logger.debug('[sync] Pre-run session XML saved to %s', pre_saved)
            except Exception:
                pre_saved = None
            repo_root = backend._get_repo_root()
            py_exec = backend._select_python_interpreter(cli_venv_bin)
            cli_env = backend._prepare_cli_env(preferred_venv_bin=cli_venv_bin)
            cli_env.setdefault('PYTHONUNBUFFERED', '1')
            cli_env.setdefault('CORETG_FLOW_ARTIFACTS_MODE', 'copy')
            app.logger.info('[sync] Using python interpreter: %s', py_exec)
            active_scenario_name = None
            if scenario_name_hint:
                active_scenario_name = scenario_name_hint
            elif scenario_payload and isinstance(scenario_payload.get('name'), str):
                active_scenario_name = scenario_payload.get('name')
            if not active_scenario_name:
                try:
                    names_for_cli = backend._scenario_names_from_xml(xml_path)
                    if names_for_cli:
                        active_scenario_name = names_for_cli[0]
                except Exception:
                    active_scenario_name = None

            try:
                out_dir_for_tag = os.path.dirname(xml_path) if xml_path else ''
                upload_base = os.path.basename(out_dir_for_tag) if out_dir_for_tag else ''
                parts = []
                if upload_base:
                    parts.append(upload_base)
                if active_scenario_name:
                    parts.append(active_scenario_name)
                scenario_tag = backend._safe_name('-'.join(parts) if parts else (active_scenario_name or 'scenario'))
                cli_env.setdefault('CORETG_SCENARIO_TAG', scenario_tag)
            except Exception:
                pass
            with backend._core_connection(core_cfg) as (conn_host, conn_port):
                forwarded_desc = f'{conn_host}:{conn_port}'
                app.logger.info(
                    '[sync] Running CLI with CORE remote=%s via=%s, xml=%s',
                    remote_desc,
                    forwarded_desc,
                    xml_path,
                )

                if docker_remove_all_containers:
                    try:
                        app.logger.warning('[sync] Pre-run: docker remove-all-containers requested')
                        backend._run_remote_python_json(
                            core_cfg,
                            backend._remote_docker_remove_all_containers_script(core_cfg.get('ssh_password')),
                            logger=app.logger,
                            label='docker.remove_all_containers(prerun)',
                            timeout=900.0,
                        )
                    except Exception as exc:
                        try:
                            app.logger.warning('[sync] Pre-run docker remove-all-containers skipped/failed: %s', exc)
                        except Exception:
                            pass
                if docker_cleanup_before_run:
                    try:
                        app.logger.info('[sync] Pre-run: docker cleanup requested (containers + wrapper images)')
                        status_payload = backend._run_remote_python_json(
                            core_cfg,
                            backend._remote_docker_status_script(core_cfg.get('ssh_password')),
                            logger=app.logger,
                            label='docker.status(for prerun cleanup)',
                            timeout=60.0,
                        )
                        names: list[str] = []
                        if isinstance(status_payload, dict) and isinstance(status_payload.get('items'), list):
                            for it in status_payload.get('items') or []:
                                if isinstance(it, dict) and it.get('name'):
                                    names.append(str(it.get('name')))
                        if names:
                            backend._run_remote_python_json(
                                core_cfg,
                                backend._remote_docker_cleanup_script(names, core_cfg.get('ssh_password')),
                                logger=app.logger,
                                label='docker.cleanup(prerun)',
                                timeout=120.0,
                            )
                        backend._run_remote_python_json(
                            core_cfg,
                            backend._remote_docker_remove_wrapper_images_script(core_cfg.get('ssh_password')),
                            logger=app.logger,
                            label='docker.wrapper_images.cleanup(prerun)',
                            timeout=180.0,
                        )
                    except Exception as exc:
                        try:
                            app.logger.warning('[sync] Pre-run docker cleanup skipped/failed: %s', exc)
                        except Exception:
                            pass

                cli_args = [
                    py_exec,
                    '-m',
                    'core_topo_gen.cli',
                    '--xml',
                    xml_path,
                    '--host',
                    conn_host,
                    '--port',
                    str(conn_port),
                ]
                try:
                    cli_verbose = str(os.getenv('CORETG_WEBAPP_CLI_VERBOSE') or '').strip().lower() in ('1', 'true', 'yes', 'y', 'on')
                except Exception:
                    cli_verbose = False
                try:
                    if (not cli_verbose) and str(os.getenv('WEBAPP_LOG_LEVEL') or '').strip().upper() == 'DEBUG':
                        cli_verbose = True
                except Exception:
                    pass
                if cli_verbose:
                    cli_args.append('--verbose')
                if active_scenario_name:
                    cli_args.extend(['--scenario', active_scenario_name])

                try:
                    fs = backend._read_flow_state_from_xml_path(xml_path, active_scenario_name)
                    if isinstance(fs, dict) and fs:
                        backend._update_flow_state_in_xml(xml_path, active_scenario_name, fs)
                except Exception:
                    pass
                proc = subprocess.run(cli_args, cwd=repo_root, check=False, capture_output=True, text=True, env=cli_env)
            logs = (proc.stdout or '') + ('\n' + proc.stderr if proc.stderr else '')
            app.logger.debug('[sync] CLI return code: %s', proc.returncode)

            try:
                docker_expected = False
                if preview_plan_path and scenario_for_plan:
                    plan_payload = backend._load_preview_payload_from_path(preview_plan_path, scenario_for_plan)
                    if isinstance(plan_payload, dict):
                        full_preview = plan_payload.get('full_preview') if isinstance(plan_payload.get('full_preview'), dict) else None
                        if isinstance(full_preview, dict):
                            role_counts = full_preview.get('role_counts') if isinstance(full_preview.get('role_counts'), dict) else None
                            if isinstance(role_counts, dict):
                                try:
                                    docker_expected = int(role_counts.get('Docker') or 0) > 0
                                except Exception:
                                    docker_expected = False
                            if not docker_expected:
                                hosts = full_preview.get('hosts') if isinstance(full_preview.get('hosts'), list) else []
                                for host in hosts or []:
                                    if not isinstance(host, dict):
                                        continue
                                    role = str(host.get('role') or '').strip().lower()
                                    if role == 'docker':
                                        docker_expected = True
                                        break
                if docker_expected:
                    try:
                        import glob as _glob
                        compose_files = _glob.glob('/tmp/vulns/docker-compose-*.yml')
                    except Exception:
                        compose_files = []
                    if not compose_files:
                        msg = 'No per-node docker-compose files were generated under /tmp/vulns despite Docker nodes in the plan.'
                        try:
                            log_f.write(f'[sync] ERROR: {msg}\n')
                        except Exception:
                            pass
                        try:
                            log_f.close()
                        except Exception:
                            pass
                        try:
                            os.remove(log_path)
                        except Exception:
                            pass
                        return jsonify({'error': msg}), 500
            except Exception:
                pass

            uploaded_vuln_artifacts = False
            try:
                uploaded_vuln_artifacts = bool(
                    backend._sync_local_vulns_to_remote(
                        core_cfg,
                        flow_plan_path=xml_path,
                        logger=app.logger,
                    )
                )
            except Exception as exc:
                uploaded_vuln_artifacts = False
                try:
                    app.logger.warning('[sync] Vuln artifact upload failed: %s', exc)
                except Exception:
                    pass
            try:
                app.logger.info('[sync] Vuln artifact upload complete uploaded=%s', bool(uploaded_vuln_artifacts))
            except Exception:
                pass

            try:
                payload = backend._run_remote_python_json(
                    core_cfg,
                    backend._remote_copy_flow_artifacts_into_containers_script(core_cfg.get('ssh_password')),
                    logger=app.logger,
                    label='docker.copy_flow_artifacts(postrun)',
                    timeout=180.0,
                )
                try:
                    copied_ok = 0
                    copied_total = 0
                    if isinstance(payload, dict) and isinstance(payload.get('items'), list):
                        copied_total = len(payload.get('items') or [])
                        copied_ok = sum(1 for it in (payload.get('items') or []) if isinstance(it, dict) and it.get('ok'))
                    app.logger.info('[sync] docker cp flow artifacts results ok=%s total=%s', int(copied_ok), int(copied_total))
                except Exception:
                    pass
            except Exception as exc:
                try:
                    app.logger.warning('[sync] docker cp flow artifacts skipped/failed: %s', exc)
                except Exception:
                    pass

            report_md = backend._extract_report_path_from_text(logs) or backend._find_latest_report_path()
            if report_md:
                app.logger.info('[sync] Detected report path: %s', report_md)
            summary_json = backend._extract_summary_path_from_text(logs)
            if not summary_json:
                summary_json = backend._derive_summary_from_report(report_md)
            if not summary_json and not report_md:
                summary_json = backend._find_latest_summary_path()
            if summary_json and not os.path.exists(summary_json):
                summary_json = None
            if summary_json:
                app.logger.info('[sync] Detected summary path: %s', summary_json)
            validation_summary = backend._extract_validation_summary_from_text(logs)
            if isinstance(validation_summary, dict):
                backend._persist_execute_validation_artifacts(report_md, summary_json, validation_summary)
            session_id = backend._extract_session_id_from_text(logs)
            if session_id:
                app.logger.info('[sync] Detected CORE session id: %s', session_id)
                backend._record_session_mapping(
                    xml_path,
                    session_id,
                    scenario_name=active_scenario_name or scenario_name_hint or None,
                )
                try:
                    sid_int = int(str(session_id).strip())
                    backend._write_remote_session_scenario_meta(
                        core_cfg,
                        session_id=sid_int,
                        scenario_name=active_scenario_name or scenario_name_hint or None,
                        scenario_xml_basename=os.path.basename(xml_path),
                        logger=app.logger,
                    )
                except Exception:
                    pass
            xml_text = ''
            try:
                with open(xml_path, 'r', encoding='utf-8', errors='ignore') as handle:
                    xml_text = handle.read()
            except Exception:
                xml_text = ''
            run_success = proc.returncode == 0
            post_saved = None
            if run_success:
                if report_md and os.path.exists(report_md):
                    flash('CLI completed. Report ready to download.')
                else:
                    flash('CLI completed. No report found.')
            else:
                flash('CLI finished with errors. See logs.')
            try:
                post_dir = os.path.join(os.path.dirname(xml_path), 'core-post')
                core_cfg_for_post = core_cfg
                try:
                    scenario_for_post = str(active_scenario_name or scenario_name_hint or '').strip()
                except Exception:
                    scenario_for_post = ''
                if scenario_for_post and isinstance(core_cfg_for_post, dict):
                    try:
                        core_cfg_for_post = backend._apply_core_secret_to_config(
                            core_cfg_for_post,
                            scenario_for_post.lower().replace(' ', '-'),
                        )
                    except Exception:
                        pass
                post_saved = backend._grpc_save_current_session_xml_with_config(core_cfg_for_post, post_dir, session_id=session_id)
                if post_saved:
                    flash(f'Captured post-run CORE session XML: {os.path.basename(post_saved)}')
                    app.logger.debug('[sync] Post-run session XML saved to %s', post_saved)
            except Exception:
                post_saved = None
            try:
                backend._append_session_scenario_discrepancies(
                    report_md,
                    xml_path,
                    post_saved,
                    scenario_label=active_scenario_name or scenario_name_hint,
                )
            except Exception:
                pass
            payload = payload_for_core or {}
            if not payload:
                try:
                    payload = backend._parse_scenarios_xml(xml_path)
                except Exception:
                    payload = {}
            if 'core' not in payload:
                payload['core'] = backend._default_core_dict()
            try:
                payload['core'] = backend._normalize_core_config(core_cfg, include_password=False)
            except Exception:
                pass
            backend._attach_base_upload(payload)
            payload['result_path'] = report_md if (report_md and os.path.exists(report_md)) else xml_path
            scen_names = []
            try:
                scen_names = backend._scenario_names_from_xml(xml_path)
            except Exception as e_names:
                app.logger.exception('[sync] failed extracting scenario names from %s: %s', xml_path, e_names)
            full_bundle_path = None
            single_scen_xml = None
            try:
                try:
                    single_scen_xml = backend._write_single_scenario_xml(
                        xml_path,
                        (active_scenario_name or (scen_names[0] if scen_names else None)),
                        out_dir=os.path.dirname(xml_path),
                    )
                except Exception:
                    single_scen_xml = None
                bundle_xml = single_scen_xml or xml_path
                app.logger.info('[sync] Building full scenario archive (xml=%s, report=%s, pre=%s, post=%s)', bundle_xml, report_md, (pre_saved if 'pre_saved' in locals() else None), post_saved)
                full_bundle_path = backend._build_full_scenario_archive(
                    os.path.dirname(bundle_xml),
                    bundle_xml,
                    (report_md if (report_md and os.path.exists(report_md)) else None),
                    (pre_saved if 'pre_saved' in locals() else None),
                    post_saved,
                    summary_path=summary_json,
                    run_id=None,
                )
            except Exception as e_bundle:
                app.logger.exception('[sync] failed building full scenario bundle: %s', e_bundle)
            try:
                session_xml_path = post_saved if (post_saved and os.path.exists(post_saved)) else None
                core_public = dict(core_cfg)
                core_public.pop('ssh_password', None)
                backend._append_run_history({
                    'timestamp': backend._local_timestamp_display(),
                    'mode': 'sync',
                    'xml_path': xml_path,
                    'post_xml_path': session_xml_path,
                    'session_xml_path': session_xml_path,
                    'scenario_xml_path': xml_path,
                    'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
                    'summary_path': summary_json if (summary_json and os.path.exists(summary_json)) else None,
                    'pre_xml_path': pre_saved if 'pre_saved' in locals() else None,
                    'full_scenario_path': full_bundle_path,
                    'single_scenario_xml_path': single_scen_xml,
                    'returncode': proc.returncode,
                    'scenario_names': scen_names,
                    'scenario_name': active_scenario_name,
                    'core': backend._normalize_core_config(core_cfg, include_password=False),
                    'core_cfg_public': core_public,
                    'scenario_core': scenario_core_public,
                    'validation_summary': validation_summary if isinstance(validation_summary, dict) else None,
                })
            except Exception as e_hist:
                app.logger.exception('[sync] failed appending run history: %s', e_hist)
            payload = backend._prepare_payload_for_index(payload, user=user)
            render_template_func = getattr(backend, 'render_template', render_template)
            return render_template_func('index.html', payload=payload, logs=logs, xml_preview=xml_text, run_success=run_success, ui_build_id=backend._WEBUI_BUILD_ID)
        except Exception as exc:
            flash(f'Error running core-topo-gen: {exc}')
            return redirect(url_for('index'))

    def _run_cli_async():
        seed = None
        xml_path = None
        preview_plan_path = None
        core_override = None
        scenario_core_override = None
        scenario_name_hint = None
        scenario_index_hint = None
        update_remote_repo = True
        adv_fix_docker_daemon = False
        adv_run_core_cleanup = False
        adv_check_core_version = False
        adv_restart_core_daemon = False
        adv_start_core_daemon = False
        adv_auto_kill_sessions = False
        docker_remove_conflicts = False
        docker_cleanup_before_run = False
        docker_remove_all_containers = False
        overwrite_existing_images = False
        upload_only_injected_artifacts = False
        scenarios_inline = None
        flow_enabled = True
        flow_disabled_reason = None
        log_f = None
        threading_module = getattr(backend, 'threading', threading)
        uuid_module = getattr(backend, 'uuid', uuid)
        secure_filename_func = getattr(backend, 'secure_filename', secure_filename)
        if request.form:
            xml_path = request.form.get('xml_path')
            raw_seed = request.form.get('seed')
            if raw_seed:
                try:
                    seed = int(raw_seed)
                except Exception:
                    seed = None
            preview_plan_path = request.form.get('preview_plan') or preview_plan_path
            scenario_name_hint = request.form.get('scenario') or request.form.get('scenario_name') or scenario_name_hint
            try:
                raw_index = request.form.get('scenario_index')
                if raw_index not in (None, ''):
                    scenario_index_hint = int(raw_index)
            except Exception:
                scenario_index_hint = scenario_index_hint
            try:
                core_json = request.form.get('core_json')
                if core_json:
                    core_override = json.loads(core_json)
            except Exception:
                core_override = None
            try:
                hitl_core_json = request.form.get('hitl_core_json')
                if hitl_core_json:
                    scenario_core_override = json.loads(hitl_core_json)
            except Exception:
                scenario_core_override = None
            adv_fix_docker_daemon = backend._coerce_bool(request.form.get('adv_fix_docker_daemon'))
            adv_run_core_cleanup = backend._coerce_bool(request.form.get('adv_run_core_cleanup'))
            adv_check_core_version = False
            adv_restart_core_daemon = backend._coerce_bool(request.form.get('adv_restart_core_daemon'))
            adv_start_core_daemon = backend._coerce_bool(request.form.get('adv_start_core_daemon'))
            adv_auto_kill_sessions = backend._coerce_bool(request.form.get('adv_auto_kill_sessions'))
            docker_remove_conflicts = backend._coerce_bool(request.form.get('docker_remove_conflicts'))
            docker_cleanup_before_run = backend._coerce_bool(request.form.get('docker_cleanup_before_run'))
            docker_remove_all_containers = backend._coerce_bool(request.form.get('docker_remove_all_containers')) or backend._coerce_bool(request.form.get('docker_nuke_all'))
            overwrite_existing_images = backend._coerce_bool(request.form.get('overwrite_existing_images'))
            if 'flow_enabled' in request.form:
                flow_enabled = backend._coerce_bool(request.form.get('flow_enabled'))
        try:
            json_body = request.get_json(silent=True) or {}
            if 'flow_enabled' in json_body:
                flow_enabled = backend._coerce_bool(json_body.get('flow_enabled'))
        except Exception:
            json_body = {}
        if not xml_path:
            try:
                xml_path = json_body.get('xml_path')
                scenarios_inline = json_body.get('scenarios')
                if 'seed' in json_body:
                    try:
                        seed = int(json_body.get('seed'))
                    except Exception:
                        seed = None
                if 'preview_plan' in json_body and not preview_plan_path:
                    preview_plan_path = json_body.get('preview_plan')
                if 'core' in json_body and json_body.get('core') is not None:
                    core_override = json_body.get('core')
                if 'hitl_core' in json_body and isinstance(json_body.get('hitl_core'), dict):
                    scenario_core_override = json_body.get('hitl_core')
                if 'scenario' in json_body and json_body.get('scenario') not in (None, ''):
                    scenario_name_hint = json_body.get('scenario')
                if 'scenario_index' in json_body:
                    try:
                        scenario_index_hint = int(json_body.get('scenario_index'))
                    except Exception:
                        scenario_index_hint = None
                adv_fix_docker_daemon = backend._coerce_bool(json_body.get('adv_fix_docker_daemon'))
                adv_run_core_cleanup = backend._coerce_bool(json_body.get('adv_run_core_cleanup'))
                adv_check_core_version = False
                adv_restart_core_daemon = backend._coerce_bool(json_body.get('adv_restart_core_daemon'))
                adv_start_core_daemon = backend._coerce_bool(json_body.get('adv_start_core_daemon'))
                adv_auto_kill_sessions = backend._coerce_bool(json_body.get('adv_auto_kill_sessions'))
                docker_remove_conflicts = backend._coerce_bool(json_body.get('docker_remove_conflicts'))
                docker_cleanup_before_run = backend._coerce_bool(json_body.get('docker_cleanup_before_run'))
                docker_remove_all_containers = backend._coerce_bool(json_body.get('docker_remove_all_containers')) or backend._coerce_bool(json_body.get('docker_nuke_all'))
                overwrite_existing_images = backend._coerce_bool(json_body.get('overwrite_existing_images'))
            except Exception:
                pass
        if backend._webui_running_in_docker() and (adv_fix_docker_daemon or docker_cleanup_before_run or docker_remove_all_containers):
            adv_fix_docker_daemon = False
            docker_cleanup_before_run = False
            docker_remove_all_containers = False
            try:
                app.logger.warning('[async] Ignoring docker repair/cleanup toggles because web UI is running in Docker')
            except Exception:
                pass
        if not xml_path:
            if isinstance(scenarios_inline, list):
                try:
                    core_meta = core_override if isinstance(core_override, dict) else None
                    normalized_core = backend._normalize_core_config(core_meta, include_password=True) if core_meta else None
                    scenario_pick = None
                    if scenario_name_hint:
                        for sc in scenarios_inline:
                            if isinstance(sc, dict) and str(sc.get('name') or '').strip() == str(scenario_name_hint).strip():
                                scenario_pick = sc
                                break
                    if scenario_pick is None and scenario_index_hint is not None:
                        if 0 <= scenario_index_hint < len(scenarios_inline):
                            candidate = scenarios_inline[scenario_index_hint]
                            if isinstance(candidate, dict):
                                scenario_pick = candidate
                    if scenario_pick is None:
                        scenario_pick = next((sc for sc in scenarios_inline if isinstance(sc, dict)), None)
                    if scenario_pick is None:
                        return jsonify({'error': 'No valid scenario supplied for execution.'}), 400
                    tree = backend._build_scenarios_xml({'scenarios': [scenario_pick], 'core': normalized_core})
                    ts = backend._local_timestamp_safe()
                    run_tag = str(uuid_module.uuid4())[:8]
                    out_dir = os.path.join(backend._outputs_dir(), f'tmp-exec-{ts}-{run_tag}')
                    os.makedirs(out_dir, exist_ok=True)
                    stem_raw = None
                    try:
                        if scenario_name_hint:
                            stem_raw = str(scenario_name_hint)
                    except Exception:
                        stem_raw = None
                    if not stem_raw:
                        try:
                            first_name = None
                            if isinstance(scenario_pick, dict) and scenario_pick.get('name'):
                                first_name = scenario_pick.get('name')
                            stem_raw = first_name or 'scenario'
                        except Exception:
                            stem_raw = 'scenario'
                    stem = secure_filename_func(str(stem_raw)).strip('_-.') or 'scenario'
                    xml_path = os.path.join(out_dir, f'{stem}.xml')
                    try:
                        from lxml import etree as LET  # type: ignore

                        raw = ET.tostring(tree.getroot(), encoding='utf-8')
                        lroot = LET.fromstring(raw)
                        pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                        with open(xml_path, 'wb') as handle:
                            handle.write(pretty)
                    except Exception:
                        tree.write(xml_path, encoding='utf-8', xml_declaration=True)
                    if not scenario_name_hint:
                        try:
                            scenario_name_hint = str((scenario_pick or {}).get('name') or '').strip() or scenario_name_hint
                        except Exception:
                            pass
                except Exception as exc:
                    return jsonify({'error': f'Failed to render XML for execution: {exc}'}), 400
            else:
                return jsonify({'error': 'XML path missing. Save XML first.'}), 400
        xml_path = os.path.abspath(xml_path)
        if not os.path.exists(xml_path) and '/outputs/' in xml_path:
            try:
                alt = xml_path.replace('/app/outputs', '/app/webapp/outputs')
                if alt != xml_path and os.path.exists(alt):
                    app.logger.info('[async] Remapped XML path %s -> %s', xml_path, alt)
                    xml_path = alt
            except Exception:
                pass
        if not os.path.exists(xml_path):
            try:
                recovered = backend._try_resolve_latest_outputs_xml(xml_path)
                if recovered and os.path.exists(recovered):
                    app.logger.warning('[async] XML path missing; recovered to newest match: %s -> %s', xml_path, recovered)
                    xml_path = recovered
            except Exception:
                pass
        if not os.path.exists(xml_path):
            return jsonify({'error': f'XML path not found: {xml_path}'}), 400
        preview_plan_path = (preview_plan_path or '').strip() or None
        if preview_plan_path:
            try:
                preview_plan_path = os.path.abspath(preview_plan_path)
                if preview_plan_path.lower().endswith('.xml'):
                    if not os.path.exists(preview_plan_path):
                        app.logger.warning('[async] preview plan path missing: %s', preview_plan_path)
                        try:
                            log_f.write(f'[async] preview plan rejected (missing): {preview_plan_path}\n')
                        except Exception:
                            pass
                        preview_plan_path = None
                else:
                    app.logger.warning('[async] preview plan rejected (non-xml): %s', preview_plan_path)
                    try:
                        log_f.write(f'[async] preview plan rejected (non-xml): {preview_plan_path}\n')
                    except Exception:
                        pass
                    preview_plan_path = None
            except Exception:
                preview_plan_path = None

        payload_for_core = None
        scenario_payload = None
        try:
            payload_for_core = backend._parse_scenarios_xml(xml_path)
        except Exception:
            payload_for_core = None
        if payload_for_core:
            scen_list = payload_for_core.get('scenarios') or []
            if isinstance(scen_list, list) and scen_list:
                if scenario_name_hint:
                    for scen_entry in scen_list:
                        if not isinstance(scen_entry, dict):
                            continue
                        if str(scen_entry.get('name') or '').strip() == str(scenario_name_hint).strip():
                            scenario_payload = scen_entry
                            break
                if scenario_payload is None and scenario_index_hint is not None:
                    if 0 <= scenario_index_hint < len(scen_list):
                        candidate = scen_list[scenario_index_hint]
                        if isinstance(candidate, dict):
                            scenario_payload = candidate
                if scenario_payload is None:
                    for scen_entry in scen_list:
                        if isinstance(scen_entry, dict):
                            scenario_payload = scen_entry
                            break

        if flow_enabled:
            preview_plan_path = xml_path
        else:
            preview_plan_path = None
        if not preview_plan_path and flow_enabled:
            try:
                scenario_norm = None
                if scenario_name_hint:
                    scenario_norm = backend._normalize_scenario_label(str(scenario_name_hint))
                if not scenario_norm and isinstance(scenario_payload, dict) and isinstance(scenario_payload.get('name'), str):
                    scenario_norm = backend._normalize_scenario_label(str(scenario_payload.get('name') or ''))
                if scenario_norm:
                    flow_plan = backend._latest_flow_plan_for_scenario_norm(scenario_norm)
                    if flow_plan and os.path.exists(flow_plan):
                        preview_plan_path = os.path.abspath(flow_plan)
                        try:
                            log_f.write(f'[async] Auto-selected plan for scenario={scenario_norm}: {preview_plan_path}\n')
                        except Exception:
                            pass
            except Exception:
                pass
        scenario_for_plan = None
        try:
            scenario_for_plan = str(scenario_name_hint or '').strip() or None
        except Exception:
            scenario_for_plan = None
        if not scenario_for_plan:
            try:
                names_for_cli = backend._scenario_names_from_xml(xml_path)
                if names_for_cli:
                    scenario_for_plan = names_for_cli[0]
            except Exception:
                scenario_for_plan = None
        try:
            if flow_enabled and xml_path and scenario_for_plan:
                parsed = backend._parse_scenarios_xml(xml_path)
                scen_list = parsed.get('scenarios') if isinstance(parsed, dict) else None
                if isinstance(scen_list, list):
                    for sc in scen_list:
                        if not isinstance(sc, dict):
                            continue
                        nm = str(sc.get('name') or '').strip()
                        if backend._normalize_scenario_label(nm) != backend._normalize_scenario_label(scenario_for_plan):
                            continue
                        fs = sc.get('flow_state') if isinstance(sc.get('flow_state'), dict) else None
                        if isinstance(fs, dict) and fs.get('flow_enabled') is False:
                            flow_enabled = False
                            preview_plan_path = None
                        break
        except Exception:
            pass
        if preview_plan_path and scenario_for_plan and flow_enabled:
            try:
                plan_payload = backend._load_preview_payload_from_path(preview_plan_path, scenario_for_plan)
                if isinstance(plan_payload, dict) and plan_payload:
                    backend._update_plan_preview_in_xml(xml_path, scenario_for_plan, plan_payload)
            except Exception:
                pass
        try:
            if flow_enabled and scenario_for_plan:
                def _flow_assignments_have_runtime(flag_assignments: list[dict[str, Any]] | None) -> bool:
                    if not isinstance(flag_assignments, list) or not flag_assignments:
                        return False
                    for assignment in flag_assignments:
                        if not isinstance(assignment, dict):
                            continue
                        flag_val = str(assignment.get('flag_value') or '').strip()
                        outputs = assignment.get('resolved_outputs') if isinstance(assignment.get('resolved_outputs'), dict) else None
                        has_any_outputs = bool(isinstance(outputs, dict) and outputs)
                        if not flag_val and isinstance(outputs, dict):
                            flag_val = str(outputs.get('Flag(flag_id)') or outputs.get('flag') or '').strip()
                        if flag_val:
                            return True
                        if has_any_outputs:
                            return True
                        if str(assignment.get('artifacts_dir') or assignment.get('run_dir') or '').strip():
                            return True
                    return False

                flow_state_xml = None
                try:
                    flow_state_xml = backend._flow_state_from_xml_path(xml_path, scenario_for_plan)
                    if not isinstance(flow_state_xml, dict):
                        flow_state_xml = backend._flow_state_from_xml_path(xml_path, None)
                except Exception:
                    flow_state_xml = None
                flag_assignments = flow_state_xml.get('flag_assignments') if isinstance(flow_state_xml, dict) and isinstance(flow_state_xml.get('flag_assignments'), list) else None
                if (not isinstance(flag_assignments, list)) or (not flag_assignments) or (not _flow_assignments_have_runtime(flag_assignments)):
                    return jsonify({'error': 'Flow is enabled, but XML has no resolved Flow runtime values. Run Generate (resolve) and Save XML before Execute.'}), 422
                flow_remote_expected = False
                try:
                    history = backend._load_run_history()
                    scenario_label = scenario_for_plan or scenario_name_hint or ''
                    selected_cfg = backend._select_core_config_for_page(backend._normalize_scenario_label(str(scenario_label or '')), history, include_password=True)
                    if isinstance(selected_cfg, dict) and backend._coerce_bool(selected_cfg.get('ssh_enabled')):
                        flow_remote_expected = True
                except Exception:
                    flow_remote_expected = False
                missing_values: list[dict[str, Any]] = []
                missing_flow_paths: list[dict[str, Any]] = []
                seen_missing_flow_paths: set[tuple[str, str, str]] = set()
                for idx, assignment in enumerate(flag_assignments or []):
                    if not isinstance(assignment, dict):
                        continue
                    gen_id = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
                    node_id = str(assignment.get('node_id') or '').strip()
                    outputs = assignment.get('resolved_outputs') if isinstance(assignment.get('resolved_outputs'), dict) else None
                    flag_val = str(assignment.get('flag_value') or '').strip()
                    if not flag_val and isinstance(outputs, dict):
                        try:
                            flag_val = str(outputs.get('Flag(flag_id)') or outputs.get('flag') or '').strip()
                        except Exception:
                            flag_val = ''
                    artifacts_dir = str(assignment.get('artifacts_dir') or assignment.get('run_dir') or '').strip()
                    has_outputs = False
                    if artifacts_dir:
                        try:
                            if not flow_remote_expected:
                                has_outputs = bool(backend._flow_read_outputs_map_from_artifacts_dir(artifacts_dir))
                            else:
                                has_outputs = True
                        except Exception:
                            has_outputs = False
                    if (not has_outputs) and isinstance(outputs, dict) and outputs:
                        has_outputs = True
                    if not flag_val and not has_outputs:
                        missing_values.append({'index': idx, 'node_id': node_id, 'generator_id': gen_id, 'reason': 'missing flag outputs'})
                    elif artifacts_dir and (not flow_remote_expected) and (not os.path.isdir(artifacts_dir)):
                        missing_values.append({'index': idx, 'node_id': node_id, 'generator_id': gen_id, 'reason': 'artifacts_dir missing', 'artifacts_dir': artifacts_dir})

                    def _add_missing_flow_path(path_type: str, path_value: str) -> None:
                        p = str(path_value or '').strip()
                        if not p or not os.path.isabs(p):
                            return
                        if flow_remote_expected:
                            return
                        if os.path.exists(p):
                            return
                        key = (str(idx), path_type, p)
                        if key in seen_missing_flow_paths:
                            return
                        seen_missing_flow_paths.add(key)
                        missing_flow_paths.append({'index': idx, 'node_id': node_id, 'generator_id': gen_id, 'reason': f'missing {path_type}', 'path_type': path_type, 'path': p})

                    def _inject_source_for_precheck(inject_value: Any) -> str:
                        text = str(inject_value or '').strip()
                        if not text:
                            return ''
                        for sep in ('->', '=>'):
                            if sep in text:
                                text = text.split(sep, 1)[0].strip()
                                break
                        return text

                    _add_missing_flow_path('artifacts_dir', str(assignment.get('artifacts_dir') or assignment.get('run_dir') or '').strip())
                    inject_files = assignment.get('inject_files') if isinstance(assignment.get('inject_files'), list) else []
                    for inject_raw in inject_files:
                        _add_missing_flow_path('inject_source', _inject_source_for_precheck(inject_raw))
                if missing_values or missing_flow_paths:
                    details = list(missing_values)
                    details.extend(missing_flow_paths)
                    return jsonify({'error': 'Execute requires pre-generated Flow values. Run Generate (with resolve) first.', 'details': details}), 422
        except Exception:
            pass
        try:
            if flow_enabled and preview_plan_path and scenario_for_plan:
                plan_payload = backend._load_preview_payload_from_path(preview_plan_path, scenario_for_plan)
                if not isinstance(plan_payload, dict):
                    raise ValueError('preview plan not embedded in XML')
                preview = plan_payload.get('full_preview') if isinstance(plan_payload, dict) else None
                docker_count = 0
                vuln_count = 0
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
                            if role == 'docker':
                                docker_count += 1
                            vulns = host.get('vulnerabilities') if isinstance(host.get('vulnerabilities'), list) else []
                            if vulns:
                                vuln_count += 1
                    vuln_by_node = preview.get('vulnerabilities_by_node') if isinstance(preview.get('vulnerabilities_by_node'), dict) else None
                    if isinstance(vuln_by_node, dict):
                        vuln_count = max(vuln_count, len([key for key, value in vuln_by_node.items() if value]))
                if (docker_count <= 0) and (vuln_count <= 0):
                    flow_enabled = False
                    preview_plan_path = None
                    flow_disabled_reason = (
                        'Flag sequencing disabled for this execute run: '
                        f'Docker nodes={docker_count}, vulnerability nodes={vuln_count}'
                    )
        except Exception:
            pass
        try:
            if preview_plan_path:
                flow_summary, flow_meta = backend._summary_from_preview_plan_path(preview_plan_path, scenario_for_plan)
                xml_summary, xml_seed = backend._summary_from_xml_plan(xml_path, scenario_for_plan, seed)
                diffs = backend._diff_plan_summaries(flow_summary, xml_summary)
                if diffs:
                    diff_lines = []
                    for entry in diffs:
                        field = entry.get('field')
                        diff_lines.append(f"{field}: flow={entry.get('flow')} xml={entry.get('xml')}")
                    detail_text = '\n'.join(diff_lines)
                    flow_scenario = None
                    try:
                        flow_scenario = (flow_meta or {}).get('scenario')
                        if not flow_scenario and isinstance((flow_meta or {}).get('flow'), dict):
                            flow_scenario = (flow_meta or {}).get('flow', {}).get('scenario')
                    except Exception:
                        flow_scenario = None
                    return jsonify({
                        'error': 'Flow/preview plan mismatch with XML-derived plan.',
                        'detail': detail_text,
                        'mismatch': {
                            'comparison': {'mode': 'canonicalized_json_keys', 'policy_fields': ['r2r_policy', 'r2s_policy']},
                            'plan_path': preview_plan_path,
                            'plan_scenario': flow_scenario,
                            'xml_path': xml_path,
                            'xml_scenario': scenario_for_plan,
                            'xml_seed': xml_seed,
                            'differences': diffs,
                        },
                    }), 409
        except Exception as exc:
            msg = str(exc or '')
            if 'preview plan not embedded' not in msg.lower():
                return jsonify({'error': f'Failed to validate flow/preview plan vs XML: {exc}'}), 500

        run_id = str(uuid_module.uuid4())
        job_spec = {
            'seed': seed,
            'xml_path': xml_path,
            'preview_plan_path': preview_plan_path,
            'core_override': core_override,
            'scenario_core_override': scenario_core_override,
            'scenario_name_hint': scenario_name_hint,
            'scenario_index_hint': scenario_index_hint,
            'update_remote_repo': True,
            'adv_fix_docker_daemon': adv_fix_docker_daemon,
            'adv_run_core_cleanup': adv_run_core_cleanup,
            'adv_check_core_version': adv_check_core_version,
            'adv_restart_core_daemon': adv_restart_core_daemon,
            'adv_start_core_daemon': adv_start_core_daemon,
            'adv_auto_kill_sessions': adv_auto_kill_sessions,
            'docker_remove_conflicts': docker_remove_conflicts,
            'docker_cleanup_before_run': docker_cleanup_before_run,
            'docker_remove_all_containers': docker_remove_all_containers,
            'overwrite_existing_images': overwrite_existing_images,
            'upload_only_injected_artifacts': False,
            'scenarios_inline': scenarios_inline,
            'flow_enabled': flow_enabled,
            'scenario_for_plan': scenario_for_plan,
        }
        out_dir = backend._outputs_dir()
        if xml_path:
            out_dir = os.path.dirname(xml_path)
        log_path = os.path.join(out_dir, f'cli-{run_id}.log')
        backend.RUNS[run_id] = {
            'status': 'initializing',
            'submit_time': time.time(),
            'pid': None,
            'cmd': 'remote-cli',
            'done': False,
            'returncode': None,
            'log_path': log_path,
            'xml_path': xml_path,
            'preview_plan': preview_plan_path,
            'scenario': scenario_name_hint,
            'flow_enabled': bool(flow_enabled),
            'flow_disabled_reason': flow_disabled_reason,
        }
        thread = threading_module.Thread(target=backend._run_cli_background_task, args=(run_id, job_spec), daemon=True)
        thread.start()
        app.logger.info('[async] Spawning background CLI task for run_id=%s', run_id)
        response_payload = {
            'run_id': run_id,
            'status': 'initializing',
            'log_url': f"/outputs/{os.path.basename(os.path.dirname(log_path))}/{os.path.basename(log_path)}" if log_path else None,
        }
        if flow_disabled_reason:
            response_payload['warning'] = flow_disabled_reason
        return jsonify(response_payload), 202

    app.add_url_rule('/', endpoint='index', view_func=_index, methods=['GET'])
    app.add_url_rule('/run_cli', endpoint='run_cli', view_func=_run_cli, methods=['POST'])
    app.add_url_rule('/run_cli_async', endpoint='run_cli_async', view_func=_run_cli_async, methods=['POST'])

    mark_routes_registered(app, 'app_entry_routes')
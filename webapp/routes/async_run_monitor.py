from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable

from flask import Response, jsonify, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    runs_store: dict[str, dict[str, Any]],
    maybe_copy_flow_artifacts_into_containers: Callable[..., None],
    sync_remote_artifacts: Callable[[dict[str, Any]], None],
    scenario_names_from_xml: Callable[[str], list[str]],
    extract_report_path_from_text: Callable[[str], str | None],
    find_latest_report_path: Callable[[], str | None],
    extract_summary_path_from_text: Callable[[str], str | None],
    derive_summary_from_report: Callable[[str | None], str | None],
    find_latest_summary_path: Callable[[], str | None],
    outputs_dir: Callable[[], str],
    extract_session_id_from_text: Callable[[str], Any],
    record_session_mapping: Callable[..., None],
    write_remote_session_scenario_meta: Callable[..., None],
    normalize_core_config: Callable[..., dict[str, Any]],
    load_run_history: Callable[[], list[dict]],
    select_core_config_for_page: Callable[..., dict[str, Any]],
    merge_core_configs: Callable[..., dict[str, Any]],
    apply_core_secret_to_config: Callable[[dict[str, Any], str], dict[str, Any]],
    grpc_save_current_session_xml_with_config: Callable[..., str | None],
    append_async_run_log_line: Callable[[dict[str, Any], str], None],
    append_session_scenario_discrepancies: Callable[..., None],
    validate_session_nodes_and_injects: Callable[..., dict[str, Any]],
    coerce_bool: Callable[[Any], bool],
    extract_async_error_from_text: Callable[[str], str | None],
    persist_execute_validation_artifacts: Callable[..., None],
    write_single_scenario_xml: Callable[..., str | None],
    build_full_scenario_archive: Callable[..., str | None],
    append_run_history: Callable[[dict[str, Any]], bool],
    local_timestamp_display: Callable[[], str],
    close_async_run_tunnel: Callable[[dict[str, Any]], None],
    cleanup_remote_workspace: Callable[[dict[str, Any]], None],
    extract_docker_conflicts_from_text: Callable[[str], list[Any]],
    build_execute_error_logs: Callable[..., list[dict[str, Any]]],
    normalize_core_config_public: Callable[[dict[str, Any]], dict[str, Any]],
    sse_marker_prefix: str,
    download_report_endpoint: str,
) -> None:
    if not begin_route_registration(app, 'async_run_monitor_routes'):
        return

    def _run_status_view(run_id: str):
        meta = runs_store.get(run_id)
        if not meta:
            return jsonify({'error': 'not found'}), 404
        proc = meta.get('proc')
        rc = meta.get('returncode')
        if proc and rc is None:
            polled = proc.poll()
            if polled is not None:
                rc = polled
                meta['returncode'] = rc
                try:
                    maybe_copy_flow_artifacts_into_containers(meta, stage='postrun')
                except Exception:
                    pass
                try:
                    sync_remote_artifacts(meta)
                except Exception:
                    pass
                meta['done'] = True
        if meta.get('done') and rc is not None and not meta.get('history_added'):
            try:
                active_scenario_name = None
                try:
                    sns = meta.get('scenario_names') or []
                    if isinstance(sns, list) and sns:
                        active_scenario_name = sns[0]
                except Exception:
                    active_scenario_name = None
                xml_path_local = meta.get('xml_path')
                if not active_scenario_name and xml_path_local:
                    try:
                        names_from_xml = scenario_names_from_xml(xml_path_local)
                        if isinstance(names_from_xml, list) and names_from_xml:
                            active_scenario_name = names_from_xml[0]
                            try:
                                meta['scenario_names'] = names_from_xml
                            except Exception:
                                pass
                    except Exception:
                        active_scenario_name = None
                report_md = None
                txt = ''
                try:
                    lp = meta.get('log_path')
                    if lp and os.path.exists(lp):
                        with open(lp, 'r', encoding='utf-8', errors='ignore') as handle:
                            txt = handle.read()
                        report_md = extract_report_path_from_text(txt)
                except Exception:
                    report_md = None
                if not report_md:
                    report_md = find_latest_report_path()
                if report_md:
                    app.logger.info('[async] Detected report path: %s', report_md)
                summary_json = extract_summary_path_from_text(txt)
                if not summary_json:
                    summary_json = derive_summary_from_report(report_md)
                if not summary_json and not report_md:
                    summary_json = find_latest_summary_path()
                if summary_json and not os.path.exists(summary_json):
                    summary_json = None
                if summary_json:
                    meta['summary_path'] = summary_json
                    app.logger.info('[async] Detected summary path: %s', summary_json)
                post_saved = None
                try:
                    out_dir = os.path.dirname(xml_path_local or '')
                    post_dir = os.path.join(out_dir, 'core-post') if out_dir else os.path.join(outputs_dir(), 'core-post')
                    sid = extract_session_id_from_text(txt)
                    if sid:
                        app.logger.info('[async] Extracted session ID: %s', sid)
                    else:
                        app.logger.warning('[async] Could not extract session ID from logs')
                    scenario_label = meta.get('scenario_name') or active_scenario_name
                    if not scenario_label:
                        try:
                            sns_meta = meta.get('scenario_names') or []
                            if isinstance(sns_meta, list) and sns_meta:
                                scenario_label = sns_meta[0]
                        except Exception:
                            scenario_label = None
                    if sid:
                        record_session_mapping(xml_path_local, sid, scenario_label)
                        try:
                            sid_int = int(str(sid).strip())
                            cfg_for_meta = meta.get('core_cfg') if isinstance(meta.get('core_cfg'), dict) else None
                            if cfg_for_meta:
                                write_remote_session_scenario_meta(
                                    cfg_for_meta,
                                    session_id=sid_int,
                                    scenario_name=scenario_label,
                                    scenario_xml_basename=os.path.basename(xml_path_local or '') or None,
                                    logger=app.logger,
                                )
                        except Exception:
                            pass
                    cfg_for_post = meta.get('core_cfg') or {
                        'host': meta.get('core_host'),
                        'port': meta.get('core_port'),
                    }
                    try:
                        cfg_for_post = normalize_core_config(cfg_for_post, include_password=True)
                    except Exception:
                        cfg_for_post = cfg_for_post or {}
                    try:
                        ssh_user_present = str((cfg_for_post or {}).get('ssh_username') or '').strip()
                    except Exception:
                        ssh_user_present = ''
                    if not ssh_user_present:
                        try:
                            history_for_post = load_run_history()
                            scenario_for_post = None
                            try:
                                scenario_for_post = scenario_label or meta.get('scenario_name')
                            except Exception:
                                scenario_for_post = None
                            scenario_norm_for_post = ''
                            if scenario_for_post:
                                scenario_norm_for_post = str(scenario_for_post).strip().lower().replace(' ', '-')
                            if scenario_norm_for_post:
                                cfg_from_history = select_core_config_for_page(
                                    scenario_norm_for_post,
                                    history_for_post,
                                    include_password=True,
                                )
                                if isinstance(cfg_from_history, dict) and cfg_from_history:
                                    cfg_for_post = merge_core_configs(
                                        cfg_from_history,
                                        cfg_for_post,
                                        include_password=True,
                                    )
                                    try:
                                        recovered_user = str((cfg_for_post or {}).get('ssh_username') or '').strip()
                                    except Exception:
                                        recovered_user = ''
                                    if recovered_user:
                                        app.logger.info(
                                            '[async] recovered core ssh_username from saved scenario config for post-run save_xml (scenario=%s)',
                                            scenario_for_post,
                                        )
                        except Exception:
                            pass
                    try:
                        scenario_for_post = str(scenario_label or meta.get('scenario_name') or '').strip()
                    except Exception:
                        scenario_for_post = ''
                    if scenario_for_post and isinstance(cfg_for_post, dict):
                        try:
                            cfg_for_post = apply_core_secret_to_config(cfg_for_post, scenario_for_post.lower().replace(' ', '-'))
                        except Exception:
                            pass
                    post_saved = grpc_save_current_session_xml_with_config(cfg_for_post, post_dir, session_id=sid)
                except Exception:
                    post_saved = None
                if post_saved:
                    meta['post_xml_path'] = post_saved
                    app.logger.debug('[async] Post-run session XML saved to %s', post_saved)
                else:
                    try:
                        rc_int = int(rc) if rc is not None else None
                        if rc_int is None or rc_int == 0:
                            append_async_run_log_line(meta, '[validate] WARNING: post-run session XML missing; skipping validation')
                    except Exception:
                        pass
                try:
                    append_session_scenario_discrepancies(
                        report_md,
                        xml_path_local,
                        post_saved,
                        scenario_label=scenario_label,
                    )
                except Exception:
                    pass
                try:
                    rc_int = int(rc) if rc is not None else None
                    if rc_int is not None and rc_int == 0 and not post_saved:
                        core_cfg_for_reason = meta.get('core_cfg') if isinstance(meta.get('core_cfg'), dict) else {}
                        runtime_cfg = cfg_for_post if isinstance(cfg_for_post, dict) else core_cfg_for_reason
                        ssh_user = str((runtime_cfg or {}).get('ssh_username') or '').strip()
                        ssh_pass = str((runtime_cfg or {}).get('ssh_password') or '').strip()
                        ssh_secret = str((runtime_cfg or {}).get('ssh_password_secret_id') or '').strip()
                        host_for_reason = str((runtime_cfg or {}).get('host') or meta.get('core_host') or '').strip()
                        port_for_reason = str((runtime_cfg or {}).get('port') or meta.get('core_port') or '').strip()
                        sid_for_reason = str(sid).strip() if sid is not None else ''
                        reason = (
                            'post-run session XML unavailable; execute validation could not inspect session '
                            'nodes/containers (CORE VM export failed with current run-time connection or credentials)'
                        )
                        unavailable_details = [
                            f"scenario={str(scenario_label or meta.get('scenario_name') or '').strip() or 'unknown'}",
                            f'session_id_detected={sid_for_reason or "none"}',
                            f'core_endpoint={host_for_reason or "unknown"}:{port_for_reason or "unknown"}',
                            f'runtime_has_ssh_username={"yes" if bool(ssh_user) else "no"}',
                            f'runtime_has_ssh_password_or_secret={"yes" if bool(ssh_pass or ssh_secret) else "no"}',
                            'check that CORE credentials are saved on this scenario and reachable from the server runtime',
                        ]
                        validation = validate_session_nodes_and_injects(
                            scenario_xml_path=xml_path_local,
                            session_xml_path=None,
                            core_cfg=core_cfg_for_reason,
                            preview_plan_path=meta.get('preview_plan_path'),
                            scenario_label=scenario_label,
                            flow_enabled=coerce_bool(meta.get('flow_enabled')),
                        )
                        if not isinstance(validation, dict):
                            validation = {'ok': False}
                        validation['ok'] = False
                        validation['error'] = reason
                        validation['validation_unavailable'] = True
                        validation['validation_unavailable_details'] = unavailable_details
                        validation['missing_nodes'] = []
                        validation['missing_node_ids'] = []
                        validation['extra_nodes'] = []
                        validation['extra_node_ids'] = []
                        validation['missing_docker_nodes'] = []
                        validation['extra_docker_nodes'] = []
                        validation['missing_vuln_nodes'] = []
                        validation['docker_missing'] = []
                        validation['docker_not_running'] = []
                        validation['injects_missing'] = []
                        validation['generator_outputs_missing'] = []
                        validation['generator_injects_missing'] = []
                        meta['validation_summary'] = validation
                        append_async_run_log_line(meta, f'[validate] SKIP: {reason}')
                    elif rc_int is not None and rc_int != 0 and not post_saved:
                        async_error = extract_async_error_from_text(txt) or 'execute failed before session validation'
                        validation = validate_session_nodes_and_injects(
                            scenario_xml_path=xml_path_local,
                            session_xml_path=None,
                            core_cfg=meta.get('core_cfg') if isinstance(meta.get('core_cfg'), dict) else None,
                            preview_plan_path=meta.get('preview_plan_path'),
                            scenario_label=scenario_label,
                            flow_enabled=coerce_bool(meta.get('flow_enabled')),
                        )
                        if not isinstance(validation, dict):
                            validation = {'ok': False}
                        validation['ok'] = False
                        validation['error'] = async_error
                        meta['validation_summary'] = validation
                        append_async_run_log_line(meta, f'[validate] SKIP: {async_error}')
                    else:
                        append_async_run_log_line(meta, '[validate] Starting session validation')
                        validation = validate_session_nodes_and_injects(
                            scenario_xml_path=xml_path_local,
                            session_xml_path=post_saved,
                            core_cfg=meta.get('core_cfg') if isinstance(meta.get('core_cfg'), dict) else None,
                            preview_plan_path=meta.get('preview_plan_path'),
                            scenario_label=scenario_label,
                            flow_enabled=coerce_bool(meta.get('flow_enabled')),
                        )
                        meta['validation_summary'] = validation
                        append_async_run_log_line(meta, '[validate] VALIDATION_SUMMARY_JSON: ' + json.dumps(validation))
                        persist_execute_validation_artifacts(report_md, summary_json, validation)
                        if validation.get('ok'):
                            append_async_run_log_line(meta, '[validate] Nodes created; containers running; injects present.')
                        else:
                            append_async_run_log_line(
                                meta,
                                '[validate] WARNING: issues detected: '
                                f"missing_nodes={len(validation.get('missing_nodes') or [])}, "
                                f"docker_missing={len(validation.get('docker_missing') or [])}, "
                                f"docker_not_running={len(validation.get('docker_not_running') or [])}, "
                                f"injects_missing={len(validation.get('injects_missing') or [])}"
                            )
                except Exception:
                    pass
                single_xml = None
                try:
                    single_xml = write_single_scenario_xml(xml_path_local, active_scenario_name, out_dir=os.path.dirname(xml_path_local or ''))
                except Exception:
                    single_xml = None
                bundle_xml = single_xml or xml_path_local
                full_bundle = build_full_scenario_archive(
                    os.path.dirname(bundle_xml or ''),
                    bundle_xml,
                    report_md if (report_md and os.path.exists(report_md)) else None,
                    meta.get('pre_xml_path'),
                    post_saved,
                    summary_path=summary_json,
                    run_id=run_id,
                )
                if full_bundle:
                    meta['full_scenario_path'] = full_bundle
                session_xml_path = post_saved if (post_saved and os.path.exists(post_saved)) else None
                history_ok = append_run_history({
                    'timestamp': local_timestamp_display(),
                    'mode': 'async',
                    'xml_path': xml_path_local,
                    'post_xml_path': session_xml_path,
                    'session_xml_path': session_xml_path,
                    'scenario_xml_path': xml_path_local,
                    'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
                    'summary_path': summary_json if (summary_json and os.path.exists(summary_json)) else None,
                    'pre_xml_path': meta.get('pre_xml_path'),
                    'full_scenario_path': full_bundle,
                    'single_scenario_xml_path': single_xml,
                    'returncode': rc,
                    'run_id': run_id,
                    'scenario_names': meta.get('scenario_names') or [],
                    'scenario_name': meta.get('scenario_name') or active_scenario_name,
                    'preview_plan_path': meta.get('preview_plan_path'),
                    'core': meta.get('core_cfg_public') or normalize_core_config_public(meta.get('core_cfg') or {}),
                    'scenario_core': meta.get('scenario_core'),
                    'validation_summary': meta.get('validation_summary') if isinstance(meta.get('validation_summary'), dict) else None,
                })
            except Exception as exc:
                try:
                    app.logger.exception('[async] failed appending run history: %s', exc)
                except Exception:
                    pass
            finally:
                if 'history_ok' in locals() and history_ok:
                    meta['history_added'] = True
                close_async_run_tunnel(meta)
                try:
                    cleanup_remote_workspace(meta)
                except Exception:
                    pass
        if meta.get('done'):
            try:
                sync_remote_artifacts(meta)
            except Exception:
                pass
        xml_path = meta.get('xml_path', '')
        report_md = None
        txt = ''
        try:
            lp = meta.get('log_path')
            if lp and os.path.exists(lp):
                with open(lp, 'r', encoding='utf-8', errors='ignore') as handle:
                    txt = handle.read()
                report_md = extract_report_path_from_text(txt)
        except Exception:
            report_md = None
        docker_conflicts = extract_docker_conflicts_from_text(txt)
        summary_json = extract_summary_path_from_text(txt)
        if summary_json and not os.path.exists(summary_json):
            summary_json = None
        if summary_json:
            meta['summary_path'] = summary_json
        if meta.get('done'):
            try:
                if meta.get('validation_summary') is None:
                    meta['validation_summary'] = {
                        'ok': False,
                        'error': 'validation summary unavailable or incomplete; refusing fallback',
                    }
            except Exception:
                pass
        if meta.get('done') and isinstance(meta.get('validation_summary'), dict):
            try:
                val = meta.get('validation_summary') if isinstance(meta.get('validation_summary'), dict) else {}
                links_cached = meta.get('validation_error_logs') if isinstance(meta.get('validation_error_logs'), list) else None
                if links_cached is None:
                    raw_logs = build_execute_error_logs(
                        run_id=run_id,
                        validation=val,
                        main_log_path=meta.get('log_path'),
                    )
                    links: list[dict[str, str]] = []
                    for entry in raw_logs:
                        if not isinstance(entry, dict):
                            continue
                        path_value = str(entry.get('path') or '').strip()
                        if not path_value:
                            continue
                        links.append({
                            'key': str(entry.get('key') or '').strip(),
                            'label': str(entry.get('label') or '').strip() or 'Download log',
                            'path': path_value,
                            'url': url_for(download_report_endpoint, path=path_value),
                        })
                    meta['validation_error_logs'] = links
                if isinstance(meta.get('validation_error_logs'), list):
                    val['error_logs'] = meta.get('validation_error_logs')
                    meta['validation_summary'] = val
            except Exception:
                pass
        return jsonify({
            'done': bool(meta.get('done')),
            'returncode': meta.get('returncode'),
            'error': meta.get('error'),
            'error_detail': meta.get('error_detail'),
            'error_code': meta.get('error_code'),
            'daemon_conflict': bool(meta.get('daemon_conflict')),
            'daemon_pids': meta.get('daemon_pids') if isinstance(meta.get('daemon_pids'), list) else [],
            'can_stop_daemons': False if meta.get('can_stop_daemons') is False else True,
            'docker_conflicts': docker_conflicts,
            'validation_summary': meta.get('validation_summary'),
            'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
            'summary_path': summary_json if (summary_json and os.path.exists(summary_json)) else None,
            'xml_path': meta.get('post_xml_path') if meta.get('post_xml_path') and os.path.exists(meta.get('post_xml_path')) else None,
            'log_path': meta.get('log_path'),
            'scenario_xml_path': xml_path,
            'pre_xml_path': meta.get('pre_xml_path'),
            'full_scenario_path': (lambda path: path if (path and os.path.exists(path)) else None)(meta.get('full_scenario_path')),
            'core': meta.get('core_cfg_public') or normalize_core_config_public(meta.get('core_cfg') or {}),
            'forward_host': meta.get('forward_host'),
            'forward_port': meta.get('forward_port'),
        })

    def _stream_logs_view(run_id: str):
        meta = runs_store.get(run_id)
        if not meta:
            return Response(
                'event: error\ndata: not found\n\n'
                'event: end\ndata: not found\n\n',
                mimetype='text/event-stream',
                status=404,
            )
        log_path = meta.get('log_path') if isinstance(meta, dict) else None
        if not isinstance(log_path, str) or not log_path:
            try:
                if isinstance(meta, dict):
                    meta['done'] = True
                    meta.setdefault('returncode', 1)
            except Exception:
                pass
            return Response(
                'event: error\ndata: missing log_path\n\n'
                'event: end\ndata: error\n\n',
                mimetype='text/event-stream',
                status=500,
            )

        marker_re = re.compile(
            r'^' + re.escape(sse_marker_prefix) + r'\s+(?P<event>[a-zA-Z0-9_\-]+)\s+(?P<data>\{.*\})\s*$'
        )

        def _emit_line(line: str):
            try:
                match = marker_re.match(line or '')
                if match:
                    yield f"event: {match.group('event')}\n"
                    yield f"data: {match.group('data')}\n\n"
                    return
            except Exception:
                pass
            yield f'data: {line}\n\n'

        def generate():
            last_pos = 0
            last_emit_ts = time.time()
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
                    backlog = handle.read()
                    last_pos = handle.tell()
                if backlog:
                    for line in backlog.splitlines():
                        for payload in _emit_line(line):
                            yield payload
                        last_emit_ts = time.time()
            except FileNotFoundError:
                pass
            while True:
                try:
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
                        handle.seek(last_pos)
                        chunk = handle.read()
                        if chunk:
                            last_pos = handle.tell()
                            for line in chunk.splitlines():
                                for payload in _emit_line(line):
                                    yield payload
                                last_emit_ts = time.time()
                except FileNotFoundError:
                    pass
                proc = meta.get('proc')
                if proc:
                    rc = proc.poll()
                    if rc is not None and meta.get('returncode') is None:
                        meta['returncode'] = rc
                        meta['done'] = True
                if meta.get('done'):
                    try:
                        with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
                            handle.seek(last_pos)
                            tail = handle.read()
                            if tail:
                                last_pos = handle.tell()
                                for line in tail.splitlines():
                                    for payload in _emit_line(line):
                                        yield payload
                                    last_emit_ts = time.time()
                    except FileNotFoundError:
                        pass
                    yield 'event: end\ndata: done\n\n'
                    break
                if time.time() - last_emit_ts >= 5:
                    yield 'event: ping\ndata: {}\n\n'
                    last_emit_ts = time.time()
                time.sleep(0.5)

        headers = {
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Content-Type': 'text/event-stream',
            'Connection': 'keep-alive',
        }
        return Response(generate(), headers=headers)

    def _cancel_run_view(run_id: str):
        meta = runs_store.get(run_id)
        if not meta:
            return jsonify({'error': 'not found'}), 404
        proc = meta.get('proc')
        try:
            if proc and proc.poll() is None:
                log_path = meta.get('log_path')
                try:
                    with open(log_path, 'a', encoding='utf-8') as handle:
                        handle.write('\n== Run cancelled by user ==\n')
                except Exception:
                    pass
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
            meta['done'] = True
            if meta.get('returncode') is None:
                meta['returncode'] = -1
            try:
                cleanup_remote_workspace(meta)
            except Exception:
                pass
            close_async_run_tunnel(meta)
            return jsonify({'ok': True})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    app.add_url_rule('/run_status/<run_id>', endpoint='run_status', view_func=_run_status_view, methods=['GET'])
    app.add_url_rule('/stream/<run_id>', endpoint='stream_logs', view_func=_stream_logs_view, methods=['GET'])
    app.add_url_rule('/cancel_run/<run_id>', endpoint='cancel_run', view_func=_cancel_run_view, methods=['POST'])
    mark_routes_registered(app, 'async_run_monitor_routes')
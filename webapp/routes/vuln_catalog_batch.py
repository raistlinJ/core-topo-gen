from __future__ import annotations

import os
import re
import shutil
from typing import Any

from flask import Response, jsonify, request, send_file

from webapp.routes._registration import begin_route_registration, mark_routes_registered


_VALIDATION_CHECKS: tuple[tuple[str, str], ...] = (
    ('missing_nodes', 'missing nodes'),
    ('docker_not_running', 'docker not running'),
    ('injects_missing', 'missing inject files'),
    ('generator_outputs_missing', 'missing generator outputs'),
    ('generator_injects_missing', 'missing generator inject sources'),
)

_BATCH_LOG_LINE_LIMIT = 500
_ACTIVE_CHILD_TAIL_LIMIT = 18
_RESULT_CHILD_TAIL_LIMIT = 12


def _append_batch_log(meta: dict[str, Any], message: str) -> None:
    if not isinstance(meta, dict):
        return
    lines = meta.get('log_lines')
    if not isinstance(lines, list):
        lines = []
    text = str(message or '').strip()
    if not text:
        return
    lines.append(text)
    if len(lines) > _BATCH_LOG_LINE_LIMIT:
        lines = lines[-_BATCH_LOG_LINE_LIMIT:]
    meta['log_lines'] = lines


def _tail_log_lines(log_path: str, limit: int = 20) -> list[str]:
    path = str(log_path or '').strip()
    if not path:
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
            lines = [str(line).rstrip('\n') for line in handle.readlines()]
    except Exception:
        return []
    trimmed = [line for line in lines if str(line).strip()]
    if limit > 0 and len(trimmed) > limit:
        trimmed = trimmed[-limit:]
    return trimmed


def _active_child_snapshot(backend: Any, meta: dict[str, Any]) -> dict[str, Any] | None:
    child_run_id = str(meta.get('active_child_run_id') or '').strip()
    if not child_run_id:
        return None
    child_meta = backend.RUNS.get(child_run_id)
    if not isinstance(child_meta, dict):
        return {
            'run_id': child_run_id,
            'status': 'missing',
            'done': True,
            'cleanup_started': False,
            'cleanup_done': False,
            'returncode': None,
            'log_tail': [],
        }
    return {
        'run_id': child_run_id,
        'status': str(child_meta.get('status') or ''),
        'done': bool(child_meta.get('done')),
        'cleanup_started': bool(child_meta.get('cleanup_started')),
        'cleanup_done': bool(child_meta.get('cleanup_done')),
        'returncode': child_meta.get('returncode'),
        'log_tail': _tail_log_lines(str(child_meta.get('log_path') or ''), limit=_ACTIVE_CHILD_TAIL_LIMIT),
    }


def _status_log_lines(meta: dict[str, Any], active_child: dict[str, Any] | None) -> list[str]:
    lines = list(meta.get('log_lines') if isinstance(meta.get('log_lines'), list) else [])
    if not isinstance(active_child, dict):
        return lines
    child_status = str(active_child.get('status') or '').strip() or 'unknown'
    child_run_id = str(active_child.get('run_id') or '').strip() or 'unknown'
    child_tail = active_child.get('log_tail') if isinstance(active_child.get('log_tail'), list) else []
    lines.append(f'[child] run {child_run_id} status={child_status}')
    for line in child_tail:
        lines.append(f'[child] {line}')
    if len(lines) > _BATCH_LOG_LINE_LIMIT:
        lines = lines[-_BATCH_LOG_LINE_LIMIT:]
    return lines


def _snapshot_child_log(
    backend: Any,
    batch_meta: dict[str, Any],
    *,
    item_id: int,
    item_name: str,
    child_meta: dict[str, Any] | None,
) -> dict[str, Any]:
    meta = child_meta if isinstance(child_meta, dict) else {}
    log_path = str(meta.get('log_path') or '').strip()
    if not log_path or not os.path.isfile(log_path):
        return {}
    batch_run_id = str(batch_meta.get('run_id') or '').strip() or 'batch'
    safe_name = re.sub(r'[^a-z0-9_.-]+', '-', str(item_name or '').strip().lower()).strip('-') or f'item-{int(item_id or 0)}'
    batch_log_dir = os.path.join(backend._outputs_dir(), 'vuln-batch-logs', batch_run_id)
    os.makedirs(batch_log_dir, exist_ok=True)
    file_name = f'{int(item_id or 0):04d}-{safe_name}.log'
    dest_path = os.path.join(batch_log_dir, file_name)
    try:
        shutil.copy2(log_path, dest_path)
    except Exception:
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as src, open(dest_path, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        except Exception:
            return {}
    return {
        'log_path': dest_path,
        'log_filename': file_name,
        'log_download_url': f'/vuln_catalog_items/batch/item_log?run_id={batch_run_id}&item_id={int(item_id or 0)}',
    }


def _append_child_result_tail(batch_meta: dict[str, Any], item_id: int, child_meta: dict[str, Any] | None) -> None:
    meta = child_meta if isinstance(child_meta, dict) else {}
    log_path = str(meta.get('log_path') or '').strip()
    if not log_path:
        return
    tail = _tail_log_lines(log_path, limit=_RESULT_CHILD_TAIL_LIMIT)
    for line in tail:
        _append_batch_log(batch_meta, f'[item #{int(item_id or 0)}] {line}')


def _result_payload(run_id: str, result: dict[str, Any]) -> dict[str, Any]:
    payload = dict(result or {})
    log_path = str(payload.get('log_path') or '').strip()
    log_filename = str(payload.get('log_filename') or '').strip()
    if log_path and os.path.isfile(log_path):
        if not log_filename:
            log_filename = os.path.basename(log_path)
            payload['log_filename'] = log_filename
        payload['log_available'] = True
        payload['log_download_url'] = str(payload.get('log_download_url') or f'/vuln_catalog_items/batch/item_log?run_id={run_id}&item_id={int(payload.get("item_id") or 0)}')
    else:
        payload.pop('log_download_url', None)
        payload['log_available'] = False
    return payload


def _result_payloads(meta: dict[str, Any]) -> list[dict[str, Any]]:
    run_id = str(meta.get('run_id') or '').strip()
    results = meta.get('results') if isinstance(meta.get('results'), list) else []
    return [_result_payload(run_id, result) for result in results if isinstance(result, dict)]


def _ensure_child_validation_summary(backend: Any, child_meta: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(child_meta, dict):
        return None

    existing = child_meta.get('execute_validation_summary') if isinstance(child_meta.get('execute_validation_summary'), dict) else None
    if existing is None and isinstance(child_meta.get('validation_summary'), dict):
        existing = child_meta.get('validation_summary')
    if isinstance(existing, dict):
        return existing

    try:
        if not child_meta.get('done'):
            return None
    except Exception:
        return None

    log_path = str(child_meta.get('log_path') or '').strip()
    log_text = ''
    if log_path:
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
                log_text = handle.read()
        except Exception:
            log_text = ''

    xml_path = str(child_meta.get('xml_path') or '').strip()
    if not xml_path:
        return None

    scenario_label = str(
        child_meta.get('scenario_name')
        or child_meta.get('test_scenario_tag')
        or ''
    ).strip() or None
    preview_plan_path = str(child_meta.get('preview_plan_path') or '').strip() or None
    core_cfg = child_meta.get('core_cfg') if isinstance(child_meta.get('core_cfg'), dict) else None
    if not isinstance(core_cfg, dict):
        return None

    report_md = None
    summary_json = None
    try:
        backend._sync_remote_artifacts(child_meta)
    except Exception:
        pass
    try:
        report_md = backend._extract_report_path_from_text(log_text)
    except Exception:
        report_md = None
    if not report_md:
        try:
            report_md = backend._find_latest_report_path()
        except Exception:
            report_md = None
    try:
        summary_json = backend._extract_summary_path_from_text(log_text)
    except Exception:
        summary_json = None
    if not summary_json:
        try:
            summary_json = backend._derive_summary_from_report(report_md)
        except Exception:
            summary_json = None

    post_saved = None
    try:
        post_saved = str(child_meta.get('post_xml_path') or child_meta.get('session_xml_path') or '').strip() or None
    except Exception:
        post_saved = None
    if not post_saved and log_text:
        try:
            session_id = backend._extract_session_id_from_text(log_text)
        except Exception:
            session_id = None
        if session_id:
            try:
                post_dir = backend.os.path.join(backend.os.path.dirname(xml_path), 'core-post')
                post_saved = backend._grpc_save_current_session_xml_with_config(core_cfg, post_dir, session_id=session_id)
                if post_saved:
                    child_meta['post_xml_path'] = post_saved
                    child_meta['session_xml_path'] = post_saved
            except Exception:
                post_saved = None

    try:
        if post_saved:
            validation = backend._validate_session_nodes_and_injects(
                scenario_xml_path=xml_path,
                session_xml_path=post_saved,
                core_cfg=core_cfg,
                preview_plan_path=preview_plan_path,
                scenario_label=scenario_label,
                flow_enabled=backend._coerce_bool(child_meta.get('flow_enabled')),
            )
            if isinstance(validation, dict):
                child_meta['validation_summary'] = validation
                child_meta['execute_validation_summary'] = validation
                try:
                    backend._persist_execute_validation_artifacts(report_md, summary_json, validation)
                except Exception:
                    pass
                try:
                    if log_path:
                        backend._append_async_run_log_line(child_meta, '[validate] VALIDATION_SUMMARY_JSON: ' + backend.json.dumps(validation))
                except Exception:
                    pass
                return validation
    except Exception:
        pass

    return None


def _selected_item_label(item: dict[str, Any]) -> str:
    base = str(item.get('name') or item.get('Name') or item.get('Title') or '').strip()
    rel_dir = str(item.get('rel_dir') or item.get('dir_rel') or '').strip().replace('\\', '/')
    if rel_dir and rel_dir not in ('', '.', 'root'):
        parts = [part for part in rel_dir.split('/') if part]
        if len(parts) >= 2:
            return f'{parts[-2]}/{parts[-1]}'
        if parts:
            return parts[-1]
    return base or f"item-{int(item.get('id') or 0)}"


def _item_matches_query(item: dict[str, Any], query: str) -> bool:
    needle = str(query or '').strip().lower()
    if not needle:
        return True
    fields = [
        str(item.get('id') or ''),
        str(item.get('name') or ''),
        str(item.get('Name') or ''),
        str(item.get('Title') or ''),
        str(item.get('from_source') or ''),
        str(item.get('rel_dir') or item.get('dir_rel') or ''),
    ]
    return any(needle in str(value).lower() for value in fields)


def _classify_validation_summary(summary: dict[str, Any] | None) -> list[str]:
    issues: list[str] = []
    if not isinstance(summary, dict):
        return issues
    if summary.get('validation_unavailable') is True:
        issues.append('validation unavailable')
        return issues
    for key, label in _VALIDATION_CHECKS:
        values = summary.get(key)
        count = len(values) if isinstance(values, list) else 0
        if count > 0:
            issues.append(f'{label}: {count}')
    return issues


def _categorize_validation_summary(summary: dict[str, Any] | None) -> list[str]:
    categories: list[str] = []
    if not isinstance(summary, dict):
        return categories
    if summary.get('validation_unavailable') is True:
        categories.append('validation_unavailable')
        return categories
    for key, category in (
        ('missing_nodes', 'core_runtime'),
        ('docker_not_running', 'docker_runtime'),
        ('injects_missing', 'artifact_injection'),
        ('generator_outputs_missing', 'generator_outputs'),
        ('generator_injects_missing', 'generator_injects'),
    ):
        values = summary.get(key)
        if isinstance(values, list) and values:
            categories.append(category)
    return categories


def _categorize_failure(*, async_error: str | None, return_code: int | None, summary: dict[str, Any] | None) -> list[str]:
    categories: list[str] = []
    if async_error:
        lower = async_error.lower()
        if 'active session' in lower or 'core vm has active session' in lower:
            categories.append('core_session_busy')
        elif 'unable to verify core sessions' in lower or 'ssh' in lower:
            categories.append('core_connectivity')
        elif 'docker-compose.yml not found' in lower or 'compose path' in lower:
            categories.append('catalog_compose_invalid')
        else:
            categories.append('execution_error')
    if return_code not in (None, 0):
        categories.append('execute_returncode')
    for category in _categorize_validation_summary(summary):
        if category not in categories:
            categories.append(category)
    if not categories and isinstance(summary, dict):
        categories.append('validation_passed')
    if not categories:
        categories.append('uncategorized')
    return categories


def _collect_category_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        if not isinstance(result, dict):
            continue
        categories = result.get('categories') if isinstance(result.get('categories'), list) else []
        for raw in categories:
            key = str(raw or '').strip()
            if not key:
                continue
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _markdown_report(meta: dict[str, Any]) -> str:
    results = meta.get('results') if isinstance(meta.get('results'), list) else []
    progress = _summarize_batch(meta)
    category_counts = _collect_category_counts(results)
    lines = [
        '# Vulnerability Batch Test Report',
        '',
        f"- Run ID: {str(meta.get('run_id') or '')}",
        f"- Catalog: {str(meta.get('catalog_label') or meta.get('catalog_id') or '')}",
        f"- Status: {str(meta.get('status') or '')}",
        f"- Started: {str(meta.get('started_at') or '')}",
        f"- Finished: {str(meta.get('finished_at') or '')}",
        f"- Scope: {str(meta.get('scope') or '')}",
        f"- Query: {str(meta.get('query') or '')}",
        '',
        '## Progress',
        '',
        f"- Total: {progress.get('total', 0)}",
        f"- Completed: {progress.get('completed', 0)}",
        f"- Passed: {progress.get('passed', 0)}",
        f"- Failed: {progress.get('failed', 0)}",
        f"- Incomplete: {progress.get('incomplete', 0)}",
        f"- Skipped: {progress.get('skipped', 0)}",
        f"- Pending: {progress.get('pending', 0)}",
        '',
        '## Failure Categories',
        '',
    ]
    if category_counts:
        for key, value in category_counts.items():
            lines.append(f'- {key}: {value}')
    else:
        lines.append('- none')
    lines.extend([
        '',
        '## Results',
        '',
        '| # | Item | Status | Categories | Reason |',
        '| --- | --- | --- | --- | --- |',
    ])
    for result in results:
        if not isinstance(result, dict):
            continue
        categories = result.get('categories') if isinstance(result.get('categories'), list) else []
        lines.append(
            '| {item_id} | {item_name} | {status} | {categories} | {reason} |'.format(
                item_id=str(result.get('item_id') or ''),
                item_name=str(result.get('item_name') or '').replace('|', '/'),
                status=str(result.get('status') or ''),
                categories=', '.join(str(cat) for cat in categories) or '-',
                reason=str(result.get('reason') or '').replace('|', '/'),
            )
        )
    return '\n'.join(lines) + '\n'


def _export_payload(meta: dict[str, Any]) -> dict[str, Any]:
    results = _result_payloads(meta)
    return {
        'ok': True,
        'run_id': str(meta.get('run_id') or ''),
        'status': str(meta.get('status') or ''),
        'done': bool(meta.get('done')),
        'catalog': {
            'id': str(meta.get('catalog_id') or ''),
            'label': str(meta.get('catalog_label') or ''),
        },
        'selection': {
            'scope': str(meta.get('scope') or ''),
            'query': str(meta.get('query') or ''),
            'include_disabled': bool(meta.get('include_disabled')),
            'limit': meta.get('limit'),
        },
        'started_at': meta.get('started_at'),
        'finished_at': meta.get('finished_at'),
        'progress': _summarize_batch(meta),
        'category_counts': _collect_category_counts(results),
        'results': results,
        'log_lines': _status_log_lines(meta, None),
    }


def _classify_single_run(backend: Any, child_meta: dict[str, Any] | None) -> dict[str, Any]:
    meta = child_meta if isinstance(child_meta, dict) else {}
    run_id = str(meta.get('run_id') or '')
    log_path = str(meta.get('log_path') or '').strip()
    log_text = ''
    if log_path:
        try:
            with open(log_path, 'r', encoding='utf-8') as file_handle:
                log_text = file_handle.read()
        except Exception:
            log_text = ''

    summary = _ensure_child_validation_summary(backend, meta)
    if summary is None:
        summary = meta.get('execute_validation_summary') if isinstance(meta.get('execute_validation_summary'), dict) else None
    if summary is None and isinstance(meta.get('validation_summary'), dict):
        summary = meta.get('validation_summary')
    if summary is None and log_text:
        try:
            summary = backend._extract_validation_summary_from_text(log_text)
        except Exception:
            summary = None
    async_error = None
    if log_text:
        try:
            async_error = backend._extract_async_error_from_text(log_text)
        except Exception:
            async_error = None
    try:
        meta['execute_validation_summary'] = summary
    except Exception:
        pass
    try:
        if isinstance(summary, dict):
            meta['validation_summary'] = summary
    except Exception:
        pass

    if async_error:
        return {
            'status': 'failed',
            'reason': async_error,
            'categories': _categorize_failure(async_error=async_error, return_code=meta.get('returncode'), summary=summary),
            'run_id': run_id,
            'returncode': meta.get('returncode'),
            'validation_summary': summary,
        }

    return_code = meta.get('returncode')
    try:
        numeric_return_code = int(return_code)
    except Exception:
        numeric_return_code = None

    issues = _classify_validation_summary(summary)
    if numeric_return_code not in (None, 0):
        reason = f'execute returncode={numeric_return_code}'
        if issues:
            reason = f'{reason}; ' + '; '.join(issues)
        return {
            'status': 'failed',
            'reason': reason,
            'categories': _categorize_failure(async_error=None, return_code=numeric_return_code, summary=summary),
            'run_id': run_id,
            'returncode': numeric_return_code,
            'validation_summary': summary,
        }

    if issues:
        return {
            'status': 'failed',
            'reason': '; '.join(issues),
            'categories': _categorize_failure(async_error=None, return_code=numeric_return_code, summary=summary),
            'run_id': run_id,
            'returncode': numeric_return_code,
            'validation_summary': summary,
        }

    if not isinstance(summary, dict):
        return {
            'status': 'incomplete',
            'reason': 'run finished without validation summary',
            'categories': ['validation_missing'],
            'run_id': run_id,
            'returncode': numeric_return_code,
            'validation_summary': None,
        }

    return {
        'status': 'passed',
        'reason': 'runtime validation passed',
        'categories': _categorize_failure(async_error=None, return_code=numeric_return_code, summary=summary),
        'run_id': run_id,
        'returncode': numeric_return_code,
        'validation_summary': summary,
    }


def _start_execute_like_real_vuln_test(backend: Any, *, item: dict[str, Any], catalog_id: str, core_payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    item_id = int(item.get('id') or 0)
    if item_id <= 0:
        return {'ok': False, 'error': 'Invalid item id'}, 400

    try:
        compose_path = backend._vuln_catalog_item_abs_compose_path(catalog_id=catalog_id, item=item)
    except Exception as exc:
        return {'ok': False, 'error': f'Invalid compose path: {exc}'}, 400
    if not backend.os.path.isfile(compose_path):
        return {'ok': False, 'error': 'docker-compose.yml not found'}, 404

    try:
        for meta in backend.RUNS.values():
            if isinstance(meta, dict) and meta.get('kind') == 'vuln_test' and not meta.get('done'):
                return {'ok': False, 'error': 'Another vulnerability test is already running'}, 409
    except Exception:
        pass

    try:
        core_cfg = backend._merge_core_configs(core_payload, include_password=True)
        if not core_cfg.get('host'):
            core_cfg['host'] = core_cfg.get('ssh_host') or '127.0.0.1'
        if not core_cfg.get('port'):
            core_cfg['port'] = backend.CORE_PORT
        core_cfg = backend._require_core_ssh_credentials(core_cfg)
    except Exception as exc:
        return {'ok': False, 'error': f'CORE VM SSH config required: {exc}'}, 400

    try:
        errors: list[str] = []
        host = str(core_cfg.get('host') or '127.0.0.1')
        port = int(core_cfg.get('port') or backend.CORE_PORT)
        sessions = backend._list_active_core_sessions(host, port, core_cfg, errors=errors, meta={})
        if errors:
            return {'ok': False, 'error': f'Unable to verify CORE sessions: {errors[0]}'}, 409
        if sessions:
            return {'ok': False, 'error': 'CORE VM has active session(s). Stop running scenario before testing.'}, 409
    except Exception as exc:
        return {'ok': False, 'error': f'Unable to verify CORE sessions: {exc}'}, 409

    run_id = str(backend.uuid.uuid4())[:12]
    run_dir = backend.os.path.join(backend._outputs_dir(), 'vuln-tests', f'test-{run_id}')
    backend.os.makedirs(run_dir, exist_ok=True)
    log_path = backend.os.path.join(run_dir, 'run.log')

    item_name = str(item.get('name') or item.get('Name') or item.get('Title') or f'vuln-{item_id}')
    prepared_compose_path = compose_path
    try:
        from core_topo_gen.utils.vuln_process import prepare_compose_for_assignments

        node_name = f'vuln-test-{item_id}'
        record = {
            'Name': item_name,
            'Path': compose_path,
            'Type': 'docker-compose',
            'ScenarioTag': f'vuln-test-{item_id}',
        }
        created = prepare_compose_for_assignments({node_name: record}, out_base=run_dir)
        if created:
            prepared_compose_path = created[0]
    except Exception:
        prepared_compose_path = compose_path

    job_spec, build_err = backend._vuln_test_build_ephemeral_execute_job(
        run_dir=run_dir,
        run_id=run_id,
        core_cfg=core_cfg,
        item_id=item_id,
        item_name=item_name,
        compose_path=prepared_compose_path,
    )
    if not isinstance(job_spec, dict):
        return {'ok': False, 'error': str(build_err or 'failed to prepare execute-like-real vulnerability test')}, 500

    try:
        with open(log_path, 'a', encoding='utf-8') as log_f:
            log_f.write(f'[vuln-test] starting execute-like-real item_id={item_id}\n')
            backend._write_sse_marker(
                log_f,
                'phase',
                {
                    'phase': 'starting',
                    'run_id': run_id,
                    'item_id': item_id,
                    'execute_like_real': True,
                },
            )
    except Exception:
        pass

    backend.RUNS[run_id] = {
        'kind': 'vuln_test',
        'run_id': run_id,
        'proc': None,
        'log_path': log_path,
        'run_dir': run_dir,
        'xml_path': str(job_spec.get('xml_path') or '').strip(),
        'preview_plan_path': str(job_spec.get('preview_plan_path') or '').strip(),
        'flow_enabled': bool(job_spec.get('flow_enabled')),
        'scenario_name': str(job_spec.get('scenario_name_hint') or job_spec.get('scenario_for_plan') or '').strip(),
        'done': False,
        'returncode': None,
        'status': 'executing',
        'cleanup_started': False,
        'cleanup_done': False,
        'catalog_id': catalog_id,
        'item_id': item_id,
        'core_cfg': core_cfg,
        'cleanup_generated_artifacts': True,
        'execute_like_real': True,
        'compose_path_raw': compose_path,
        'compose_path_prepared': prepared_compose_path,
        'test_docker_node_id': str(job_spec.get('test_docker_node_id') or '').strip(),
        'test_docker_node_name': str(job_spec.get('test_docker_node_name') or '').strip(),
        'test_scenario_tag': str(job_spec.get('test_scenario_tag') or '').strip(),
    }

    try:
        backend.threading.Thread(
            target=backend._run_cli_background_task,
            args=(run_id, job_spec),
            name=f'vuln-test-exec-{run_id[:8]}',
            daemon=True,
        ).start()
    except Exception as exc:
        backend.RUNS.pop(run_id, None)
        return {'ok': False, 'error': f'failed to start execute-like-real vulnerability test: {exc}'}, 500

    return {
        'ok': True,
        'run_id': run_id,
        'execute_like_real': True,
        'cleanup_generated_artifacts': True,
    }, 200


def _summarize_batch(meta: dict[str, Any]) -> dict[str, int]:
    items = meta.get('selected_items') if isinstance(meta.get('selected_items'), list) else []
    total = len(items)
    results = meta.get('results') if isinstance(meta.get('results'), list) else []
    counts = {
        'total': total,
        'completed': len(results),
        'passed': 0,
        'failed': 0,
        'incomplete': 0,
        'skipped': 0,
    }
    for result in results:
        if not isinstance(result, dict):
            continue
        status = str(result.get('status') or '').strip().lower()
        if status in counts:
            counts[status] += 1
    counts['pending'] = max(0, total - counts['completed'])
    return counts


def _request_batch_stop(backend: Any, meta: dict[str, Any]) -> None:
    meta['stop_requested'] = True
    _append_batch_log(meta, '[batch] stop requested')
    active_child_run_id = str(meta.get('active_child_run_id') or '').strip()
    if not active_child_run_id:
        return
    child_meta = backend.RUNS.get(active_child_run_id)
    if not isinstance(child_meta, dict) or child_meta.get('cleanup_started'):
        return
    try:
        backend._stop_vuln_test_meta(child_meta, None)
        meta['active_child_stop_requested'] = True
        _append_batch_log(meta, f'[batch] stopping active test {active_child_run_id}')
    except Exception as exc:
        _append_batch_log(meta, f'[batch] failed to stop active test {active_child_run_id}: {exc}')


def _run_batch(backend: Any, batch_meta: dict[str, Any], core_payload: dict[str, Any]) -> None:
    items = batch_meta.get('selected_items') if isinstance(batch_meta.get('selected_items'), list) else []
    total = len(items)
    batch_meta['status'] = 'running'
    _append_batch_log(batch_meta, f'[batch] queued {total} item(s)')

    for index, item in enumerate(items):
        if batch_meta.get('stop_requested'):
            break
        item_id = int(item.get('id') or 0)
        item_name = _selected_item_label(item)
        batch_meta['active_item_id'] = item_id
        batch_meta['active_item_name'] = item_name
        batch_meta['active_index'] = index + 1
        batch_meta['active_child_run_id'] = None
        batch_meta['active_child_stop_requested'] = False
        _append_batch_log(batch_meta, f'[batch] starting {index + 1}/{total}: #{item_id} {item_name}')

        start_payload, status_code = _start_execute_like_real_vuln_test(
            backend,
            item=item,
            catalog_id=str(batch_meta.get('catalog_id') or ''),
            core_payload=core_payload,
        )
        if status_code != 200 or start_payload.get('ok') is not True:
            reason = str(start_payload.get('error') or f'failed to start (http {status_code})')
            batch_meta.setdefault('results', []).append(
                {
                    'item_id': item_id,
                    'item_name': item_name,
                    'status': 'failed',
                    'reason': reason,
                    'categories': _categorize_failure(async_error=reason, return_code=None, summary=None),
                    'finished_at': backend._local_timestamp_display(),
                }
            )
            _append_batch_log(batch_meta, f'[batch] start failed for #{item_id}: {reason}')
            continue

        child_run_id = str(start_payload.get('run_id') or '').strip()
        batch_meta['active_child_run_id'] = child_run_id
        _append_batch_log(batch_meta, f'[batch] child run {child_run_id} created for #{item_id} {item_name}')
        classification: dict[str, Any] | None = None
        cleanup_requested = False

        while True:
            child_meta = backend.RUNS.get(child_run_id)
            if batch_meta.get('stop_requested') and not cleanup_requested:
                if isinstance(child_meta, dict) and child_meta.get('cleanup_started'):
                    snapshot = _snapshot_child_log(backend, batch_meta, item_id=item_id, item_name=item_name, child_meta=child_meta)
                    cleanup_requested = True
                    classification = {
                        'status': 'incomplete',
                        'reason': 'batch stop requested',
                        'categories': ['batch_stopped'],
                        'run_id': child_run_id,
                        'returncode': child_meta.get('returncode'),
                        'validation_summary': child_meta.get('execute_validation_summary'),
                    }
                    classification.update(snapshot)
                else:
                    try:
                        snapshot = _snapshot_child_log(backend, batch_meta, item_id=item_id, item_name=item_name, child_meta=child_meta)
                        if isinstance(child_meta, dict):
                            backend._stop_vuln_test_meta(child_meta, None)
                        cleanup_requested = True
                        classification = {
                            'status': 'incomplete',
                            'reason': 'batch stop requested',
                            'categories': ['batch_stopped'],
                            'run_id': child_run_id,
                            'returncode': child_meta.get('returncode') if isinstance(child_meta, dict) else None,
                            'validation_summary': child_meta.get('execute_validation_summary') if isinstance(child_meta, dict) else None,
                        }
                        classification.update(snapshot)
                    except Exception as exc:
                        cleanup_requested = True
                        classification = {
                            'status': 'incomplete',
                            'reason': f'batch stop requested; cleanup error: {exc}',
                            'categories': ['batch_stopped', 'cleanup_error'],
                            'run_id': child_run_id,
                            'returncode': child_meta.get('returncode') if isinstance(child_meta, dict) else None,
                            'validation_summary': child_meta.get('execute_validation_summary') if isinstance(child_meta, dict) else None,
                        }
                        if isinstance(child_meta, dict):
                            classification.update(_snapshot_child_log(backend, batch_meta, item_id=item_id, item_name=item_name, child_meta=child_meta))
                    _append_batch_log(batch_meta, f'[batch] stopping #{item_id} {item_name}')

            if isinstance(child_meta, dict) and child_meta.get('done') and not cleanup_requested:
                classification = _classify_single_run(backend, child_meta)
                classification.update(_snapshot_child_log(backend, batch_meta, item_id=item_id, item_name=item_name, child_meta=child_meta))
                _append_child_result_tail(batch_meta, item_id, child_meta)
                result_status = str(classification.get('status') or '').strip().lower()
                user_ok = True if result_status == 'passed' else (False if result_status == 'failed' else None)
                try:
                    backend._stop_vuln_test_meta(child_meta, user_ok)
                except Exception as exc:
                    classification['status'] = 'incomplete'
                    classification['reason'] = f"{classification.get('reason') or 'cleanup error'}; cleanup error: {exc}"
                cleanup_requested = True
                _append_batch_log(batch_meta, f"[batch] finished #{item_id} with {classification.get('status')}: {classification.get('reason')}")

            if cleanup_requested and isinstance(child_meta, dict) and child_meta.get('cleanup_done'):
                break

            if cleanup_requested and not isinstance(child_meta, dict):
                break

            backend.time.sleep(1.0)

        if classification is None:
            classification = {
                'status': 'incomplete',
                'reason': 'test metadata unavailable',
                'categories': ['metadata_missing'],
                'run_id': child_run_id,
                'returncode': None,
                'validation_summary': None,
            }

        batch_meta.setdefault('results', []).append(
            {
                'item_id': item_id,
                'item_name': item_name,
                'status': classification.get('status'),
                'reason': classification.get('reason'),
                'categories': classification.get('categories') if isinstance(classification.get('categories'), list) else [],
                'run_id': classification.get('run_id'),
                'returncode': classification.get('returncode'),
                'validation_summary': classification.get('validation_summary'),
                'log_path': classification.get('log_path'),
                'log_filename': classification.get('log_filename'),
                'log_download_url': classification.get('log_download_url'),
                'finished_at': backend._local_timestamp_display(),
            }
        )
        batch_meta['active_item_id'] = None
        batch_meta['active_item_name'] = None
        batch_meta['active_child_run_id'] = None
        batch_meta['active_child_stop_requested'] = False

    if batch_meta.get('stop_requested'):
        seen_ids = {int(result.get('item_id') or 0) for result in batch_meta.get('results') or [] if isinstance(result, dict)}
        for item in items:
            item_id = int(item.get('id') or 0)
            if item_id in seen_ids:
                continue
            batch_meta.setdefault('results', []).append(
                {
                    'item_id': item_id,
                    'item_name': _selected_item_label(item),
                    'status': 'skipped',
                    'reason': 'batch stop requested',
                    'categories': ['batch_stopped'],
                    'finished_at': backend._local_timestamp_display(),
                }
            )
        batch_meta['status'] = 'stopped'
        _append_batch_log(batch_meta, '[batch] stopped')
    else:
        batch_meta['status'] = 'completed'
        _append_batch_log(batch_meta, '[batch] completed')

    batch_meta['done'] = True
    batch_meta['finished_at'] = backend._local_timestamp_display()


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'vuln_catalog_batch_routes'):
        return

    backend = backend_module

    def _find_batch_meta(run_id: str) -> dict[str, Any] | None:
        target = str(run_id or '').strip()
        if target:
            meta = backend.RUNS.get(target)
            if isinstance(meta, dict) and meta.get('kind') == 'vuln_test_batch':
                return meta
            return None
        active = None
        for candidate in backend.RUNS.values():
            if not isinstance(candidate, dict) or candidate.get('kind') != 'vuln_test_batch':
                continue
            if not candidate.get('done'):
                return candidate
            active = candidate
        return active

    @app.route('/vuln_catalog_items/batch/start', methods=['POST'])
    def vuln_catalog_items_batch_start():
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}

        try:
            for meta in backend.RUNS.values():
                if not isinstance(meta, dict):
                    continue
                if meta.get('kind') in ('vuln_test', 'vuln_test_batch') and not meta.get('done'):
                    return jsonify({'ok': False, 'error': 'Another vulnerability test or batch run is already active'}), 409
        except Exception:
            pass

        state = backend._load_vuln_catalogs_state()
        entry = backend._get_active_vuln_catalog_entry(state)
        if not entry:
            return jsonify({'ok': False, 'error': 'No active catalog pack'}), 404

        items = backend._normalize_vuln_catalog_items(entry)
        scope = str(payload.get('scope') or 'unvalidated').strip().lower()
        if scope not in ('unvalidated', 'failed', 'all_enabled'):
            scope = 'unvalidated'
        query = str(payload.get('query') or '').strip()
        include_disabled = backend._coerce_bool(payload.get('include_disabled')) if 'include_disabled' in payload else False
        limit = None
        try:
            limit_raw = payload.get('limit')
            if limit_raw not in (None, '', False):
                limit = max(1, min(int(limit_raw), 500))
        except Exception:
            limit = None

        selected_items: list[dict[str, Any]] = []
        for item in items:
            if not include_disabled and bool(item.get('disabled')):
                continue
            if scope == 'failed' and item.get('validated_ok') is not False:
                continue
            if scope == 'unvalidated' and not (item.get('validated_ok') is None or item.get('validated_incomplete') is True):
                continue
            if not _item_matches_query(item, query):
                continue
            selected_items.append(item)

        if limit is not None:
            selected_items = selected_items[:limit]

        if not selected_items:
            return jsonify({'ok': False, 'error': 'No catalog items matched the selected batch filters'}), 400

        try:
            core_cfg = backend._merge_core_configs(payload.get('core'), include_password=True)
            if not core_cfg.get('host'):
                core_cfg['host'] = core_cfg.get('ssh_host') or '127.0.0.1'
            if not core_cfg.get('port'):
                core_cfg['port'] = backend.CORE_PORT
            core_cfg = backend._require_core_ssh_credentials(core_cfg)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'CORE VM SSH config required: {exc}'}), 400

        batch_run_id = str(backend.uuid.uuid4())[:12]
        batch_meta = {
            'kind': 'vuln_test_batch',
            'run_id': batch_run_id,
            'done': False,
            'status': 'queued',
            'catalog_id': str(entry.get('id') or '').strip(),
            'catalog_label': str(entry.get('label') or '').strip() or str(entry.get('id') or '').strip(),
            'scope': scope,
            'query': query,
            'include_disabled': include_disabled,
            'limit': limit,
            'selected_items': [dict(item) for item in selected_items],
            'results': [],
            'log_lines': [],
            'active_item_id': None,
            'active_item_name': None,
            'active_child_run_id': None,
            'active_child_stop_requested': False,
            'stop_requested': False,
            'started_at': backend._local_timestamp_display(),
            'finished_at': None,
        }
        backend.RUNS[batch_run_id] = batch_meta

        try:
            backend.threading.Thread(
                target=_run_batch,
                args=(backend, batch_meta, core_cfg),
                name=f'vuln-batch-{batch_run_id[:8]}',
                daemon=True,
            ).start()
        except Exception as exc:
            backend.RUNS.pop(batch_run_id, None)
            return jsonify({'ok': False, 'error': f'failed to start batch run: {exc}'}), 500

        return jsonify(
            {
                'ok': True,
                'run_id': batch_run_id,
                'selected_count': len(selected_items),
                'scope': scope,
                'include_disabled': include_disabled,
                'limit': limit,
            }
        )

    @app.route('/vuln_catalog_items/batch/status')
    def vuln_catalog_items_batch_status():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        active_child = _active_child_snapshot(backend, meta)
        return jsonify(
            {
                'ok': True,
                'run_id': str(meta.get('run_id') or ''),
                'done': bool(meta.get('done')),
                'status': str(meta.get('status') or ''),
                'stop_requested': bool(meta.get('stop_requested')),
                'started_at': meta.get('started_at'),
                'finished_at': meta.get('finished_at'),
                'catalog': {
                    'id': str(meta.get('catalog_id') or ''),
                    'label': str(meta.get('catalog_label') or ''),
                },
                'selection': {
                    'scope': str(meta.get('scope') or ''),
                    'query': str(meta.get('query') or ''),
                    'include_disabled': bool(meta.get('include_disabled')),
                    'limit': meta.get('limit'),
                },
                'progress': _summarize_batch(meta),
                'category_counts': _collect_category_counts(meta.get('results') if isinstance(meta.get('results'), list) else []),
                'active_item': (
                    {
                        'id': meta.get('active_item_id'),
                        'name': meta.get('active_item_name'),
                        'child_run_id': meta.get('active_child_run_id'),
                        'stop_requested': bool(meta.get('active_child_stop_requested')),
                        'child_status': active_child,
                    }
                    if meta.get('active_item_id')
                    else None
                ),
                'active_child': active_child,
                'results': _result_payloads(meta),
                'log_lines': _status_log_lines(meta, active_child),
            }
        )

    @app.route('/vuln_catalog_items/batch/stop', methods=['POST'])
    def vuln_catalog_items_batch_stop():
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        run_id = str(payload.get('run_id') or '').strip()
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        _request_batch_stop(backend, meta)
        return jsonify({'ok': True, 'run_id': str(meta.get('run_id') or ''), 'stop_requested': True})

    @app.route('/vuln_catalog_items/batch/export.json')
    def vuln_catalog_items_batch_export_json():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        return jsonify(_export_payload(meta))

    @app.route('/vuln_catalog_items/batch/export.md')
    def vuln_catalog_items_batch_export_markdown():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        report = _markdown_report(meta)
        filename = f"vuln-batch-{str(meta.get('run_id') or 'report')}.md"
        headers = {'Content-Disposition': f'attachment; filename={filename}'}
        return Response(report, mimetype='text/markdown; charset=utf-8', headers=headers)

    @app.route('/vuln_catalog_items/batch/item_log')
    def vuln_catalog_items_batch_item_log():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        item_id = int(request.args.get('item_id') or 0)
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        results = meta.get('results') if isinstance(meta.get('results'), list) else []
        for result in results:
            if not isinstance(result, dict):
                continue
            if int(result.get('item_id') or 0) != item_id:
                continue
            log_path = str(result.get('log_path') or '').strip()
            if not log_path or not os.path.isfile(log_path):
                return jsonify({'ok': False, 'error': 'log not available'}), 404
            download_name = str(result.get('log_filename') or os.path.basename(log_path) or f'batch-item-{item_id}.log').strip()
            return send_file(log_path, as_attachment=True, download_name=download_name, mimetype='text/plain; charset=utf-8')
        return jsonify({'ok': False, 'error': 'not found'}), 404

    mark_routes_registered(app, 'vuln_catalog_batch_routes')
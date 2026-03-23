from pathlib import Path

from webapp import app_backend
from webapp.routes import vuln_catalog_batch


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_vuln_catalog_batch_start_selects_matching_items(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(app_backend, '_load_vuln_catalogs_state', lambda: {'catalogs': []})
    monkeypatch.setattr(app_backend, '_get_active_vuln_catalog_entry', lambda _state: {'id': 'cat1', 'label': 'Catalog One'})
    monkeypatch.setattr(
        app_backend,
        '_normalize_vuln_catalog_items',
        lambda _entry: [
            {'id': 1, 'name': 'alpha', 'compose_rel': 'vuln/a/docker-compose.yml', 'validated_ok': None, 'disabled': False},
            {'id': 2, 'name': 'beta', 'compose_rel': 'vuln/b/docker-compose.yml', 'validated_ok': False, 'disabled': False},
            {'id': 3, 'name': 'gamma', 'compose_rel': 'vuln/c/docker-compose.yml', 'validated_incomplete': True, 'validated_ok': None, 'disabled': False},
            {'id': 4, 'name': 'delta', 'compose_rel': 'vuln/d/docker-compose.yml', 'validated_ok': None, 'disabled': True},
        ],
    )
    monkeypatch.setattr(
        app_backend,
        '_merge_core_configs',
        lambda *_args, **_kwargs: {
            'ssh_host': '127.0.0.1',
            'ssh_port': 22,
            'ssh_username': 'u',
            'ssh_password': 'p',
            'host': '127.0.0.1',
            'port': 50051,
        },
    )
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)

    class _DummyThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            self.target = target
            self.args = args

        def start(self):
            return None

    monkeypatch.setattr(app_backend.threading, 'Thread', _DummyThread)

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    resp = client.post('/vuln_catalog_items/batch/start', json={'scope': 'unvalidated', 'core': {}})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    assert payload['selected_count'] == 2

    run_id = str(payload.get('run_id') or '')
    meta = app_backend.RUNS.get(run_id) or {}
    assert meta.get('kind') == 'vuln_test_batch'
    assert [item['id'] for item in meta.get('selected_items') or []] == [1, 3]
    assert [item['compose_rel'] for item in meta.get('selected_items') or []] == [
        'vuln/a/docker-compose.yml',
        'vuln/c/docker-compose.yml',
    ]

    app_backend.RUNS.pop(run_id, None)


def test_vuln_catalog_batch_start_rejects_when_other_test_active(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    app_backend.RUNS['busy-vuln-test'] = {'kind': 'vuln_test', 'done': False}

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    resp = client.post('/vuln_catalog_items/batch/start', json={'scope': 'all_enabled', 'core': {}})

    assert resp.status_code == 409
    assert resp.get_json() == {
        'ok': False,
        'error': 'Another vulnerability test or batch run is already active',
    }

    app_backend.RUNS.pop('busy-vuln-test', None)


def test_vuln_catalog_batch_status_and_stop(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)

    batch_id = 'batch-123'
    app_backend.RUNS[batch_id] = {
        'kind': 'vuln_test_batch',
        'run_id': batch_id,
        'done': False,
        'status': 'running',
        'catalog_id': 'cat1',
        'catalog_label': 'Catalog One',
        'scope': 'all_enabled',
        'query': '',
        'include_disabled': False,
        'limit': None,
        'selected_items': [{'id': 1, 'name': 'alpha'}, {'id': 2, 'name': 'beta'}],
        'results': [{'item_id': 1, 'item_name': 'alpha', 'status': 'passed', 'reason': 'runtime validation passed'}],
        'log_lines': ['[batch] starting'],
        'active_item_id': 2,
        'active_item_name': 'beta',
        'active_child_run_id': '',
        'active_child_stop_requested': False,
        'stop_requested': False,
        'started_at': 'now',
        'finished_at': None,
    }

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    status_resp = client.get('/vuln_catalog_items/batch/status', query_string={'run_id': batch_id})
    assert status_resp.status_code == 200
    status_payload = status_resp.get_json() or {}
    assert status_payload['ok'] is True
    assert status_payload['progress'] == {
        'total': 2,
        'completed': 1,
        'passed': 1,
        'failed': 0,
        'incomplete': 0,
        'skipped': 0,
        'pending': 1,
    }
    assert status_payload['active_item']['id'] == 2

    stop_resp = client.post('/vuln_catalog_items/batch/stop', json={'run_id': batch_id})
    assert stop_resp.status_code == 200
    assert stop_resp.get_json() == {'ok': True, 'run_id': batch_id, 'stop_requested': True}
    assert app_backend.RUNS[batch_id]['stop_requested'] is True

    app_backend.RUNS.pop(batch_id, None)


def test_append_batch_log_keeps_last_500_lines():
    meta = {'log_lines': []}

    for idx in range(520):
        vuln_catalog_batch._append_batch_log(meta, f'line {idx}')

    lines = meta.get('log_lines') or []
    assert len(lines) == 500
    assert lines[0] == 'line 20'
    assert lines[-1] == 'line 519'


def test_vuln_catalog_batch_status_surfaces_active_child_log_tail(tmp_path, monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)

    child_log = tmp_path / 'child.log'
    child_log.write_text('line one\nline two\n[async] still working\n', encoding='utf-8')

    batch_id = 'batch-child-tail'
    child_id = 'child-run-1'
    app_backend.RUNS[batch_id] = {
        'kind': 'vuln_test_batch',
        'run_id': batch_id,
        'done': False,
        'status': 'running',
        'catalog_id': 'cat1',
        'catalog_label': 'Catalog One',
        'scope': 'all_enabled',
        'query': '',
        'include_disabled': False,
        'limit': None,
        'selected_items': [{'id': 16, 'name': 'apisix/CVE-2021-45232'}],
        'results': [],
        'log_lines': ['[batch] queued 1 item(s)', '[batch] starting 1/1: #16 apisix/CVE-2021-45232'],
        'active_item_id': 16,
        'active_item_name': 'apisix/CVE-2021-45232',
        'active_child_run_id': child_id,
        'active_child_stop_requested': False,
        'stop_requested': False,
        'started_at': 'now',
        'finished_at': None,
    }
    app_backend.RUNS[child_id] = {
        'kind': 'vuln_test',
        'status': 'executing',
        'done': False,
        'cleanup_started': False,
        'cleanup_done': False,
        'returncode': None,
        'log_path': str(child_log),
    }

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    try:
        status_resp = client.get('/vuln_catalog_items/batch/status', query_string={'run_id': batch_id})
        assert status_resp.status_code == 200
        status_payload = status_resp.get_json() or {}
        assert status_payload['active_child']['run_id'] == child_id
        assert status_payload['active_child']['status'] == 'executing'
        assert status_payload['active_item']['child_status']['status'] == 'executing'
        assert '[child] run child-run-1 status=executing' in status_payload['log_lines']
        assert '[child] [async] still working' in status_payload['log_lines']
    finally:
        app_backend.RUNS.pop(batch_id, None)
        app_backend.RUNS.pop(child_id, None)


def test_classify_single_run_uses_validation_summary_field(monkeypatch):
    child_meta = {
        'run_id': 'child-validated',
        'returncode': 0,
        'validation_summary': {
            'ok': True,
            'missing_nodes': [],
            'docker_not_running': [],
            'injects_missing': [],
            'generator_outputs_missing': [],
            'generator_injects_missing': [],
        },
    }

    monkeypatch.setattr(app_backend, '_extract_validation_summary_from_text', lambda _text: None)
    monkeypatch.setattr(app_backend, '_extract_async_error_from_text', lambda _text: None)

    result = vuln_catalog_batch._classify_single_run(app_backend, child_meta)

    assert result['status'] == 'passed'
    assert result['reason'] == 'runtime validation passed'
    assert result['validation_summary']['ok'] is True
    assert child_meta['execute_validation_summary']['ok'] is True


def test_classify_single_run_computes_validation_when_missing(tmp_path, monkeypatch):
    log_path = tmp_path / 'run.log'
    log_path.write_text('session id: 42\n', encoding='utf-8')
    xml_path = tmp_path / 'ephemeral_execute.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')
    post_xml = tmp_path / 'core-post' / 'session.xml'
    post_xml.parent.mkdir(parents=True, exist_ok=True)
    post_xml.write_text('<session/>', encoding='utf-8')

    child_meta = {
        'run_id': 'child-compute-validation',
        'log_path': str(log_path),
        'xml_path': str(xml_path),
        'preview_plan_path': str(xml_path),
        'core_cfg': {'ssh_host': '127.0.0.1', 'ssh_username': 'u', 'ssh_password': 'p'},
        'flow_enabled': True,
        'scenario_name': 'vuln-test-16',
        'done': True,
        'returncode': 0,
    }

    monkeypatch.setattr(app_backend, '_sync_remote_artifacts', lambda _meta: None)
    monkeypatch.setattr(app_backend, '_extract_report_path_from_text', lambda _text: None)
    monkeypatch.setattr(app_backend, '_find_latest_report_path', lambda: None)
    monkeypatch.setattr(app_backend, '_extract_summary_path_from_text', lambda _text: None)
    monkeypatch.setattr(app_backend, '_derive_summary_from_report', lambda _report: None)
    monkeypatch.setattr(app_backend, '_extract_session_id_from_text', lambda _text: 42)
    monkeypatch.setattr(app_backend, '_grpc_save_current_session_xml_with_config', lambda _cfg, _out_dir, session_id=None: str(post_xml) if session_id == 42 else None)
    monkeypatch.setattr(
        app_backend,
        '_validate_session_nodes_and_injects',
        lambda **_kwargs: {
            'ok': True,
            'missing_nodes': [],
            'docker_not_running': [],
            'injects_missing': [],
            'generator_outputs_missing': [],
            'generator_injects_missing': [],
        },
    )
    monkeypatch.setattr(app_backend, '_persist_execute_validation_artifacts', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(app_backend, '_append_async_run_log_line', lambda _meta, _line: None)
    monkeypatch.setattr(app_backend, '_extract_validation_summary_from_text', lambda _text: None)
    monkeypatch.setattr(app_backend, '_extract_async_error_from_text', lambda _text: None)

    result = vuln_catalog_batch._classify_single_run(app_backend, child_meta)

    assert result['status'] == 'passed'
    assert result['validation_summary']['ok'] is True
    assert child_meta['execute_validation_summary']['ok'] is True
    assert child_meta['session_xml_path'] == str(post_xml)


def test_vuln_catalog_batch_status_includes_category_counts_and_exports(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)

    batch_log_path = Path(app_backend._outputs_dir()) / 'test-batch-item.log'
    batch_log_path.write_text('full batch child log\nline two\n', encoding='utf-8')

    batch_id = 'batch-export'
    app_backend.RUNS[batch_id] = {
        'kind': 'vuln_test_batch',
        'run_id': batch_id,
        'done': True,
        'status': 'completed',
        'catalog_id': 'cat1',
        'catalog_label': 'Catalog One',
        'scope': 'all_enabled',
        'query': 'alpha',
        'include_disabled': False,
        'limit': 25,
        'selected_items': [{'id': 1, 'name': 'alpha'}, {'id': 2, 'name': 'beta'}],
        'results': [
            {
                'item_id': 1,
                'item_name': 'alpha',
                'status': 'failed',
                'reason': 'execute returncode=1',
                'categories': ['execute_returncode', 'docker_runtime'],
                'log_path': str(batch_log_path),
                'log_filename': 'alpha.log',
            },
            {'item_id': 2, 'item_name': 'beta', 'status': 'passed', 'reason': 'runtime validation passed', 'categories': ['validation_passed']},
        ],
        'log_lines': ['[batch] completed'],
        'active_item_id': None,
        'active_item_name': None,
        'active_child_run_id': '',
        'active_child_stop_requested': False,
        'stop_requested': False,
        'started_at': 'now',
        'finished_at': 'later',
    }

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    status_resp = client.get('/vuln_catalog_items/batch/status', query_string={'run_id': batch_id})
    assert status_resp.status_code == 200
    status_payload = status_resp.get_json() or {}
    assert status_payload['category_counts'] == {
        'docker_runtime': 1,
        'execute_returncode': 1,
        'validation_passed': 1,
    }
    assert status_payload['results'][0]['log_available'] is True
    assert status_payload['results'][0]['log_download_url'] == f'/vuln_catalog_items/batch/item_log?run_id={batch_id}&item_id=1'

    json_resp = client.get('/vuln_catalog_items/batch/export.json', query_string={'run_id': batch_id})
    assert json_resp.status_code == 200
    json_payload = json_resp.get_json() or {}
    assert json_payload['ok'] is True
    assert json_payload['run_id'] == batch_id
    assert json_payload['category_counts']['execute_returncode'] == 1
    assert json_payload['results'][0]['log_available'] is True

    md_resp = client.get('/vuln_catalog_items/batch/export.md', query_string={'run_id': batch_id})
    assert md_resp.status_code == 200
    assert 'attachment; filename=vuln-batch-batch-export.md' in md_resp.headers.get('Content-Disposition', '')
    markdown = md_resp.get_data(as_text=True)
    assert '# Vulnerability Batch Test Report' in markdown
    assert 'execute_returncode: 1' in markdown
    assert '| 1 | alpha | failed | execute_returncode, docker_runtime | execute returncode=1 |' in markdown

    log_resp = client.get('/vuln_catalog_items/batch/item_log', query_string={'run_id': batch_id, 'item_id': 1})
    assert log_resp.status_code == 200
    assert 'attachment; filename=alpha.log' in log_resp.headers.get('Content-Disposition', '')
    assert log_resp.get_data(as_text=True) == 'full batch child log\nline two\n'

    app_backend.RUNS.pop(batch_id, None)
    batch_log_path.unlink(missing_ok=True)
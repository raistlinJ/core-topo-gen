from pathlib import Path

from webapp import app_backend
from webapp.routes import flag_catalog_batch


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_build_batch_input_config_marks_manual_inputs():
    result = flag_catalog_batch._build_batch_input_config(
        {
            'inputs': [
                {'name': 'username', 'required': True},
                {'name': 'input_file', 'required': True, 'type': 'file'},
                {'name': 'seed', 'required': True, 'default': '42'},
            ]
        }
    )

    assert result['ok'] is False
    assert result['manual_inputs'] == ['username', 'input_file']
    assert result['cfg'] == {'seed': '42'}


def test_flag_catalog_batch_start_selects_matching_items(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        app_backend,
        '_flag_generators_from_manifests',
        lambda *, kind: (
            [
                {'id': 'alpha', 'name': 'Alpha', 'inputs': [], 'source': {'path': 'outputs/installed_generators/a'}},
                {'id': 'beta', 'name': 'Beta', 'inputs': [{'name': 'token', 'required': True}], 'source': {'path': 'outputs/installed_generators/b'}},
                {'id': 'gamma', 'name': 'Gamma', 'inputs': [], 'source': {'path': 'outputs/installed_generators/c'}, '_disabled': True},
            ],
            {},
            [],
        ),
    )
    monkeypatch.setattr(app_backend, '_is_installed_generator_view', lambda _generator: True)
    monkeypatch.setattr(app_backend, '_annotate_disabled_state', lambda generators, *, kind: generators)
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
    monkeypatch.setattr(app_backend, '_ensure_core_vm_idle_for_test', lambda _cfg: None)

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

    resp = client.post('/flag_catalog_items/batch/start', json={'kind': 'flag-generator', 'query': 'a', 'core': {}})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    assert payload['selected_count'] == 2
    assert payload['eligible_count'] == 1
    assert payload['manual_input_count'] == 1

    run_id = str(payload.get('run_id') or '')
    meta = app_backend.RUNS.get(run_id) or {}
    assert meta.get('kind') == 'flag_test_batch'
    assert meta.get('kind_name') == 'flag-generator'
    assert [item['id'] for item in meta.get('selected_items') or []] == ['alpha', 'beta']

    app_backend.RUNS.pop(run_id, None)


def test_flag_catalog_batch_status_and_stop(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)

    batch_id = 'flag-batch-123'
    app_backend.RUNS[batch_id] = {
        'kind': 'flag_test_batch',
        'kind_name': 'flag-generator',
        'run_id': batch_id,
        'done': False,
        'status': 'running',
        'query': '',
        'include_disabled': False,
        'limit': None,
        'selected_items': [{'id': 'alpha', 'name': 'Alpha'}, {'id': 'beta', 'name': 'Beta'}],
        'results': [{'item_id': 'alpha', 'item_name': 'Alpha', 'status': 'passed', 'reason': 'generated 1 output file'}],
        'log_lines': ['[batch] starting'],
        'active_item_id': 'beta',
        'active_item_name': 'Beta',
        'active_child_run_id': '',
        'active_child_stop_requested': False,
        'stop_requested': False,
        'started_at': 'now',
        'finished_at': None,
    }

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    status_resp = client.get('/flag_catalog_items/batch/status', query_string={'run_id': batch_id})
    assert status_resp.status_code == 200
    status_payload = status_resp.get_json() or {}
    assert status_payload['ok'] is True
    assert status_payload['selection']['kind'] == 'flag-generator'
    assert status_payload['progress'] == {
        'total': 2,
        'completed': 1,
        'passed': 1,
        'failed': 0,
        'incomplete': 0,
        'skipped': 0,
        'pending': 1,
    }
    assert status_payload['active_item']['id'] == 'beta'

    stop_resp = client.post('/flag_catalog_items/batch/stop', json={'run_id': batch_id})
    assert stop_resp.status_code == 200
    assert stop_resp.get_json() == {'ok': True, 'run_id': batch_id, 'stop_requested': True}
    assert app_backend.RUNS[batch_id]['stop_requested'] is True

    app_backend.RUNS.pop(batch_id, None)


def test_flag_catalog_batch_status_exports_and_item_log(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)

    batch_log_path = Path(app_backend._outputs_dir()) / 'test-flag-batch-item.log'
    batch_log_path.write_text('full flag batch child log\nline two\n', encoding='utf-8')

    batch_id = 'flag-batch-export'
    app_backend.RUNS[batch_id] = {
        'kind': 'flag_test_batch',
        'kind_name': 'flag-node-generator',
        'run_id': batch_id,
        'done': True,
        'status': 'completed',
        'query': 'alpha',
        'include_disabled': False,
        'limit': 25,
        'selected_items': [{'id': 'alpha', 'name': 'Alpha'}, {'id': 'beta', 'name': 'Beta'}],
        'results': [
            {
                'item_id': 'alpha',
                'item_name': 'Alpha',
                'status': 'failed',
                'reason': 'execute returncode=1',
                'categories': ['execute_returncode', 'outputs_missing'],
                'log_path': str(batch_log_path),
                'log_filename': 'alpha.log',
            },
            {'item_id': 'beta', 'item_name': 'Beta', 'status': 'passed', 'reason': 'generated 1 output file', 'categories': ['outputs_present']},
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

    status_resp = client.get('/flag_catalog_items/batch/status', query_string={'run_id': batch_id})
    assert status_resp.status_code == 200
    status_payload = status_resp.get_json() or {}
    assert status_payload['category_counts'] == {
        'execute_returncode': 1,
        'outputs_missing': 1,
        'outputs_present': 1,
    }
    assert status_payload['results'][0]['log_available'] is True
    assert status_payload['results'][0]['log_download_url'] == f'/flag_catalog_items/batch/item_log?run_id={batch_id}&item_id=alpha'

    json_resp = client.get('/flag_catalog_items/batch/export.json', query_string={'run_id': batch_id})
    assert json_resp.status_code == 200
    json_payload = json_resp.get_json() or {}
    assert json_payload['ok'] is True
    assert json_payload['run_id'] == batch_id
    assert json_payload['category_counts']['execute_returncode'] == 1

    md_resp = client.get('/flag_catalog_items/batch/export.md', query_string={'run_id': batch_id})
    assert md_resp.status_code == 200
    assert 'attachment; filename=flag-batch-flag-batch-export.md' in md_resp.headers.get('Content-Disposition', '')
    markdown = md_resp.get_data(as_text=True)
    assert '# Flag Catalog Batch Test Report' in markdown
    assert 'execute_returncode: 1' in markdown
    assert '| alpha | Alpha | failed | execute_returncode, outputs_missing | execute returncode=1 |' in markdown

    log_resp = client.get('/flag_catalog_items/batch/item_log', query_string={'run_id': batch_id, 'item_id': 'alpha'})
    assert log_resp.status_code == 200
    assert 'attachment; filename=alpha.log' in log_resp.headers.get('Content-Disposition', '')
    assert log_resp.get_data(as_text=True) == 'full flag batch child log\nline two\n'

    app_backend.RUNS.pop(batch_id, None)
    batch_log_path.unlink(missing_ok=True)
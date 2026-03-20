import json

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


class _FakeUUID:
    def __init__(self, value):
        self.hex = value


def test_core_push_repo_uses_scenario_specific_core_config(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text('<Scenarios />', encoding='utf-8')

    init_calls = []
    schedule_calls = []

    monkeypatch.setattr(backend.uuid, 'uuid4', lambda: _FakeUUID('repo-progress-1'))
    monkeypatch.setattr(
        backend,
        '_parse_scenarios_xml',
        lambda path: {
            'core': {'host': 'global-host'},
            'scenarios': [
                {'name': 'Scenario 1', 'hitl': {'core': {'host': 'scenario-host', 'ssh_host': 'scenario-vm'}}},
            ],
        },
    )
    monkeypatch.setattr(backend, '_merge_core_configs', lambda *args, **kwargs: {'host': 'merged-host', 'ssh_host': 'scenario-vm'})
    monkeypatch.setattr(backend, '_init_repo_push_progress', lambda *args, **kwargs: init_calls.append((args, kwargs)))
    monkeypatch.setattr(backend, '_schedule_repo_push_to_remote', lambda *args, **kwargs: schedule_calls.append((args, kwargs)))

    resp = client.post(
        '/core/push_repo',
        data={
            'xml_path': str(xml_path),
            'scenario': 'Scenario 1',
            'core_json': json.dumps({'host': 'override-host'}),
        },
    )

    payload = resp.get_json() or {}
    assert resp.status_code == 200
    assert payload.get('ok') is True
    assert payload.get('progress_id') == 'repo-progress-1'
    assert len(init_calls) == 1
    assert len(schedule_calls) == 1
    assert schedule_calls[0][0][0] == payload.get('progress_id')
    assert schedule_calls[0][0][1] == {'host': 'merged-host', 'ssh_host': 'scenario-vm'}


def test_core_push_repo_reports_ssh_tunnel_error(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text('<Scenarios />', encoding='utf-8')

    updates = []

    monkeypatch.setattr(backend.uuid, 'uuid4', lambda: _FakeUUID('repo-progress-2'))
    monkeypatch.setattr(backend, '_parse_scenarios_xml', lambda path: {})
    monkeypatch.setattr(backend, '_merge_core_configs', lambda *args, **kwargs: {'host': 'merged-host'})
    monkeypatch.setattr(backend, '_init_repo_push_progress', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_update_repo_push_progress', lambda *args, **kwargs: updates.append((args, kwargs)))

    def _raise_tunnel(*args, **kwargs):
        raise backend._SSHTunnelError('ssh tunnel failed')

    monkeypatch.setattr(backend, '_schedule_repo_push_to_remote', _raise_tunnel)

    resp = client.post('/core/push_repo', data={'xml_path': str(xml_path)})

    payload = resp.get_json() or {}
    assert resp.status_code == 400
    assert payload.get('error') == 'ssh tunnel failed'
    assert updates and updates[0][0][0] == 'repo-progress-2'
    assert updates == [
        (
            ('repo-progress-2',),
            {'status': 'error', 'stage': 'error', 'detail': 'ssh tunnel failed'},
        )
    ]
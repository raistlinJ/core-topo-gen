from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


class _FakeSSHClient:
    def set_missing_host_key_policy(self, *_args, **_kwargs):
        return None

    def connect(self, **_kwargs):
        return None

    def close(self):
        return None


class _FakeParamiko:
    SSHClient = _FakeSSHClient

    class AutoAddPolicy:
        pass


def test_stop_duplicate_daemons_api_requires_password(monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_core_config_for_request', lambda include_password=True: {'host': '127.0.0.1', 'port': 50051, 'ssh_password': ''})

    resp = client.post('/core/stop_duplicate_daemons_api', json={'pids': [1, 2]})

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert payload.get('ok') is False
    assert payload.get('can_stop_daemons') is False


def test_stop_duplicate_daemons_api_reports_before_and_after(monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    calls = []

    def fake_collect(_client):
        if not calls:
            return [11, 22]
        return [11]

    def fake_stop(_client, sudo_password=None, pids=None, logger=None):
        calls.append((sudo_password, list(pids or [])))

    monkeypatch.setattr(backend, '_core_config_for_request', lambda include_password=True: {
        'host': '127.0.0.1',
        'port': 50051,
        'ssh_host': '127.0.0.1',
        'ssh_port': 22,
        'ssh_username': 'core',
        'ssh_password': 'pw',
    })
    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda: None)
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', fake_collect)
    monkeypatch.setattr(backend, '_stop_remote_core_daemon_conflict', fake_stop)

    resp = client.post('/core/stop_duplicate_daemons_api', json={'pids': [11, 22]})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert payload.get('daemon_pids_before') == [11, 22]
    assert payload.get('daemon_pids_after') == [11]
    assert calls == [('pw', [11, 22])]
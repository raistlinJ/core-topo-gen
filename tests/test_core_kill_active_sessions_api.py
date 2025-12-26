from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_kill_active_sessions_api_kill_all(monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_core_config_for_request', lambda include_password=True: {'host': '127.0.0.1', 'port': 50051})
    monkeypatch.setattr(
        backend,
        '_list_active_core_sessions',
        lambda host, port, core_cfg, errors=None, meta=None: [
            {'id': 11, 'state': 'running'},
            {'id': 12, 'state': 'running'},
        ],
    )

    deleted = []

    def fake_action(core_cfg, action, sid, logger=None):
        assert action == 'delete'
        deleted.append(int(sid))

    monkeypatch.setattr(backend, '_execute_remote_core_session_action', fake_action)

    resp = client.post('/core/kill_active_sessions_api', json={'kill_all': True})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('ok') is True
    assert sorted(data.get('deleted') or []) == [11, 12]
    assert sorted(deleted) == [11, 12]

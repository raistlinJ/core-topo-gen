from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_prepare_core_sessions_no_active(monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(
        backend,
        '_list_active_core_sessions',
        lambda host, port, core_cfg, errors=None, meta=None: [],
    )

    resp = client.post(
        '/api/test/core_sessions/prepare',
        json={
            'core': {
                'host': '127.0.0.1',
                'port': 50051,
                'ssh_host': '127.0.0.1',
                'ssh_port': 22,
                'ssh_username': 'core',
                'ssh_password': 'secret',
            },
            'cleanup': False,
        },
    )
    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data.get('ok') is True
    assert data.get('active') is False
    assert data.get('session_count') == 0


def test_prepare_core_sessions_cleanup_active(monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(
        backend,
        '_list_active_core_sessions',
        lambda host, port, core_cfg, errors=None, meta=None: [{'id': 21}, {'id': 22}],
    )

    actions = []

    def fake_action(core_cfg, action, sid, logger=None):
        actions.append((action, int(sid)))

    monkeypatch.setattr(backend, '_execute_remote_core_session_action', fake_action)

    def fake_run_remote_python_json(core_cfg, script, logger=None, label=None, timeout=None):
        if label == 'docker.status(test prepare cleanup)':
            return {'items': [{'name': 'docker-1'}]}
        if label == 'docker.cleanup(test prepare cleanup)':
            return {'results': [{'name': 'docker-1', 'ok': True}]}
        if label == 'docker.wrapper_images.cleanup(test prepare cleanup)':
            return {'removed': ['coretg/foo:iproute2']}
        return {}

    monkeypatch.setattr(backend, '_run_remote_python_json', fake_run_remote_python_json)

    resp = client.post(
        '/api/test/core_sessions/prepare',
        json={
            'core': {
                'host': '127.0.0.1',
                'port': 50051,
                'ssh_host': '127.0.0.1',
                'ssh_port': 22,
                'ssh_username': 'core',
                'ssh_password': 'secret',
            },
            'cleanup': True,
        },
    )
    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data.get('ok') is True
    assert data.get('active') is True
    assert data.get('cleaned') is True
    assert data.get('session_count') == 2
    assert sorted(data.get('session_ids') or []) == [21, 22]
    assert sorted(data.get('stopped') or []) == [21, 22]
    assert sorted(data.get('deleted') or []) == [21, 22]
    assert data.get('cleanup_containers') == 1
    assert data.get('cleanup_images') == 1

    assert sorted(actions) == [('delete', 21), ('delete', 22), ('stop', 21), ('stop', 22)]

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_vuln_catalog_test_status_returns_flags(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setitem(
        backend.RUNS,
        'run-1',
        {'kind': 'vuln_test', 'done': False, 'cleanup_started': True, 'cleanup_done': False},
    )

    try:
        resp = client.post('/vuln_catalog_items/test/status', json={'run_id': 'run-1'})
    finally:
        backend.RUNS.pop('run-1', None)

    assert resp.status_code == 200
    assert resp.get_json() == {
        'ok': True,
        'done': False,
        'cleanup_started': True,
        'cleanup_done': False,
    }


def test_vuln_catalog_test_stop_requires_run_id(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    resp = client.post('/vuln_catalog_items/test/stop', json={})

    assert resp.status_code == 400
    assert resp.get_json() == {'ok': False, 'error': 'run_id required'}


def test_vuln_catalog_test_stop_delegates_to_helper(monkeypatch):
    client = app.test_client()
    _login(client)
    captured = {}

    def fake_stop(meta, user_ok):
        captured['meta'] = dict(meta)
        captured['user_ok'] = user_ok
        return backend.jsonify({'ok': True, 'stopped': True})

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_stop_vuln_test_meta', fake_stop)
    monkeypatch.setitem(backend.RUNS, 'run-2', {'kind': 'vuln_test', 'done': False, 'item_id': 22})

    try:
        resp = client.post('/vuln_catalog_items/test/stop', json={'run_id': 'run-2', 'ok': False})
    finally:
        backend.RUNS.pop('run-2', None)

    assert resp.status_code == 200
    assert resp.get_json() == {'ok': True, 'stopped': True}
    assert captured['meta']['item_id'] == 22
    assert captured['user_ok'] is False


def test_vuln_catalog_test_stop_active_uses_first_active_run(monkeypatch):
    client = app.test_client()
    _login(client)
    captured = {}

    def fake_stop(meta, user_ok):
        captured['meta'] = dict(meta)
        captured['user_ok'] = user_ok
        return backend.jsonify({'ok': True})

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_stop_vuln_test_meta', fake_stop)
    monkeypatch.setitem(backend.RUNS, 'done-run', {'kind': 'vuln_test', 'done': True, 'item_id': 1})
    monkeypatch.setitem(backend.RUNS, 'active-run', {'kind': 'vuln_test', 'done': False, 'item_id': 7})

    try:
        resp = client.post('/vuln_catalog_items/test/stop_active', json={'ok': True})
    finally:
        backend.RUNS.pop('done-run', None)
        backend.RUNS.pop('active-run', None)

    assert resp.status_code == 200
    assert captured['meta']['item_id'] == 7
    assert captured['user_ok'] is True


def test_vuln_catalog_test_stop_active_returns_404_without_active_run(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    resp = client.post('/vuln_catalog_items/test/stop_active', json={})

    assert resp.status_code == 404
    assert resp.get_json() == {'ok': False, 'error': 'no active test'}
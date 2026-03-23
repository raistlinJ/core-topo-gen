from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_generator_packs_set_disabled_redirects_and_maps_form(monkeypatch):
    client = app.test_client()
    _login(client)
    captured = {}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    def fake_set_pack_disabled_state(*, pack_id, disabled):
        captured['pack_id'] = pack_id
        captured['disabled'] = disabled
        return True, 'updated'

    monkeypatch.setattr(backend, '_set_pack_disabled_state', fake_set_pack_disabled_state)

    resp = client.post('/generator_packs/set_disabled/p-1', data={'disabled': 'yes'}, follow_redirects=False)

    assert resp.status_code == 302
    assert resp.headers['Location'].endswith('/flag_catalog')
    assert captured == {'pack_id': 'p-1', 'disabled': True}


def test_api_generator_packs_set_disabled_returns_json(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_set_pack_disabled_state', lambda **kwargs: (True, f"pack {kwargs['pack_id']} updated"))

    resp = client.post('/api/generator_packs/set_disabled', json={'pack_id': 'p-2', 'disabled': True})

    assert resp.status_code == 200
    assert resp.get_json() == {'ok': True, 'message': 'pack p-2 updated'}


def test_api_flag_generators_delete_returns_error_payload(monkeypatch):
    client = app.test_client()
    _login(client)
    captured = {}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    def fake_delete_installed_generator(*, kind, generator_id):
        captured['kind'] = kind
        captured['generator_id'] = generator_id
        return False, 'not found'

    monkeypatch.setattr(backend, '_delete_installed_generator', fake_delete_installed_generator)

    resp = client.post('/api/flag_generators/delete', json={'id': 'g-1'})

    assert resp.status_code == 400
    assert resp.get_json() == {'ok': False, 'error': 'not found'}
    assert captured == {'kind': 'flag-generator', 'generator_id': 'g-1'}


def test_api_flag_node_generators_set_disabled_maps_kind(monkeypatch):
    client = app.test_client()
    _login(client)
    captured = {}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    def fake_set_generator_disabled_state(*, kind, generator_id, disabled):
        captured['kind'] = kind
        captured['generator_id'] = generator_id
        captured['disabled'] = disabled
        return True, 'updated'

    monkeypatch.setattr(backend, '_set_generator_disabled_state', fake_set_generator_disabled_state)

    resp = client.post('/api/flag_node_generators/set_disabled', json={'generator_id': 'node-g-1', 'disabled': True})

    assert resp.status_code == 200
    assert resp.get_json() == {'ok': True, 'message': 'updated'}
    assert captured == {'kind': 'flag-node-generator', 'generator_id': 'node-g-1', 'disabled': True}
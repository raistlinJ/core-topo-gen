import io
import zipfile

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_generator_builder_page_renders(monkeypatch):
    client = app.test_client()
    _login(client)

    called = {'count': 0}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: called.__setitem__('count', called['count'] + 1))

    resp = client.get('/generator_builder')

    assert resp.status_code == 200
    assert called['count'] == 1


def test_generator_artifacts_index_merges_sources_reserved_and_custom(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_flag_generators_from_enabled_sources',
        lambda: ([{'id': 'flag-a', 'name': 'Flag A', 'outputs': [{'name': 'alpha', 'type': 'file', 'description': 'Alpha file', 'sensitive': False}]}], []),
    )
    monkeypatch.setattr(
        backend,
        '_flag_node_generators_from_enabled_sources',
        lambda: ([{'id': 'node-b', 'name': 'Node B', 'outputs': [{'name': 'beta', 'type': 'path', 'description': '', 'sensitive': True}]}], []),
    )
    monkeypatch.setattr(backend, '_load_custom_artifacts', lambda: {'custom.gamma': {'type': 'json'}, 'alpha': {'type': 'ignored'}})
    monkeypatch.setitem(
        backend._RESERVED_ARTIFACTS,
        'reserved.delta',
        {'type': 'text', 'description': 'Reserved item', 'sensitive': False},
    )

    resp = client.get('/api/generators/artifacts_index')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    artifacts = {item['artifact']: item for item in (payload.get('artifacts') or [])}
    assert artifacts['alpha']['type'] == 'file'
    assert artifacts['alpha']['producers'][0]['plugin_id'] == 'flag-a'
    assert artifacts['beta']['sensitive'] is True
    assert artifacts['reserved.delta']['producers'][0]['plugin_type'] == 'reserved'
    assert artifacts['custom.gamma']['type'] == 'json'


def test_generator_artifacts_index_custom_add_persists_item(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_upsert_custom_artifact',
        lambda artifact, *, type_value=None: {'artifact': artifact, 'type': type_value},
    )

    resp = client.post('/api/generators/artifacts_index/custom', json={'artifact': 'artifact.one', 'type': 'json'})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload == {'ok': True, 'artifact': {'artifact': 'artifact.one', 'type': 'json'}}


def test_generator_scaffold_meta_returns_sorted_paths(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_build_generator_scaffold',
        lambda payload: ({'z/file.txt': 'z', 'a/manifest.yaml': 'm'}, 'manifest-body', 'folder'),
    )

    resp = client.post('/api/generators/scaffold_meta', json={'plugin_id': 'demo'})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload == {
        'ok': True,
        'manifest_yaml': 'manifest-body',
        'scaffold_paths': ['a/manifest.yaml', 'z/file.txt'],
    }


def test_generator_scaffold_zip_streams_archive(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_build_generator_scaffold',
        lambda payload: ({'demo/manifest.yaml': 'manifest-body', 'demo/run.py': 'print(1)\n'}, 'manifest-body', 'demo'),
    )
    monkeypatch.setattr(backend, '_sanitize_id', lambda value: 'demo-plugin')

    resp = client.post('/api/generators/scaffold_zip', json={'plugin_id': 'Demo Plugin'})

    assert resp.status_code == 200
    assert resp.mimetype == 'application/zip'
    assert 'attachment; filename=generator_scaffold_demo-plugin.zip' in resp.headers.get('Content-Disposition', '')

    with zipfile.ZipFile(io.BytesIO(resp.data), 'r') as archive:
        assert sorted(archive.namelist()) == ['demo/manifest.yaml', 'demo/run.py']
        assert archive.read('demo/manifest.yaml').decode('utf-8') == 'manifest-body'
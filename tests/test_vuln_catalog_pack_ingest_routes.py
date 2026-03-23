import io
from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_vuln_catalog_pack_upload_ajax_missing_file_returns_400(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    resp = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data={},
        content_type='multipart/form-data',
    )

    assert resp.status_code == 400
    assert resp.get_json() == {'ok': False, 'error': 'Missing zip_file'}


def test_vuln_catalog_pack_upload_ajax_installs_zip(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)
    captured = {}

    def fake_install(*, zip_file_path, label, origin):
        captured['zip_file_path'] = zip_file_path
        captured['label'] = label
        captured['origin'] = origin
        captured['exists_during_install'] = Path(zip_file_path).exists()
        return {'id': 'catalog-123'}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_install_vuln_catalog_zip_file', fake_install)

    resp = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data={'zip_file': (io.BytesIO(b'PK\x03\x04demo'), '../danger demo.zip')},
        content_type='multipart/form-data',
    )

    assert resp.status_code == 200
    assert resp.get_json() == {
        'ok': True,
        'message': 'Vulnerability catalog pack installed.',
        'catalog_id': 'catalog-123',
    }
    assert captured['origin'] == 'upload'
    assert captured['label'] == 'danger_demo.zip'
    assert captured['exists_during_install'] is True
    assert not Path(captured['zip_file_path']).exists()


def test_vuln_catalog_pack_import_url_blocks_unsafe_url(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_is_safe_remote_zip_url', lambda url: (False, 'host not allowed'))
    monkeypatch.setattr(
        backend,
        '_download_zip_from_url',
        lambda url: (_ for _ in ()).throw(AssertionError('download should not run')),
    )

    resp = client.post('/vuln_catalog_packs/import_url', data={'zip_url': 'https://blocked.example/demo.zip'})

    assert resp.status_code == 302
    assert resp.headers['Location'].endswith('/vuln_catalog_page')


def test_vuln_catalog_pack_import_url_installs_downloaded_zip(monkeypatch):
    client = app.test_client()
    _login(client)
    captured = {}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_is_safe_remote_zip_url', lambda url: (True, ''))
    monkeypatch.setattr(backend, '_download_zip_from_url', lambda url: b'zip-bytes')

    def fake_install(*, zip_bytes, label, origin):
        captured['zip_bytes'] = zip_bytes
        captured['label'] = label
        captured['origin'] = origin
        return {'id': 'catalog-789'}

    monkeypatch.setattr(backend, '_install_vuln_catalog_zip_bytes', fake_install)

    resp = client.post('/vuln_catalog_packs/import_url', data={'zip_url': 'https://example.com/packs/demo.zip'})

    assert resp.status_code == 302
    assert resp.headers['Location'].endswith('/vuln_catalog_page')
    assert captured == {
        'zip_bytes': b'zip-bytes',
        'label': 'demo.zip',
        'origin': 'https://example.com/packs/demo.zip',
    }
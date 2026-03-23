from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_core_start_session_redirects_after_action(monkeypatch):
    client = app.test_client()
    _login(client)

    calls = []
    monkeypatch.setattr(backend, '_core_config_for_request', lambda **kwargs: {'host': '127.0.0.1', 'port': 50051})
    monkeypatch.setattr(backend, '_execute_remote_core_session_action', lambda cfg, action, sid, logger=None: calls.append((action, sid)))

    resp = client.post('/core/start_session', data={'session_id': '12'})

    assert resp.status_code in (302, 303)
    assert calls == [('start', 12)]


def test_core_delete_removes_allowed_xml_and_clears_mapping(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    xml_path = outdir / 'delete-me.xml'
    xml_path.write_text('<session />', encoding='utf-8')

    cleared = []
    monkeypatch.setattr(backend, '_uploads_dir', lambda: str(tmp_path / 'uploads'))
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_update_xml_session_mapping', lambda path, session_id: cleared.append((path, session_id)))

    resp = client.post('/core/delete', data={'path': str(xml_path)})

    assert resp.status_code in (302, 303)
    assert not xml_path.exists()
    assert cleared == [(str(xml_path.resolve()), None)]
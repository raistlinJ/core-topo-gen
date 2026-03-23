from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_core_save_xml_streams_saved_file(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    saved_file = outdir / 'core-sessions' / 'session-7.xml'

    def fake_save(_cfg, out_dir, session_id=None):
        assert Path(out_dir) == outdir / 'core-sessions'
        assert session_id == '7'
        saved_file.parent.mkdir(parents=True, exist_ok=True)
        saved_file.write_text('<session />', encoding='utf-8')
        return str(saved_file)

    monkeypatch.setattr(backend, '_grpc_save_current_session_xml_with_config', fake_save, raising=False)
    monkeypatch.setattr(backend, '_core_config_for_request', lambda **kwargs: {'host': '127.0.0.1', 'port': 50051})

    resp = client.post('/core/save_xml', data={'session_id': '7'})

    assert resp.status_code == 200
    assert resp.mimetype == 'application/xml'
    assert 'attachment; filename=session-7.xml' in resp.headers.get('Content-Disposition', '')


def test_core_session_scenario_prefers_local_store_label(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    run_history_path = outdir / 'run_history.json'
    run_history_path.write_text(
        '[{"timestamp":"2025-12-26T00:00:00Z","mode":"async","scenario_name":"Alpha","returncode":0}]',
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, 'RUN_HISTORY_PATH', str(run_history_path))
    monkeypatch.setattr(backend, '_core_config_for_request', lambda **kwargs: {'host': '127.0.0.1', 'port': 50051})
    monkeypatch.setattr(backend, '_load_core_sessions_store', lambda: {'/tmp/alpha.xml': {'session_id': 11, 'scenario_name': 'Alpha', 'core_host': '127.0.0.1', 'core_port': 50051}})
    monkeypatch.setattr(backend, '_migrate_core_sessions_store_with_core_targets', lambda store, history: store)
    monkeypatch.setattr(backend, '_filter_core_sessions_store_for_core', lambda store, host, port: store)
    monkeypatch.setattr(backend, '_read_remote_session_scenario_meta', lambda *args, **kwargs: None)

    resp = client.get('/core/session_scenario?sid=11')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert payload.get('scenario_name') == 'Alpha'
    assert payload.get('source') == 'local_store'
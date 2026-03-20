from io import BytesIO

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_core_upload_saves_valid_xml(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    upload_root = tmp_path / 'uploads'
    monkeypatch.setitem(app.config, 'UPLOAD_FOLDER', str(upload_root))
    monkeypatch.setattr(backend, '_local_timestamp_safe', lambda: '20260101-010203')
    monkeypatch.setattr(backend, '_validate_core_xml', lambda path: (True, []))

    resp = client.post(
        '/core/upload',
        data={'xml_file': (BytesIO(b'<scenario />'), 'sample.xml')},
        content_type='multipart/form-data',
    )

    saved = list((upload_root / 'core').glob('*.xml'))
    assert resp.status_code in (302, 303)
    assert len(saved) == 1
    assert saved[0].read_text(encoding='utf-8') == '<scenario />'


def test_core_start_updates_mapping_and_remote_meta(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<scenario />', encoding='utf-8')

    removed = []
    mapping = []
    remote_meta = []
    run_calls = []

    monkeypatch.setattr(backend, '_validate_core_xml', lambda path: (True, []))
    monkeypatch.setattr(
        backend,
        '_core_config_for_request',
        lambda **kwargs: {'host': '10.0.0.5', 'port': 50051, 'ssh_username': 'tester', 'ssh_host': 'core-vm'},
    )
    monkeypatch.setattr(backend, '_normalize_core_config', lambda cfg, **kwargs: dict(cfg))
    monkeypatch.setattr(backend, '_upload_file_to_core_host', lambda cfg, path: '/remote/scenario.xml')
    monkeypatch.setattr(
        backend,
        '_remote_core_open_xml_script',
        lambda address, remote_xml_path, auto_start=True: f'{address}|{remote_xml_path}|{auto_start}',
    )
    monkeypatch.setattr(
        backend,
        '_run_remote_python_json',
        lambda cfg, script, logger=None, label=None, command_desc=None: run_calls.append((cfg, script, label, command_desc)) or {'session_id': 23},
    )
    monkeypatch.setattr(backend, '_remove_remote_file', lambda cfg, path: removed.append((cfg, path)))
    monkeypatch.setattr(backend, '_update_xml_session_mapping', lambda *args, **kwargs: mapping.append((args, kwargs)))
    monkeypatch.setattr(backend, '_write_remote_session_scenario_meta', lambda *args, **kwargs: remote_meta.append((args, kwargs)))

    resp = client.post('/core/start', data={'path': str(xml_path), 'scenario': 'Scenario 2'})

    assert resp.status_code in (302, 303)
    assert len(run_calls) == 1
    assert removed == [({'host': '10.0.0.5', 'port': 50051, 'ssh_username': 'tester', 'ssh_host': 'core-vm'}, '/remote/scenario.xml')]
    assert mapping == [
        (
            (str(xml_path.resolve()), 23),
            {'scenario_name': 'Scenario 2', 'core_host': '10.0.0.5', 'core_port': 50051},
        )
    ]
    assert remote_meta == [
        (
            ({'host': '10.0.0.5', 'port': 50051, 'ssh_username': 'tester', 'ssh_host': 'core-vm'},),
            {
                'session_id': 23,
                'scenario_name': 'Scenario 2',
                'scenario_xml_basename': 'scenario.xml',
                'logger': backend.app.logger,
            },
        )
    ]
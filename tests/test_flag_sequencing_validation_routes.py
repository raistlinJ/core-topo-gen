from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_api_flow_test_core_connection_returns_success(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<xml />', encoding='utf-8')

    monkeypatch.setattr(backend, '_normalize_scenario_label', lambda value: str(value or '').strip().lower())
    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda scenario_norm: str(xml_path))
    monkeypatch.setattr(
        backend,
        '_core_config_from_xml_path',
        lambda *args, **kwargs: {
            'host': '10.0.0.5',
            'port': 50051,
            'ssh_enabled': True,
            'validated': True,
            'ssh_host': '10.0.0.5',
            'ssh_username': 'core',
            'ssh_password': 'secret',
        },
    )
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, scenario_norm: cfg)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda cfg, timeout=5.0: None)

    resp = client.post('/api/flag-sequencing/test_core_connection', json={'scenario': 'Scenario One'})

    assert resp.status_code == 200
    assert resp.get_json() == {'ok': True, 'host': '10.0.0.5', 'port': 50051}
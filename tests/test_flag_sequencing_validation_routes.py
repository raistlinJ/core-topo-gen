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
    monkeypatch.setattr(backend, '_select_core_config_for_page', lambda scenario_norm, include_password=True: None)
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, scenario_norm: cfg)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda cfg, timeout=5.0: None)

    resp = client.post('/api/flag-sequencing/test_core_connection', json={'scenario': 'Scenario One'})

    assert resp.status_code == 200
    assert resp.get_json() == {'ok': True, 'host': '10.0.0.5', 'port': 50051}


def test_api_flow_test_core_connection_uses_saved_page_core_cfg_when_xml_lacks_password(monkeypatch, tmp_path):
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
            'host': 'localhost',
            'port': 50051,
            'ssh_enabled': True,
            'validated': True,
            'ssh_host': '',
            'ssh_username': 'core',
            'ssh_password': '',
        },
    )
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda scenario_norm, include_password=True: {
            'host': '10.0.0.8',
            'port': 50051,
            'ssh_enabled': True,
            'validated': True,
            'ssh_host': '10.0.0.8',
            'ssh_username': 'core',
            'ssh_password': 'saved-secret',
            'core_secret_id': 'core-secret-1',
        },
    )
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, scenario_norm: cfg)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    observed = {}
    def _fake_ensure(cfg, timeout=5.0):
        observed['host'] = cfg.get('host')
        observed['port'] = cfg.get('port')
        observed['ssh_host'] = cfg.get('ssh_host')
        observed['ssh_password'] = cfg.get('ssh_password')
        return None
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', _fake_ensure)

    resp = client.post('/api/flag-sequencing/test_core_connection', json={'scenario': 'Scenario One'})

    assert resp.status_code == 200
    assert resp.get_json() == {'ok': True, 'host': 'localhost', 'port': 50051}
    assert observed == {
        'host': 'localhost',
        'port': 50051,
        'ssh_host': '10.0.0.8',
        'ssh_password': 'saved-secret',
    }


def test_api_flow_test_core_connection_invalidates_vm_access_on_ssh_auth_error(monkeypatch, tmp_path):
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
            'host': 'localhost',
            'port': 50051,
            'ssh_enabled': True,
            'validated': True,
            'ssh_host': '10.0.0.8',
            'ssh_username': 'core',
            'ssh_password': 'bad-secret',
            'core_secret_id': 'core-secret-1',
        },
    )
    monkeypatch.setattr(backend, '_select_core_config_for_page', lambda scenario_norm, include_password=True: None)
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, scenario_norm: cfg)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    observed = {'cleared': [], 'deleted': []}
    monkeypatch.setattr(backend, '_clear_hitl_validation_in_scenario_catalog', lambda scenario_name, **kwargs: observed['cleared'].append((scenario_name, kwargs)))
    monkeypatch.setattr(backend, '_delete_core_credentials', lambda secret_id: observed['deleted'].append(secret_id) or True)

    def _fake_ensure(cfg, timeout=5.0):
        raise RuntimeError('SSH connect failed to 10.0.0.8:22 as core: AuthenticationException: Authentication failed.')

    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', _fake_ensure)

    resp = client.post('/api/flag-sequencing/test_core_connection', json={'scenario': 'Scenario One'})

    assert resp.status_code == 502
    assert observed == {
        'cleared': [('Scenario One', {'core': True})],
        'deleted': ['core-secret-1'],
    }


def test_api_flow_test_core_connection_does_not_invalidate_vm_access_on_timeout(monkeypatch, tmp_path):
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
            'host': 'localhost',
            'port': 50051,
            'ssh_enabled': True,
            'validated': True,
            'ssh_host': '10.0.0.8',
            'ssh_username': 'core',
            'ssh_password': 'secret',
            'core_secret_id': 'core-secret-1',
        },
    )
    monkeypatch.setattr(backend, '_select_core_config_for_page', lambda scenario_norm, include_password=True: None)
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, scenario_norm: cfg)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    observed = {'cleared': [], 'deleted': []}
    monkeypatch.setattr(backend, '_clear_hitl_validation_in_scenario_catalog', lambda scenario_name, **kwargs: observed['cleared'].append((scenario_name, kwargs)))
    monkeypatch.setattr(backend, '_delete_core_credentials', lambda secret_id: observed['deleted'].append(secret_id) or True)

    def _fake_ensure(cfg, timeout=5.0):
        raise RuntimeError('SSH connect failed to 10.0.0.8:22 as core: TimeoutError: timed out')

    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', _fake_ensure)

    resp = client.post('/api/flag-sequencing/test_core_connection', json={'scenario': 'Scenario One'})

    assert resp.status_code == 502
    assert observed == {'cleared': [], 'deleted': []}
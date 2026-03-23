from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_latest_preview_plan_reports_core_and_topology_reasons_when_unavailable(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [],
            'vulnerabilities_by_node': {},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': False, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_load_scenario_hitl_validation_from_disk', lambda: {})
    monkeypatch.setattr(backend, '_select_latest_core_secret_record', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda: [])

    resp = client.get('/api/flag-sequencing/latest_preview_plan', query_string={'scenario': 'Scenario One'})
    assert resp.status_code == 422
    data = resp.get_json()
    assert data['flow_eligible'] is False
    assert 'CORE VM must be validated in VM / Access.' in data['flow_eligibility_reasons']
    assert 'Topology must include Docker or vulnerability nodes.' in data['flow_eligibility_reasons']
    assert 'No vulnerabilities are available in the Vulnerability Catalog.' in data['flow_eligibility_reasons']


def test_latest_preview_plan_reports_missing_flag_generators_for_vuln_nodes(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [
                {'id': 'docker-1', 'role': 'docker', 'vulnerabilities': ['vuln-a']},
            ],
            'vulnerabilities_by_node': {'docker-1': ['vuln-a']},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': True, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda: [{'Name': 'Example Vuln'}])

    resp = client.get('/api/flag-sequencing/latest_preview_plan', query_string={'scenario': 'Scenario One'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['flow_eligible'] is False
    assert data['vuln_count'] == 1
    assert data['flag_generator_count'] == 0
    assert 'No enabled flag-generators are available for vulnerability nodes.' in data['flow_eligibility_reasons']


def test_latest_preview_plan_reports_no_validated_tested_vulns_when_catalog_is_present_but_unselectable(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [
                {'id': 'docker-1', 'role': 'docker', 'vulnerabilities': ['vuln-a']},
            ],
            'vulnerabilities_by_node': {'docker-1': ['vuln-a']},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': True, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([{'id': 'fg-1'}], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))

    def _fake_load_backend_vuln_catalog_items(*, selectable_only=True):
        if selectable_only:
            return []
        return [{'Name': 'Example Vuln', 'eligible_for_selection': False}]

    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', _fake_load_backend_vuln_catalog_items)

    resp = client.get('/api/flag-sequencing/latest_preview_plan', query_string={'scenario': 'Scenario One'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['vuln_catalog_count'] == 0
    assert data['vuln_catalog_total_count'] == 1
    assert 'No validated/tested vulnerabilities are currently eligible in the Vulnerability Catalog. Validate at least one vulnerability to use vulnerability-based flag sequencing.' in data['flow_eligibility_reasons']


def test_latest_preview_plan_accepts_run_remote_query_flag(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [],
            'vulnerabilities_by_node': {},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': False, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_load_scenario_hitl_validation_from_disk', lambda: {})
    monkeypatch.setattr(backend, '_select_latest_core_secret_record', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda: [])

    resp = client.get(
        '/api/flag-sequencing/latest_preview_plan',
        query_string={'scenario': 'Scenario One', 'run_remote': '1'},
    )

    assert resp.status_code == 422
    data = resp.get_json()
    assert data['core_validated'] is False
    assert data['flow_eligible'] is False
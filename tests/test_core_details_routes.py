from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_api_core_details_topology_requires_scenario():
    client = app.test_client()
    _login(client)

    resp = client.get('/api/core-details/topology')

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert payload.get('ok') is False
    assert payload.get('error') == 'Missing scenario.'


def test_api_core_details_topology_falls_back_to_preview_plan(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    plan_path = tmp_path / 'preview-plan.json'
    plan_path.write_text('{}', encoding='utf-8')

    monkeypatch.setattr(backend, '_latest_session_xml_for_scenario_norm', lambda scenario_norm: None)
    monkeypatch.setattr(backend, '_latest_preview_plan_for_scenario_norm', lambda scenario_norm, prefer_flow=True: str(plan_path))
    monkeypatch.setattr(backend, '_load_preview_payload_from_path', lambda path, scenario_label=None: {'preview': {'nodes': [{'id': 'n1', 'is_vuln': True}], 'links': []}})
    monkeypatch.setattr(backend, '_build_topology_graph_from_preview_plan', lambda preview: ([{'id': 'n1', 'is_vuln': True}], [], {}))
    monkeypatch.setattr(backend, '_flow_state_from_latest_xml', lambda scenario_norm: {'chains': 1})

    resp = client.get('/api/core-details/topology?scenario=alpha')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert payload.get('source') == 'preview_plan'
    nodes = payload.get('nodes') if isinstance(payload.get('nodes'), list) else []
    assert nodes and nodes[0].get('is_vulnerability') is True
    assert payload.get('flow') == {'chains': 1}


def test_core_details_uses_session_export_when_only_session_id_provided(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    saved_file = outdir / 'core-sessions' / 'session-9.xml'

    def fake_save(_cfg, out_dir, session_id=None):
        assert Path(out_dir) == outdir / 'core-sessions'
        assert session_id == '9'
        saved_file.parent.mkdir(parents=True, exist_ok=True)
        saved_file.write_text('<session><container /></session>', encoding='utf-8')
        return str(saved_file)

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_core_config_for_request', lambda **kwargs: {'host': '127.0.0.1', 'port': 50051})
    monkeypatch.setattr(backend, '_grpc_save_current_session_xml_with_config', fake_save, raising=False)
    monkeypatch.setattr(backend, '_validate_core_xml', lambda path: (False, 'schema mismatch'))
    monkeypatch.setattr(backend, '_analyze_core_xml', lambda path: {'nodes': [{'id': 'n1'}], 'switch_nodes': [], 'links_detail': []})
    monkeypatch.setattr(backend, '_build_topology_graph_from_session_xml', lambda path: ([{'id': 'n1'}], [], {}))
    monkeypatch.setattr(backend, '_list_active_core_sessions', lambda *args, **kwargs: [{'id': 9, 'file': str(saved_file)}])
    monkeypatch.setattr(backend, '_flow_state_from_latest_xml', lambda scenario_norm: None)

    resp = client.get('/core/details?session_id=9')

    assert resp.status_code == 200
    assert b'session-9.xml' in resp.data


def test_core_details_falls_back_to_existing_scenario_path(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    scenario_file = tmp_path / 'alpha.xml'
    scenario_file.write_text('<session><container /></session>', encoding='utf-8')

    monkeypatch.setattr(backend, '_load_run_history', lambda: [])
    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda history=None, user=None: (['Alpha'], {'alpha': {str(scenario_file)}}, {}),
    )
    monkeypatch.setattr(backend, '_core_config_for_request', lambda **kwargs: {'host': '127.0.0.1', 'port': 50051})
    monkeypatch.setattr(backend, '_validate_core_xml', lambda path: (False, 'schema mismatch'))
    monkeypatch.setattr(backend, '_analyze_core_xml', lambda path: {'nodes': [{'id': 'n1'}], 'switch_nodes': [], 'links_detail': []})
    monkeypatch.setattr(backend, '_build_topology_graph_from_session_xml', lambda path: ([{'id': 'n1'}], [], {}))
    monkeypatch.setattr(backend, '_list_active_core_sessions', lambda *args, **kwargs: [])
    monkeypatch.setattr(backend, '_flow_state_from_latest_xml', lambda scenario_norm: None)

    resp = client.get('/core/details?scenario_name=Alpha')

    assert resp.status_code == 200
    assert b'alpha.xml' in resp.data
import json
import os
import time

from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_api_scenario_latest_xml_returns_saved_path_for_scenario(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    scenario_name = 'LatestXmlScenario'
    payload = {
        'scenarios': [
            {
                'name': scenario_name,
                'base': {'filepath': ''},
                'sections': {
                    'Node Information': {'density': 0, 'items': []},
                    'Routing': {'density': 0.5, 'items': []},
                    'Services': {'density': 0.5, 'items': []},
                    'Traffic': {'density': 0.5, 'items': []},
                    'Vulnerabilities': {'density': 0.5, 'items': []},
                    'Segmentation': {'density': 0.5, 'items': []},
                },
                'notes': '',
            }
        ]
    }

    save_resp = client.post('/save_xml_api', data=json.dumps(payload), content_type='application/json')
    assert save_resp.status_code == 200
    save_data = save_resp.get_json() or {}
    assert save_data.get('ok') is True
    saved_path = save_data.get('result_path')
    assert saved_path and os.path.exists(saved_path)

    latest_resp = client.get('/api/scenario/latest_xml', query_string={'scenario': scenario_name})
    assert latest_resp.status_code == 200
    latest_data = latest_resp.get_json() or {}
    assert latest_data.get('ok') is True
    assert latest_data.get('xml_path') == saved_path


def test_latest_xml_path_for_scenario_falls_back_to_outputs_scan_when_catalog_stale(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    scenario_name = 'NewScenario12'
    scenario_norm = backend._normalize_scenario_label(scenario_name)

    outdir = tmp_path / 'outputs'
    scen_dir_old = outdir / 'scenarios-01'
    scen_dir_new = outdir / 'scenarios-02'
    scen_dir_old.mkdir(parents=True, exist_ok=True)
    scen_dir_new.mkdir(parents=True, exist_ok=True)

    old_xml = scen_dir_old / f'{scenario_name}.xml'
    new_xml = scen_dir_new / f'{scenario_name}.xml'

    xml_text = (
        '<Scenarios>'
        f'<Scenario name="{scenario_name}"><ScenarioEditor/></Scenario>'
        '</Scenarios>'
    )
    old_xml.write_text(xml_text, encoding='utf-8')
    new_xml.write_text(xml_text, encoding='utf-8')

    now = time.time()
    os.utime(old_xml, (now - 100, now - 100))
    os.utime(new_xml, (now, now))

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_current_user', lambda: {'username': 'coreadmin', 'role': 'admin'})
    monkeypatch.setattr(backend, '_scenario_catalog_for_user', lambda *_a, **_k: ([], {}, {}))

    resolved = backend._latest_xml_path_for_scenario(scenario_norm)

    assert resolved == str(new_xml)


def test_filter_history_by_scenario_uses_xml_when_names_missing(tmp_path):
    from webapp import app_backend as backend

    scenario_name = 'HistoryXmlScenario'
    scenario_norm = backend._normalize_scenario_label(scenario_name)
    xml_path = tmp_path / 'history.xml'
    xml_path.write_text(
        '<Scenarios>'
        f'<Scenario name="{scenario_name}"><ScenarioEditor/></Scenario>'
        '</Scenarios>',
        encoding='utf-8',
    )

    history = [
        {
            'timestamp': '2026-02-28T00:00:00+00:00',
            'scenario_names': [],
            'scenario_name': None,
            'xml_path': str(xml_path),
        }
    ]

    filtered = backend._filter_history_by_scenario(history, scenario_norm)

    assert len(filtered) == 1


def test_latest_xml_path_for_scenario_falls_back_to_run_history_when_catalog_empty(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    scenario_name = 'RunHistoryFallback'
    scenario_norm = backend._normalize_scenario_label(scenario_name)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    hist_xml = tmp_path / 'outside' / f'{scenario_name}.xml'
    hist_xml.parent.mkdir(parents=True, exist_ok=True)
    hist_xml.write_text(
        '<Scenarios>'
        f'<Scenario name="{scenario_name}"><ScenarioEditor/></Scenario>'
        '</Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_current_user', lambda: {'username': 'coreadmin', 'role': 'admin'})
    monkeypatch.setattr(backend, '_scenario_catalog_for_user', lambda *_a, **_k: ([], {}, {}))
    monkeypatch.setattr(
        backend,
        '_load_run_history',
        lambda: [
            {
                'timestamp': '2026-02-28T12:34:56+00:00',
                'scenario_names': [],
                'scenario_name': None,
                'xml_path': str(hist_xml),
            }
        ],
    )

    resolved = backend._latest_xml_path_for_scenario(scenario_norm)

    assert resolved == str(hist_xml)


def test_latest_xml_path_for_scenario_ignores_run_history_xml_without_scenario_names(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    scenario_name = 'RunHistoryNoNames'
    scenario_norm = backend._normalize_scenario_label(scenario_name)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    # Session-style XML without <Scenarios>/<Scenario name=...> should not be used
    # as latest scenario XML fallback.
    session_like_xml = tmp_path / 'outside' / 'session-1.xml'
    session_like_xml.parent.mkdir(parents=True, exist_ok=True)
    session_like_xml.write_text('<session><node name="rj45"/></session>', encoding='utf-8')

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_current_user', lambda: {'username': 'coreadmin', 'role': 'admin'})
    monkeypatch.setattr(backend, '_scenario_catalog_for_user', lambda *_a, **_k: ([], {}, {}))
    monkeypatch.setattr(
        backend,
        '_load_run_history',
        lambda: [
            {
                'timestamp': '2026-03-01T12:34:56+00:00',
                'scenario_names': [scenario_name],
                'scenario_name': scenario_name,
                'xml_path': str(session_like_xml),
            }
        ],
    )

    resolved = backend._latest_xml_path_for_scenario(scenario_norm)

    assert resolved is None


def test_api_latest_state_strict_xml_merges_hitl_hints(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    scenario_name = 'Anatest'
    scen_norm = backend._normalize_scenario_label(scenario_name)

    xml_path = tmp_path / 'Anatest.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="Anatest"><ScenarioEditor><HardwareInLoop enabled="true"/></ScenarioEditor></Scenario></Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _norm: str(xml_path))
    monkeypatch.setattr(
        backend,
        '_load_scenario_hitl_validation_from_disk',
        lambda: {
            scen_norm: {
                'proxmox': {'secret_id': 'prox-secret-1', 'validated': True},
                'core': {'core_secret_id': 'core-secret-1', 'validated': True, 'vm_key': 'pve::101'},
            }
        },
    )
    monkeypatch.setattr(backend, '_load_scenario_hitl_config_from_disk', lambda: {})

    resp = client.get('/api/scenario/latest_state', query_string={'scenario': scenario_name})
    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data.get('ok') is True
    scenario_state = data.get('scenario_state') or {}
    hitl = scenario_state.get('hitl') or {}
    prox = hitl.get('proxmox') or {}
    core = hitl.get('core') or {}

    assert prox.get('secret_id') == 'prox-secret-1'
    assert prox.get('validated') is True
    assert core.get('core_secret_id') == 'core-secret-1'
    assert core.get('validated') is True
    assert core.get('vm_key') == 'pve::101'


def test_api_latest_state_prefers_explicit_xml_path_over_latest_lookup(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    scenario_name = 'OrderCheck'
    stale_xml = tmp_path / 'stale.xml'
    fresh_xml = tmp_path / 'fresh.xml'

    stale_xml.write_text(
        '<Scenarios><Scenario name="OrderCheck"><ScenarioEditor><HardwareInLoop enabled="false"/></ScenarioEditor></Scenario></Scenarios>',
        encoding='utf-8',
    )
    fresh_xml.write_text(
        '<Scenarios><Scenario name="OrderCheck"><ScenarioEditor><HardwareInLoop enabled="true"/></ScenarioEditor></Scenario></Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _norm: str(stale_xml))

    resp = client.get(
        '/api/scenario/latest_state',
        query_string={'scenario': scenario_name, 'xml_path': str(fresh_xml)},
    )
    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data.get('ok') is True
    assert data.get('xml_path') == str(fresh_xml)

    scenario_state = data.get('scenario_state') or {}
    hitl = scenario_state.get('hitl') or {}
    assert hitl.get('enabled') is True


def test_save_then_latest_state_roundtrip_preserves_hitl_and_sections(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    save_payload = {
        'scenarios': [
            {
                'name': 'Anatest',
                'base': {'filepath': ''},
                'hitl': {
                    'enabled': True,
                    'bridge_validated': True,
                    'core': {
                        'vm_key': 'pve::101',
                        'core_secret_id': 'core-secret-1',
                        'validated': True,
                        'last_validated_at': '2026-03-05T10:00:00',
                    },
                    'proxmox': {
                        'secret_id': 'prox-secret-1',
                        'validated': True,
                        'url': 'https://proxmox.local',
                        'last_validated_at': '2026-03-05T10:00:00',
                    },
                    'interfaces': [
                        {'name': 'en0', 'attachment': 'existing_router'},
                    ],
                },
                'sections': {
                    'Node Information': {
                        'density': 0,
                        'items': [
                            {'selected': 'Docker', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 3},
                        ],
                    },
                    'Routing': {
                        'density': 0.5,
                        'items': [
                            {'selected': 'RIP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
                        ],
                    },
                    'Services': {'density': 0.5, 'items': []},
                    'Traffic': {'density': 0.5, 'items': []},
                    'Vulnerabilities': {'density': 0.5, 'items': []},
                    'Segmentation': {'density': 0.5, 'items': []},
                },
            }
        ]
    }

    saved = client.post('/save_xml_api', data=json.dumps(save_payload), content_type='application/json')
    assert saved.status_code == 200
    saved_data = saved.get_json() or {}
    assert saved_data.get('ok') is True
    assert saved_data.get('result_path')

    latest = client.get('/api/scenario/latest_state', query_string={'scenario': 'Anatest'})
    assert latest.status_code == 200
    latest_data = latest.get_json() or {}
    assert latest_data.get('ok') is True

    scen = latest_data.get('scenario_state') or {}
    hitl = scen.get('hitl') or {}
    core = hitl.get('core') or {}
    prox = hitl.get('proxmox') or {}

    assert core.get('validated') is True
    assert core.get('core_secret_id') == 'core-secret-1'
    assert core.get('vm_key') == 'pve::101'
    assert prox.get('validated') is True
    assert prox.get('secret_id') == 'prox-secret-1'
    assert hitl.get('bridge_validated') is True

    sections = scen.get('sections') or {}
    ni_items = (sections.get('Node Information') or {}).get('items') or []
    routing_items = (sections.get('Routing') or {}).get('items') or []
    assert ni_items and ni_items[0].get('selected') == 'Docker'
    assert routing_items and routing_items[0].get('selected') == 'RIP'

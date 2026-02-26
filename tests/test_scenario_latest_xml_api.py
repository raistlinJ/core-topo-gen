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
                    'Events': {'density': 0.5, 'items': []},
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

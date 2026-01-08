import json
import os
from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_save_xml_api_writes_file(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)
    # Ensure outputs dir is under tmp to avoid polluting repo
    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    def fake_outputs_dir():
        return str(outdir)

    monkeypatch.setattr(backend, '_outputs_dir', fake_outputs_dir)

    payload = {
        "scenarios": [
            {
                "name": "TestScenario",
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {"density": 0, "items": []},
                    "Routing": {"density": 0.5, "items": []},
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []}
                },
                "notes": ""
            }
        ]
    }

    resp = client.post('/save_xml_api', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('ok') is True
    path = data.get('result_path')
    assert path and os.path.isabs(path)
    assert os.path.exists(path)


def test_save_xml_api_vulnerabilities_category_roundtrip_preserves_type_vector(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    payload = {
        "scenarios": [
            {
                "name": "VulnCategoryRoundTrip",
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {"density": 0, "items": []},
                    "Routing": {"density": 0.5, "items": []},
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {
                        "density": 0.5,
                        "items": [
                            {
                                "selected": "Category",
                                "factor": 1.0,
                                "v_metric": "Weight",
                                "v_type": "docker-compose",
                                "v_vector": "network",
                            }
                        ],
                    },
                    "Segmentation": {"density": 0.5, "items": []},
                },
                "notes": "",
            }
        ]
    }

    resp = client.post('/save_xml_api', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('ok') is True
    path = data.get('result_path')
    assert path and os.path.isabs(path)
    assert os.path.exists(path)

    # XML should use schema label Type/Vector but preserve type/vector attrs.
    xml_text = open(path, 'r', encoding='utf-8', errors='ignore').read()
    assert 'name="Vulnerabilities"' in xml_text
    assert 'selected="Type/Vector"' in xml_text
    assert 'v_type="docker-compose"' in xml_text
    assert 'v_vector="network"' in xml_text

    # Re-parse should normalize selection to UI label Category.
    parsed = backend._parse_scenarios_xml(path)
    scen0 = (parsed.get('scenarios') or [])[0]
    vuln = scen0['sections']['Vulnerabilities']
    items = vuln.get('items') or []
    assert len(items) == 1
    assert items[0].get('selected') == 'Category'
    assert items[0].get('v_type') == 'docker-compose'
    assert items[0].get('v_vector') == 'network'
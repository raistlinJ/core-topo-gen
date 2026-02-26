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


def test_save_xml_api_topology_bounds_roundtrip_persists(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    payload = {
        "scenarios": [
            {
                "name": "TopologyBoundsRoundTrip",
                "density_count": 20,
                "density_count_min_enabled": True,
                "density_count_min": 12,
                "density_count_max_enabled": True,
                "density_count_max": 42,
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {
                        "density": 0,
                        "node_count_min_enabled": True,
                        "node_count_min": 5,
                        "node_count_max_enabled": True,
                        "node_count_max": 50,
                        "items": [
                            {"selected": "Docker", "factor": 1.0, "v_metric": "Count", "v_count": 5}
                        ],
                    },
                    "Routing": {"density": 0.5, "items": []},
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []},
                },
                "notes": "",
            }
        ]
    }

    resp = client.post('/save_xml_api', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data.get('ok') is True
    path = data.get('result_path')
    assert path and os.path.isabs(path)
    assert os.path.exists(path)

    xml_text = open(path, 'r', encoding='utf-8', errors='ignore').read()
    assert 'density_count_min_enabled="true"' in xml_text
    assert 'density_count_min="12"' in xml_text
    assert 'density_count_max_enabled="true"' in xml_text
    assert 'density_count_max="42"' in xml_text
    assert 'node_count_min_enabled="true"' in xml_text
    assert 'node_count_min="5"' in xml_text
    assert 'node_count_max_enabled="true"' in xml_text
    assert 'node_count_max="50"' in xml_text

    parsed = backend._parse_scenarios_xml(path)
    scen0 = (parsed.get('scenarios') or [])[0]
    assert scen0.get('density_count_min_enabled') is True
    assert scen0.get('density_count_min') == 12
    assert scen0.get('density_count_max_enabled') is True
    assert scen0.get('density_count_max') == 42
    ni = scen0.get('sections', {}).get('Node Information', {})
    assert ni.get('node_count_min_enabled') is True
    assert ni.get('node_count_min') == 5
    assert ni.get('node_count_max_enabled') is True
    assert ni.get('node_count_max') == 50


def test_save_xml_api_topology_roundtrip_preserves_section_fields(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    payload = {
        "scenarios": [
            {
                "name": "TopologyRoundTripFull",
                "density_count": 25,
                "density_count_min_enabled": True,
                "density_count_min": 10,
                "density_count_max_enabled": True,
                "density_count_max": 80,
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {
                        "density": 0,
                        "node_count_min_enabled": True,
                        "node_count_min": 8,
                        "node_count_max_enabled": True,
                        "node_count_max": 40,
                        "items": [
                            {"selected": "Docker", "factor": 0.6, "v_metric": "Weight"},
                            {"selected": "Workstation", "factor": 0.4, "v_metric": "Weight"},
                        ],
                    },
                    "Routing": {
                        "density": 0.4,
                        "node_count_min_enabled": True,
                        "node_count_min": 3,
                        "node_count_max_enabled": True,
                        "node_count_max": 9,
                        "items": [
                            {
                                "selected": "OSPFv2",
                                "factor": 1.0,
                                "v_metric": "Count",
                                "v_count": 4,
                                "r2r_mode": "Exact",
                                "r2r_edges": 2,
                                "r2s_mode": "Exact",
                                "r2s_edges": 2,
                                "r2s_hosts_min": 2,
                                "r2s_hosts_max": 6,
                            }
                        ],
                    },
                    "Services": {
                        "density": 0.3,
                        "node_count_min_enabled": True,
                        "node_count_min": 1,
                        "items": [{"selected": "SSH", "factor": 1.0, "v_metric": "Count", "v_count": 2}],
                    },
                    "Traffic": {
                        "density": 0.7,
                        "items": [
                            {
                                "selected": "Random",
                                "factor": 1.0,
                                "pattern": "bursty",
                                "rate_kbps": 256,
                                "period_s": 2,
                                "jitter_pct": 15,
                                "content_type": "json",
                            }
                        ],
                    },
                    "Events": {
                        "density": 0.1,
                        "items": [
                            {"selected": "Specific", "factor": 1.0, "script_path": "/tmp/test_event.sh"}
                        ],
                    },
                    "Vulnerabilities": {
                        "density": 0.6,
                        "flag_type": "text",
                        "items": [
                            {
                                "selected": "Category",
                                "factor": 1.0,
                                "v_metric": "Count",
                                "v_count": 3,
                                "v_type": "docker-compose",
                                "v_vector": "network",
                            }
                        ],
                    },
                    "Segmentation": {
                        "density": 0.2,
                        "items": [{"selected": "NAT", "factor": 1.0}],
                    },
                },
                "notes": "roundtrip",
            }
        ]
    }

    resp = client.post('/save_xml_api', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data.get('ok') is True
    path = data.get('result_path')
    assert path and os.path.isabs(path)
    assert os.path.exists(path)

    parsed = backend._parse_scenarios_xml(path)
    scen0 = (parsed.get('scenarios') or [])[0]

    assert scen0.get('density_count') == 25
    assert scen0.get('density_count_min_enabled') is True
    assert scen0.get('density_count_min') == 10
    assert scen0.get('density_count_max_enabled') is True
    assert scen0.get('density_count_max') == 80

    secs = scen0.get('sections', {})
    ni = secs.get('Node Information', {})
    assert ni.get('node_count_min_enabled') is True
    assert ni.get('node_count_min') == 8
    assert ni.get('node_count_max_enabled') is True
    assert ni.get('node_count_max') == 40

    routing = secs.get('Routing', {})
    assert routing.get('node_count_min_enabled') is True
    assert routing.get('node_count_min') == 3
    assert routing.get('node_count_max_enabled') is True
    assert routing.get('node_count_max') == 9
    r0 = (routing.get('items') or [])[0]
    assert r0.get('v_count') == 4
    assert r0.get('r2r_mode') == 'Exact'
    assert r0.get('r2r_edges') == 2
    assert r0.get('r2s_mode') == 'Exact'
    assert r0.get('r2s_edges') == 2
    assert r0.get('r2s_hosts_min') == 2
    assert r0.get('r2s_hosts_max') == 6

    traffic = secs.get('Traffic', {})
    t0 = (traffic.get('items') or [])[0]
    assert t0.get('pattern') == 'bursty'
    assert float(t0.get('rate_kbps')) == 256.0
    assert float(t0.get('period_s')) == 2.0
    assert float(t0.get('jitter_pct')) == 15.0
    assert t0.get('content_type') == 'json'

    events = secs.get('Events', {})
    e0 = (events.get('items') or [])[0]
    assert e0.get('script_path') == '/tmp/test_event.sh'

    vulns = secs.get('Vulnerabilities', {})
    assert vulns.get('flag_type') == 'text'
    v0 = (vulns.get('items') or [])[0]
    assert v0.get('selected') == 'Category'
    assert v0.get('v_metric') == 'Count'
    assert v0.get('v_count') == 3
    assert v0.get('v_type') == 'docker-compose'
    assert v0.get('v_vector') == 'network'

    assert scen0.get('notes') == 'roundtrip'
import json
import os
import re
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


def test_save_xml_api_accepts_empty_scenarios_and_persists_snapshot(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    payload = {"scenarios": [], "active_index": 0}

    resp = client.post('/save_xml_api', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('ok') is True
    assert data.get('result_path') is None
    assert data.get('scenario_paths_by_index') == []

    snapshot = backend._load_editor_state_snapshot({'username': 'coreadmin', 'role': 'admin'})
    assert snapshot is not None
    assert snapshot.get('scenarios') == []
    assert snapshot.get('result_path') is None


def test_editor_snapshot_api_accepts_empty_scenario_list(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    resp = client.post(
        '/api/editor_snapshot',
        data=json.dumps({"scenarios": [], "active_index": 0}),
        content_type='application/json',
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data == {'success': True}

    snapshot = backend._load_editor_state_snapshot({'username': 'coreadmin', 'role': 'admin'})
    assert snapshot is not None
    assert snapshot.get('scenarios') == []


def test_index_preserves_empty_snapshot_on_reload(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    saved = client.post(
        '/api/editor_snapshot',
        data=json.dumps({"scenarios": [], "active_index": 0}),
        content_type='application/json',
    )
    assert saved.status_code == 200

    resp = client.get('/')
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    match = re.search(r'<script id="payload-data" type="application/json">(.*?)</script>', html, re.S)
    assert match is not None
    payload = json.loads(match.group(1))
    assert payload.get('scenarios') == []
    assert payload.get('editor_snapshot', {}).get('scenarios') == []


def test_index_without_catalog_or_snapshot_renders_empty_payload(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    resp = client.get('/')
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    match = re.search(r'<script id="payload-data" type="application/json">(.*?)</script>', html, re.S)
    assert match is not None
    payload = json.loads(match.group(1))
    assert payload.get('scenarios') == []


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


def test_save_xml_api_preserves_hitl_when_payload_omits_hitl(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    existing_xml = tmp_path / 'existing-anatest.xml'
    existing_xml.write_text(
        """<?xml version='1.0' encoding='utf-8'?>
<Scenarios>
  <Scenario name="Anatest">
    <ScenarioEditor>
      <section name="Node Information" density="0" />
      <section name="Routing" density="0.5" />
      <section name="Services" density="0.5" />
      <section name="Traffic" density="0.5" />
      <section name="Vulnerabilities" density="0.5" />
      <section name="Segmentation" density="0.5" />
      <hardwareinloop enabled="true">
        <proxmoxconnection username="root@pam" validated="true" secret_id="prox-secret-1" />
        <coreconnection grpc_host="localhost" grpc_port="50051" validated="true" core_secret_id="core-secret-1" />
      </hardwareinloop>
    </ScenarioEditor>
  </Scenario>
</Scenarios>
""",
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_latest_xml_path_for_scenario',
        lambda norm: str(existing_xml) if norm == backend._normalize_scenario_label('Anatest') else None,
    )

    save_payload = {
        'project_key_hint': str(existing_xml),
        'scenarios': [
            {
                'name': 'Anatest',
                'saved_xml_path': str(existing_xml),
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
                # Intentionally omits 'hitl'
                'notes': '',
            }
        ]
    }

    resp = client.post('/save_xml_api', data=json.dumps(save_payload), content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data.get('ok') is True
    path = data.get('result_path')
    assert path and os.path.exists(path)

    parsed = backend._parse_scenarios_xml(path)
    scen = (parsed.get('scenarios') or [])[0]
    hitl = scen.get('hitl') if isinstance(scen.get('hitl'), dict) else {}
    core = hitl.get('core') if isinstance(hitl.get('core'), dict) else {}
    prox = hitl.get('proxmox') if isinstance(hitl.get('proxmox'), dict) else {}

    assert core.get('validated') is True
    assert prox.get('validated') is True


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


def test_save_xml_api_hydrates_summary_only_payload_from_project_hint(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    original_payload = {
        "scenarios": [
            {
                "name": "Anatest",
                "density_count": 10,
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {
                        "density": 0,
                        "items": [
                            {"selected": "Docker", "factor": 1.0, "v_metric": "Count", "v_count": 5}
                        ],
                    },
                    "Routing": {
                        "density": 0.5,
                        "items": [
                            {
                                "selected": "RIP",
                                "factor": 1.0,
                                "v_metric": "Weight",
                                "r2r_mode": "NonUniform",
                            }
                        ],
                    },
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {
                        "density": 0.5,
                        "items": [
                            {"selected": "Specific", "factor": 1.0, "v_metric": "Count", "v_name": "redis/CVE-2022-0543", "v_count": 1}
                        ],
                    },
                    "Segmentation": {"density": 0.5, "items": []},
                },
                "notes": "seed",
            }
        ]
    }

    first = client.post('/save_xml_api', data=json.dumps(original_payload), content_type='application/json')
    assert first.status_code == 200
    first_data = first.get_json() or {}
    assert first_data.get('ok') is True
    source_xml = first_data.get('result_path')
    assert source_xml and os.path.exists(source_xml)

    summary_only_payload = {
        "project_key_hint": source_xml,
        "scenario_query": "Anatest",
        "scenarios": [
            {
                "name": "Anatest",
                "density_count": 10,
                "scenario_total_nodes": 10,
                "sections": {
                    "Node Information": {
                        "density": 0,
                        "base_nodes": 10,
                        "additional_nodes": 0,
                        "combined_nodes": 10,
                        "items": [],
                    },
                    "Routing": {"density": 0.5, "items": []},
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []},
                },
            }
        ],
    }

    second = client.post('/save_xml_api', data=json.dumps(summary_only_payload), content_type='application/json')
    assert second.status_code == 200
    second_data = second.get_json() or {}
    assert second_data.get('ok') is True
    result_xml = second_data.get('result_path')
    assert result_xml and os.path.exists(result_xml)

    parsed = backend._parse_scenarios_xml(result_xml)
    scen0 = (parsed.get('scenarios') or [])[0]
    secs = scen0.get('sections', {})

    ni_items = (secs.get('Node Information', {}) or {}).get('items') or []
    routing_items = (secs.get('Routing', {}) or {}).get('items') or []
    vuln_items = (secs.get('Vulnerabilities', {}) or {}).get('items') or []

    assert len(ni_items) == 1
    assert ni_items[0].get('selected') == 'Docker'
    assert len(routing_items) == 1
    assert routing_items[0].get('selected') == 'RIP'
    assert len(vuln_items) == 1
    assert vuln_items[0].get('v_name') == 'redis/CVE-2022-0543'


def test_save_xml_api_marks_topology_dirty_when_topology_changes(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    base_payload = {
        "scenarios": [
            {
                "name": "DirtyTopo",
                "density_count": 8,
                "base": {"filepath": ""},
                "flow_state": {
                    "length": 2,
                    "chain_ids": ["n1", "n2"],
                    "flow_enabled": True,
                },
                "sections": {
                    "Node Information": {
                        "density": 0,
                        "items": [
                            {"selected": "Docker", "factor": 1.0, "v_metric": "Count", "v_count": 4}
                        ],
                    },
                    "Routing": {
                        "density": 0.5,
                        "items": [
                            {"selected": "RIP", "factor": 1.0, "v_metric": "Weight", "r2r_mode": "NonUniform"}
                        ],
                    },
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []},
                },
            }
        ]
    }

    first = client.post('/save_xml_api', data=json.dumps(base_payload), content_type='application/json')
    assert first.status_code == 200
    first_data = first.get_json() or {}
    assert first_data.get('ok') is True
    source_xml = first_data.get('result_path')
    assert source_xml and os.path.exists(source_xml)

    changed_payload = {
        "project_key_hint": source_xml,
        "scenario_query": "DirtyTopo",
        "scenarios": [
            {
                "name": "DirtyTopo",
                "density_count": 8,
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {
                        "density": 0,
                        "items": [
                            {"selected": "Docker", "factor": 1.0, "v_metric": "Count", "v_count": 5}
                        ],
                    },
                    "Routing": {
                        "density": 0.5,
                        "items": [
                            {"selected": "RIP", "factor": 1.0, "v_metric": "Weight", "r2r_mode": "Exact"}
                        ],
                    },
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []},
                },
            }
        ],
    }

    second = client.post('/save_xml_api', data=json.dumps(changed_payload), content_type='application/json')
    assert second.status_code == 200
    second_data = second.get_json() or {}
    assert second_data.get('ok') is True
    result_xml = second_data.get('result_path')
    assert result_xml and os.path.exists(result_xml)

    parsed = backend._parse_scenarios_xml(result_xml)
    scen0 = (parsed.get('scenarios') or [])[0]
    flow_state = scen0.get('flow_state') or {}
    assert flow_state.get('topology_dirty') is True
    assert flow_state.get('topology_dirty_reason') == 'topology_or_ip_changed'
    assert (flow_state.get('chain_ids') or []) == []
    assert (flow_state.get('flag_assignments') or []) == []
    assert flow_state.get('length') == 0


def test_save_xml_api_preserves_hitl_validation_state_roundtrip(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    payload = {
        "scenarios": [
            {
                "name": "Anatest",
                "base": {"filepath": ""},
                "hitl": {
                    "enabled": True,
                    "core": {
                        "vm_key": "pve::101",
                        "vm_node": "pve",
                        "core_secret_id": "core-secret-1",
                        "validated": True,
                        "last_validated_at": "2026-03-03T00:00:00",
                    },
                    "proxmox": {
                        "url": "https://proxmox.local",
                        "username": "root@pam",
                        "port": 8006,
                        "verify_ssl": False,
                        "remember_credentials": True,
                        "secret_id": "prox-secret-1",
                        "validated": True,
                        "last_validated_at": "2026-03-03T00:00:00",
                    },
                    "interfaces": [{
                        "name": "en0",
                        "core_bridge": "vmbr1",
                        "attachment": "existing_router",
                        "proxmox_target": {
                            "node": "pve",
                            "vmid": "101",
                            "interface_id": "net0",
                            "bridge": "vmbr1",
                            "vm_name": "participant-1",
                        },
                        "external_vm": {
                            "vm_key": "pve::101",
                            "vm_node": "pve",
                            "vm_name": "participant-1",
                            "vmid": "101",
                            "interface_id": "net0",
                            "interface_bridge": "vmbr1",
                        },
                    }],
                },
                "sections": {
                    "Node Information": {"density": 0, "items": []},
                    "Routing": {"density": 0.5, "items": []},
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []},
                },
            }
        ]
    }

    resp = client.post('/save_xml_api', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data.get('ok') is True
    path = data.get('result_path')
    assert path and os.path.exists(path)

    parsed = backend._parse_scenarios_xml(path)
    scen0 = (parsed.get('scenarios') or [])[0]
    hitl = scen0.get('hitl') or {}
    core = hitl.get('core') or {}
    prox = hitl.get('proxmox') or {}

    assert core.get('core_secret_id') == 'core-secret-1'
    assert core.get('validated') is True
    assert core.get('vm_key') == 'pve::101'

    assert prox.get('secret_id') == 'prox-secret-1'
    assert prox.get('validated') is True
    assert prox.get('url') == 'https://proxmox.local'
    assert prox.get('username') == 'root@pam'
    assert prox.get('remember_credentials') is True

    interfaces = hitl.get('interfaces') or []
    assert interfaces and interfaces[0].get('name') == 'en0'
    pve_target = interfaces[0].get('proxmox_target') or {}
    ext_vm = interfaces[0].get('external_vm') or {}
    assert pve_target.get('node') == 'pve'
    assert pve_target.get('interface_id') == 'net0'
    assert ext_vm.get('vm_key') == 'pve::101'
    assert ext_vm.get('interface_bridge') == 'vmbr1'
    assert interfaces[0].get('core_bridge') == 'vmbr1'


def test_save_xml_api_partial_hitl_payload_keeps_verified_readiness(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    # Initial save with full verified HITL state.
    initial_payload = {
        "scenarios": [
            {
                "name": "Anatest",
                "base": {"filepath": ""},
                "hitl": {
                    "enabled": True,
                    "bridge_validated": True,
                    "core": {
                        "vm_key": "pve::101",
                        "core_secret_id": "core-secret-1",
                        "validated": True,
                    },
                    "proxmox": {
                        "secret_id": "prox-secret-1",
                        "validated": True,
                        "url": "https://proxmox.local",
                    },
                    "interfaces": [{"name": "en0", "attachment": "existing_router"}],
                },
                "sections": {
                    "Node Information": {"density": 0, "items": []},
                    "Routing": {"density": 0.5, "items": []},
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []},
                },
            }
        ]
    }
    first = client.post('/save_xml_api', data=json.dumps(initial_payload), content_type='application/json')
    assert first.status_code == 200
    first_data = first.get_json() or {}
    assert first_data.get('ok') is True
    first_path = first_data.get('result_path')
    assert first_path and os.path.exists(first_path)

    # Follow-up save with a partial HITL payload (simulates delayed autosave/editor snapshot)
    # that omits readiness-critical fields.
    partial_payload = {
        "project_key_hint": first_path,
        "scenario_query": "Anatest",
        "scenarios": [
            {
                "name": "Anatest",
                "base": {"filepath": ""},
                "hitl": {
                    "enabled": True,
                    "core": {"vm_name": "CORE VM"},
                    "proxmox": {"url": "https://proxmox.local"},
                    "interfaces": [{"name": "en0", "attachment": "existing_router"}],
                },
                "sections": {
                    "Node Information": {"density": 0, "items": []},
                    "Routing": {"density": 0.5, "items": []},
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []},
                },
            }
        ]
    }

    second = client.post('/save_xml_api', data=json.dumps(partial_payload), content_type='application/json')
    assert second.status_code == 200
    second_data = second.get_json() or {}
    assert second_data.get('ok') is True
    second_path = second_data.get('result_path')
    assert second_path and os.path.exists(second_path)

    parsed = backend._parse_scenarios_xml(second_path)
    scen0 = (parsed.get('scenarios') or [])[0]
    hitl = scen0.get('hitl') or {}
    core = hitl.get('core') or {}
    prox = hitl.get('proxmox') or {}

    # Readiness-critical fields must survive partial save payloads.
    assert core.get('core_secret_id') == 'core-secret-1'
    assert core.get('validated') is True
    assert core.get('vm_key') == 'pve::101'
    assert prox.get('secret_id') == 'prox-secret-1'
    assert prox.get('validated') is True
    assert hitl.get('bridge_validated') is True


def test_save_xml_api_partial_payload_preserves_unrelated_sections(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    initial_payload = {
        "scenarios": [
            {
                "name": "Anatest",
                "density_count": 12,
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {
                        "density": 0,
                        "items": [{"selected": "Docker", "factor": 1.0, "v_metric": "Count", "v_count": 3}],
                    },
                    "Routing": {
                        "density": 0.5,
                        "items": [{"selected": "RIP", "factor": 1.0, "v_metric": "Count", "v_count": 2}],
                    },
                    "Services": {"density": 0.5, "items": [{"selected": "SSH", "factor": 1.0, "v_metric": "Count", "v_count": 1}]},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []},
                },
            }
        ]
    }

    first = client.post('/save_xml_api', data=json.dumps(initial_payload), content_type='application/json')
    assert first.status_code == 200
    first_data = first.get_json() or {}
    assert first_data.get('ok') is True
    first_path = first_data.get('result_path')
    assert first_path and os.path.exists(first_path)

    # Update only Node Information; omit Routing/Services in payload.
    partial_payload = {
        "project_key_hint": first_path,
        "scenario_query": "Anatest",
        "scenarios": [
            {
                "name": "Anatest",
                "density_count": 12,
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {
                        "density": 0,
                        "items": [{"selected": "Docker", "factor": 1.0, "v_metric": "Count", "v_count": 5}],
                    }
                },
            }
        ],
    }

    second = client.post('/save_xml_api', data=json.dumps(partial_payload), content_type='application/json')
    assert second.status_code == 200
    second_data = second.get_json() or {}
    assert second_data.get('ok') is True
    second_path = second_data.get('result_path')
    assert second_path and os.path.exists(second_path)

    parsed = backend._parse_scenarios_xml(second_path)
    scen0 = (parsed.get('scenarios') or [])[0]
    sections = scen0.get('sections') or {}

    # Provided field updates.
    ni = sections.get('Node Information') or {}
    ni_items = ni.get('items') or []
    assert ni_items and ni_items[0].get('v_count') == 5

    # Omitted sections remain unchanged from prior XML.
    routing = sections.get('Routing') or {}
    routing_items = routing.get('items') or []
    assert routing_items and routing_items[0].get('selected') == 'RIP'
    assert routing_items[0].get('v_count') == 2

    services = sections.get('Services') or {}
    services_items = services.get('items') or []
    assert services_items and services_items[0].get('selected') == 'SSH'
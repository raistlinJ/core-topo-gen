import json
import os
import shutil
import tempfile
import uuid

from webapp import app_backend


def _seed_xml_plan(scenario: str, full_preview: dict, flow_meta: dict | None = None) -> tuple[str, str]:
        td = tempfile.mkdtemp(prefix="coretg-flow-persist-")
        xml_path = os.path.join(td, f"{scenario}.xml")
        xml = f"""<Scenarios>
    <Scenario name='{scenario}'>
        <ScenarioEditor>
            <section name='Node Information'>
                <item selected='Docker' v_metric='Count' v_count='2'/>
            </section>
            <section name='Routing' density='0.0'></section>
            <section name='Services' density='0.0'></section>
            <section name='Vulnerabilities' density='0.0'></section>
            <section name='Segmentation' density='0.0'></section>
            <section name='Traffic' density='0.0'></section>
        </ScenarioEditor>
    </Scenario>
</Scenarios>"""
        with open(xml_path, "w", encoding="utf-8") as f:
                f.write(xml)

        payload = {
                "full_preview": full_preview,
                "metadata": {
                        "xml_path": xml_path,
                        "scenario": scenario,
                        "seed": full_preview.get("seed"),
                },
        }
        if isinstance(flow_meta, dict) and flow_meta:
                payload["metadata"]["flow"] = flow_meta
        ok, err = app_backend._update_plan_preview_in_xml(xml_path, scenario, payload)
        assert ok, err
        if isinstance(flow_meta, dict) and flow_meta:
                ok2, err2 = app_backend._update_flow_state_in_xml(xml_path, scenario, flow_meta)
                assert ok2, err2
        return xml_path, td


def test_flag_sequencing_attackflow_preview_reuses_saved_flow_assignments(tmp_path):
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()

    # Authenticate (Flow endpoints are protected under /api/).
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-flow-{uuid.uuid4().hex[:10]}"

    # Create a minimal preview plan payload with two docker hosts and embedded flow metadata.
    full_preview = {
        'seed': 123,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'hosts': [
            {'node_id': 'h1', 'name': 'host-1', 'role': 'Docker', 'vulnerabilities': []},
            {'node_id': 'h2', 'name': 'host-2', 'role': 'Docker', 'vulnerabilities': [{'id': 'dummy'}]},
        ],
        'host_router_map': {},
        'r2r_links_preview': [],
    }

    saved_chain = [
        {'id': 'h2', 'name': 'host-2', 'type': 'docker'},
        {'id': 'h1', 'name': 'host-1', 'type': 'docker'},
    ]
    saved_assignments = [
        {
            'node_id': 'h2',
            'id': 'textfile_username_password',
            'name': 'Saved Gen 2',
            'type': 'flag-generator',
            'hint': 'saved hint 2',
            'outputs': ['network.ip'],
        },
        {
            'node_id': 'h1',
            'id': 'nfs_sensitive_file',
            'name': 'Saved Gen 1',
            'type': 'flag-node-generator',
            'hint': 'saved hint 1',
            'inputs': ['network.ip'],
            'outputs': ['credential.pair'],
        },
    ]

    plan_path, plan_dir = _seed_xml_plan(
        scenario,
        full_preview,
        flow_meta={
            'scenario': scenario,
            'length': 2,
            'chain': saved_chain,
            'flag_assignments': saved_assignments,
            'modified_at': '2026-01-06T00:00:00Z',
        },
    )

    try:
        # Now fetch preview using this plan explicitly.
        resp = client.get('/api/flag-sequencing/attackflow_preview', query_string={
            'scenario': scenario,
            'length': 2,
            'preview_plan': plan_path,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data and data.get('ok') is True

        # Chain order should match saved chain.
        chain = data.get('chain') or []
        assert [c.get('id') for c in chain] == ['h2', 'h1']

        # Assignments should be the persisted ones (not recomputed).
        fas = data.get('flag_assignments') or []
        assert [fa.get('id') for fa in fas] == ['textfile_username_password', 'nfs_sensitive_file']
        hints = [fa.get('hint') for fa in fas]
        assert all(isinstance(h, str) and h.strip() for h in hints)
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


def test_flag_sequencing_reload_with_default_length_does_not_break_saved_chain(tmp_path):
    """If the UI reloads with the default length, a shorter saved chain should still load."""
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-flow-len-{uuid.uuid4().hex[:10]}"

    full_preview = {
        'seed': 123,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'hosts': [
            {'node_id': 'h1', 'name': 'host-1', 'role': 'Docker', 'vulnerabilities': []},
            {'node_id': 'h2', 'name': 'host-2', 'role': 'Docker', 'vulnerabilities': []},
        ],
        'host_router_map': {},
        'r2r_links_preview': [],
    }

    saved_chain = [
        {'id': 'h2', 'name': 'host-2', 'type': 'docker'},
        {'id': 'h1', 'name': 'host-1', 'type': 'docker'},
    ]
    saved_assignments = [
        {
            'node_id': 'h2',
            'id': 'textfile_username_password',
            'name': 'Saved Gen 2',
            'type': 'flag-generator',
            'hint': 'saved hint 2',
            'outputs': ['network.ip'],
        },
        {
            'node_id': 'h1',
            'id': 'nfs_sensitive_file',
            'name': 'Saved Gen 1',
            'type': 'flag-node-generator',
            'hint': 'saved hint 1',
            'inputs': ['network.ip'],
            'outputs': ['credential.pair'],
        },
    ]

    plan_path, plan_dir = _seed_xml_plan(
        scenario,
        full_preview,
        flow_meta={
            'scenario': scenario,
            'length': 2,
            'chain': saved_chain,
            'flag_assignments': saved_assignments,
            'modified_at': '2026-01-06T00:00:00Z',
        },
    )

    try:
        resp = client.get('/api/flag-sequencing/attackflow_preview', query_string={
            'scenario': scenario,
            # Simulate a page reload where the length input defaulted back to 5.
            'length': 5,
            'preview_plan': plan_path,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data and data.get('ok') is True
        assert data.get('length') == 2
        chain = data.get('chain') or []
        assert [c.get('id') for c in chain] == ['h2', 'h1']
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


def test_flow_state_flag_inject_roundtrip_saved_and_loaded_from_xml(tmp_path, monkeypatch):
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario_name = 'FlowRoundtripScenario'
    scenario_norm = app_backend._normalize_scenario_label(scenario_name)

    xml_path = tmp_path / f'{scenario_name}.xml'
    xml_path.write_text(
        '<Scenarios>'
        f'<Scenario name="{scenario_name}"><ScenarioEditor/></Scenario>'
        '</Scenarios>',
        encoding='utf-8',
    )

    # Ensure participant topology resolves this scenario to our test XML.
    monkeypatch.setattr(
        app_backend,
        '_latest_xml_path_for_scenario',
        lambda norm: str(xml_path) if norm == scenario_norm else None,
    )

    flow_state = {
        'chain_ids': ['live-proof'],
        'flag_assignments': [
            {
                'chain_id': 'live-proof',
                'step_id': 'proof-step',
                'inject_files': ['flag.txt -> /tmp'],
                'vulnerabilities': [{'name': 'xstream/CVE-2021-29505'}],
            }
        ],
    }

    save_resp = client.post(
        '/api/flag-sequencing/save_flow_state_to_xml',
        data=json.dumps(
            {
                'xml_path': str(xml_path),
                'scenario': scenario_name,
                'flow_state': flow_state,
            }
        ),
        content_type='application/json',
    )
    assert save_resp.status_code == 200
    save_data = save_resp.get_json() or {}
    assert save_data.get('ok') is True

    xml_flow = app_backend._flow_state_from_xml_path(str(xml_path), scenario_name)
    assert isinstance(xml_flow, dict)
    xml_assignments = xml_flow.get('flag_assignments') if isinstance(xml_flow, dict) else []
    assert isinstance(xml_assignments, list) and xml_assignments
    xml_injects = xml_assignments[0].get('inject_files') if isinstance(xml_assignments[0], dict) else []
    assert isinstance(xml_injects, list)
    assert 'flag.txt -> /tmp' in xml_injects

    topo_resp = client.get('/participant-ui/topology', query_string={'scenario': scenario_name})
    assert topo_resp.status_code == 200
    topo_data = topo_resp.get_json() or {}
    assert topo_data.get('ok') is True
    flow_meta = topo_data.get('flow') if isinstance(topo_data.get('flow'), dict) else {}
    topo_assignments = flow_meta.get('flag_assignments') if isinstance(flow_meta, dict) else []
    assert isinstance(topo_assignments, list) and topo_assignments
    topo_injects = topo_assignments[0].get('inject_files') if isinstance(topo_assignments[0], dict) else []
    assert isinstance(topo_injects, list)
    assert 'flag.txt -> /tmp' in topo_injects


def test_attackflow_preview_returns_vuln_assignment_with_flag_inject(tmp_path):
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = f"Anatest-{uuid.uuid4().hex[:8]}"
    full_preview = {
        'seed': 123,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'hosts': [
            {'node_id': 'h2', 'name': 'docker-5', 'role': 'Docker', 'vulnerabilities': ['xstream/CVE-2021-29505']},
        ],
        'host_router_map': {},
        'r2r_links_preview': [],
    }

    plan_path, plan_dir = _seed_xml_plan(
        scenario,
        full_preview,
        flow_meta={
            'scenario': scenario,
            'length': 1,
            'chain': [{'id': 'h2', 'name': 'docker-5', 'type': 'docker'}],
            'flag_assignments': [
                {
                    'node_id': 'h2',
                    'id': 'textfile_username_password',
                    'type': 'flag-generator',
                    'vulnerabilities': ['xstream/CVE-2021-29505'],
                    'inject_files': ['flag.txt -> /tmp'],
                }
            ],
            'modified_at': '2026-03-01T00:00:00Z',
        },
    )

    try:
        resp = client.get('/api/flag-sequencing/attackflow_preview', query_string={
            'scenario': scenario,
            'length': 5,
            'preview_plan': plan_path,
            'prefer_flow': '1',
        })
        assert resp.status_code == 200
        data = resp.get_json() or {}
        assert data.get('ok') is True

        assignments = data.get('flag_assignments') or []
        assert isinstance(assignments, list) and assignments

        vuln_rows = []
        for item in assignments:
            if not isinstance(item, dict):
                continue
            vulns = item.get('vulnerabilities') if isinstance(item.get('vulnerabilities'), list) else []
            if any(str(v or '').strip() for v in vulns):
                vuln_rows.append(item)

        assert vuln_rows, 'expected at least one vulnerability assignment row'
        assert any(
            'flag.txt -> /tmp' in [str(x or '').strip() for x in (row.get('inject_files') or [])]
            for row in vuln_rows
        )
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


def test_attackflow_preview_backfills_vuln_assignment_with_default_flag_inject(tmp_path):
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = f"AnatestBackfill-{uuid.uuid4().hex[:8]}"
    full_preview = {
        'seed': 123,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'hosts': [
            {'node_id': 'h2', 'name': 'docker-5', 'role': 'Docker', 'vulnerabilities': ['xstream/CVE-2021-29505']},
        ],
        'host_router_map': {},
        'r2r_links_preview': [],
    }

    plan_path, plan_dir = _seed_xml_plan(
        scenario,
        full_preview,
        flow_meta={
            'scenario': scenario,
            'length': 1,
            'chain': [{'id': 'h2', 'name': 'docker-5', 'type': 'docker'}],
            'flag_assignments': [
                {
                    'node_id': 'h2',
                    'id': 'textfile_username_password',
                    'type': 'flag-generator',
                    'vulnerabilities': ['xstream/CVE-2021-29505'],
                }
            ],
            'modified_at': '2026-03-01T00:00:00Z',
        },
    )

    try:
        resp = client.get('/api/flag-sequencing/attackflow_preview', query_string={
            'scenario': scenario,
            'length': 5,
            'preview_plan': plan_path,
            'prefer_flow': '1',
        })
        assert resp.status_code == 200
        data = resp.get_json() or {}
        assert data.get('ok') is True

        assignments = data.get('flag_assignments') or []
        assert isinstance(assignments, list) and assignments
        assert any(
            'flag.txt -> /tmp' in [str(x or '').strip() for x in (item.get('inject_files') or [])]
            for item in assignments if isinstance(item, dict)
        )
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)

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
            'id': 'binary_embed_text',
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
        assert [fa.get('id') for fa in fas] == ['binary_embed_text', 'nfs_sensitive_file']
        assert [fa.get('hint') for fa in fas] == ['saved hint 2', 'saved hint 1']
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
            'id': 'binary_embed_text',
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

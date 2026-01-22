import json
import os
import time
import uuid

from webapp import app_backend


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

    plan_payload = {
        'full_preview': full_preview,
        'metadata': {
            'xml_path': '/tmp/does-not-matter.xml',
            'scenario': scenario,
            'seed': 123,
            'flow': {
                'scenario': scenario,
                'length': 2,
                'chain': saved_chain,
                'flag_assignments': saved_assignments,
                'modified_at': '2026-01-06T00:00:00Z',
            },
        },
    }

    plan_path = app_backend._canonical_plan_path_for_scenario(scenario, create_dir=True)
    with open(plan_path, 'w', encoding='utf-8') as f:
        json.dump(plan_payload, f)

    try:
        # Ensure the helper prefers the flow plan (scenario is unique).
        chosen = app_backend._latest_preview_plan_for_scenario_norm(scenario)
        assert chosen == plan_path

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
        try:
            os.remove(plan_path)
        except Exception:
            pass


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

    plan_payload = {
        'full_preview': full_preview,
        'metadata': {
            'xml_path': '/tmp/does-not-matter.xml',
            'scenario': scenario,
            'seed': 123,
            'flow': {
                'scenario': scenario,
                'length': 2,
                'chain': saved_chain,
                'flag_assignments': saved_assignments,
                'modified_at': '2026-01-06T00:00:00Z',
            },
        },
    }

    plan_path = app_backend._canonical_plan_path_for_scenario(scenario, create_dir=True)
    with open(plan_path, 'w', encoding='utf-8') as f:
        json.dump(plan_payload, f)

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
        try:
            os.remove(plan_path)
        except Exception:
            pass

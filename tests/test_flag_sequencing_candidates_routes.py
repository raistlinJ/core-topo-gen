from types import SimpleNamespace
import os

from flask import Flask

from webapp.routes import flag_sequencing_candidates


def _build_backend(plan_path: str):
    nodes = [
        {'id': 'v1', 'name': 'Vuln 1', 'type': 'host', 'is_vuln': True},
        {'id': 'd1', 'name': 'Docker 1', 'type': 'docker', 'is_vuln': False},
        {'id': 'd2', 'name': 'Docker 2', 'type': 'DOCKER', 'is_vuln': False},
    ]
    preview_payload = {'full_preview': {'nodes': nodes}}

    return SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _existing_xml_path_or_none=lambda path: path,
        _latest_preview_plan_for_scenario_norm=lambda scenario_norm, prefer_flow=True: plan_path,
        _load_preview_payload_from_path=lambda path, scenario_norm: preview_payload,
        _build_topology_graph_from_preview_plan=lambda preview: (nodes, [], {}),
        _flow_node_is_docker_role=lambda node: str(node.get('type') or '').strip().lower() == 'docker',
        _flag_generators_from_enabled_sources=lambda: ([{'id': 'gen-v', 'name': 'Vuln Gen', '_source_name': 'pack-a'}], None),
        _flag_node_generators_from_enabled_sources=lambda: (
            [
                {'id': 'gen-ok', 'name': 'Docker Gen', '_source_name': 'pack-b'},
                {'id': 'gen-miss', 'name': 'Missing Artifact', '_source_name': 'pack-c'},
            ],
            None,
        ),
        _flow_enabled_plugin_contracts_by_id=lambda: {
            'gen-v': {'produces': [{'artifact': 'cred'}]},
            'gen-ok': {'requires': ['cred']},
            'gen-miss': {'requires': ['token']},
        },
        _flow_synthesized_inputs=lambda: set(),
        os=os,
    )


def _make_client(tmp_path):
    plan_path = tmp_path / 'preview.xml'
    plan_path.write_text('<xml />', encoding='utf-8')

    app = Flask(__name__)
    app.config['TESTING'] = True
    flag_sequencing_candidates.register(app, backend_module=_build_backend(str(plan_path)))
    return app.test_client(), str(plan_path)


def test_substitution_candidates_reports_compatible_and_blocked_generators(tmp_path):
    client, plan_path = _make_client(tmp_path)

    resp = client.post(
        '/api/flag-sequencing/substitution_candidates',
        json={
            'scenario': 'Demo Scenario',
            'index': 1,
            'kind': 'flag-node-generator',
            'chain_ids': ['v1', 'd1'],
            'flag_assignments': [
                {'id': 'gen-v'},
                {'id': 'gen-ok'},
            ],
            'candidate_ids': ['gen-ok', 'gen-miss'],
            'preview_plan': plan_path,
        },
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body['ok'] is True
    assert body['kind'] == 'flag-node-generator'
    assert body['is_vuln'] is False
    assert [entry['id'] for entry in body['candidates']] == ['gen-ok', 'gen-miss']
    assert body['candidates'][0]['compatible'] is True
    assert body['candidates'][1]['compatible'] is False
    assert body['candidates'][1]['blocked_by'] == ['missing inputs (artifacts): token']
    assert [entry['id'] for entry in body['node_candidates']] == ['d1', 'd1', 'd2']
    assert body['node_candidates'][0]['current'] is True
    assert body['node_candidates'][-1]['compatible'] is True


def test_substitution_candidates_rejects_out_of_range_index(tmp_path):
    client, plan_path = _make_client(tmp_path)

    resp = client.post(
        '/api/flag-sequencing/substitution_candidates',
        json={
            'scenario': 'Demo Scenario',
            'index': 2,
            'kind': 'flag-node-generator',
            'chain_ids': ['v1', 'd1'],
            'flag_assignments': [
                {'id': 'gen-v'},
                {'id': 'gen-ok'},
            ],
            'preview_plan': plan_path,
        },
    )

    assert resp.status_code == 400
    assert resp.get_json() == {'ok': False, 'error': 'Index out of range.'}
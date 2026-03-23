from types import SimpleNamespace
import os

from flask import Flask

from webapp.routes import flag_sequencing_values


def _build_backend(plan_path: str):
    return SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _planner_get_plan=lambda scenario_norm: {'plan_path': plan_path},
        _latest_preview_plan_for_scenario_norm_origin=lambda scenario_norm, origin='planner': None,
        _latest_preview_plan_for_scenario_norm=lambda scenario_norm, prefer_flow=True: None,
        _load_preview_payload_from_path=lambda path, scenario: {
            'metadata': {
                'flow': {
                    'flag_assignments': [
                        {
                            'node_id': 'node-1',
                            'id': 'gen-1',
                            'name': 'Generator One',
                            'artifacts_dir': '/tmp/vulns/run-1',
                        },
                        {
                            'node_id': 'node-2',
                            'id': 'gen-2',
                            'name': 'Generator Two',
                            'run_dir': '/tmp/vulns/run-2',
                        },
                    ]
                }
            }
        },
        _flow_read_flag_value_from_artifacts_dir=lambda path: {
            '/tmp/vulns/run-1': 'FLAG{one}',
            '/tmp/vulns/run-2': 'FLAG{two}',
        }.get(path, ''),
        os=os,
    )


def _make_client(tmp_path):
    plan_path = tmp_path / 'preview.xml'
    plan_path.write_text('<xml />', encoding='utf-8')
    app = Flask(__name__)
    app.config['TESTING'] = True
    flag_sequencing_values.register(app, backend_module=_build_backend(str(plan_path)))
    return app.test_client()


def test_flag_values_for_node_returns_matching_runtime_flags(tmp_path):
    client = _make_client(tmp_path)

    resp = client.get('/api/flag-sequencing/flag_values_for_node', query_string={'scenario': 'Demo Scenario', 'node_id': 'node-2'})

    assert resp.status_code == 200
    assert resp.get_json() == {
        'ok': True,
        'scenario': 'Demo Scenario',
        'node_id': 'node-2',
        'flags': [
            {
                'generator_id': 'gen-2',
                'generator_name': 'Generator Two',
                'flag_value': 'FLAG{two}',
            }
        ],
    }


def test_flag_values_for_node_returns_empty_when_no_assignment_matches(tmp_path):
    client = _make_client(tmp_path)

    resp = client.get('/api/flag-sequencing/flag_values_for_node', query_string={'scenario': 'Demo Scenario', 'node_id': 'missing'})

    assert resp.status_code == 200
    assert resp.get_json() == {
        'ok': True,
        'scenario': 'Demo Scenario',
        'node_id': 'missing',
        'flags': [],
    }


def test_flag_values_for_node_requires_node_id(tmp_path):
    client = _make_client(tmp_path)

    resp = client.get('/api/flag-sequencing/flag_values_for_node', query_string={'scenario': 'Demo Scenario'})

    assert resp.status_code == 400
    assert resp.get_json() == {'ok': False, 'error': 'No node_id specified.'}
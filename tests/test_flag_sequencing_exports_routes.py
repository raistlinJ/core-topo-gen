from types import SimpleNamespace
import os

from flask import Flask

from webapp.routes import flag_sequencing_exports


def _build_backend():
    return SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _flow_state_from_latest_xml=lambda scenario_norm: None,
        _planner_get_plan=lambda scenario_norm: None,
        _latest_preview_plan_for_scenario_norm_origin=lambda scenario_norm, origin='planner': None,
        _latest_preview_plan_for_scenario_norm=lambda scenario_norm: None,
        _load_preview_payload_from_path=lambda path, scenario: {},
        _attach_latest_flow_into_plan_payload=lambda payload, scenario: None,
        _first_valid_ipv4=lambda value: str(value or '').strip() or None,
        _flow_normalize_fact_override=lambda value: value,
        _flow_compute_flag_assignments=lambda preview, chain_nodes, scenario_label, initial_facts_override=None, goal_facts_override=None: [],
        _flow_validate_chain_order_by_requires_produces=lambda chain_nodes, flag_assignments, scenario_label=None: (True, []),
        _attack_flow_builder_afb_for_chain=lambda **kwargs: {'kind': 'afb', 'nodes': len(kwargs.get('chain_nodes') or [])},
        _attack_graph_for_chain=lambda **kwargs: {'nodes': [node.get('id') for node in (kwargs.get('chain_nodes') or [])]},
        _attack_graph_dot=lambda graph: 'digraph G {}',
        _attack_graph_pdf_base64=lambda dot: 'cGRm',
        os=os,
    )


def _make_client():
    app = Flask(__name__)
    app.config['TESTING'] = True
    flag_sequencing_exports.register(app, backend_module=_build_backend())
    return app.test_client()


def test_bundle_from_chain_returns_gone():
    client = _make_client()

    resp = client.post('/api/flag-sequencing/bundle_from_chain', json={})

    assert resp.status_code == 410
    assert resp.get_json() == {
        'ok': False,
        'error': 'STIX bundle export has been removed. Use /api/flag-sequencing/afb_from_chain.',
    }


def test_afb_from_chain_returns_export_payload():
    client = _make_client()

    resp = client.post(
        '/api/flag-sequencing/afb_from_chain',
        json={
            'scenario': 'Demo Scenario',
            'chain': [
                {'id': 'n1', 'name': 'First', 'type': 'host', 'is_vuln': True},
                {'id': 'n2', 'name': 'Second', 'type': 'docker'},
            ],
        },
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body['ok'] is True
    assert body['scenario'] == 'Demo Scenario'
    assert body['length'] == 2
    assert body['afb'] == {'kind': 'afb', 'nodes': 2}
    assert body['attack_graph'] == {'nodes': ['n1', 'n2']}
    assert body['attack_graph_dot'] == 'digraph G {}'
    assert body['attack_graph_pdf_base64'] == 'cGRm'
    assert body['flags_enabled'] is True


def test_attackflow_returns_gone():
    client = _make_client()

    resp = client.get('/api/flag-sequencing/attackflow')

    assert resp.status_code == 410
    assert resp.get_json() == {
        'ok': False,
        'error': 'STIX/AttackFlow bundle export has been removed. Use /api/flag-sequencing/attackflow_preview for chain preview and /api/flag-sequencing/afb_from_chain for Attack Flow Builder export.',
    }
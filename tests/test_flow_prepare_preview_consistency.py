import json
import re
import uuid

from webapp import app_backend


IP_AT_RE = re.compile(r"@\s*((?:\d{1,3}\.){3}\d{1,3})")


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def _seed_xml_with_preview_and_flow_state(tmp_path, scenario: str, full_preview: dict, flow_state: dict) -> str:
    xml_path = tmp_path / f"{scenario}.xml"
    xml_path.write_text(
        (
            '<Scenarios>'
            f'<Scenario name="{scenario}"><ScenarioEditor></ScenarioEditor></Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    payload = {
        'full_preview': full_preview,
        'metadata': {
            'scenario': scenario,
            'seed': full_preview.get('seed'),
            'xml_path': str(xml_path),
            'flow': flow_state,
        },
    }

    ok, err = app_backend._update_plan_preview_in_xml(str(xml_path), scenario, payload)
    assert ok, err
    ok2, err2 = app_backend._update_flow_state_in_xml(str(xml_path), scenario, flow_state)
    assert ok2, err2
    return str(xml_path)


def test_prepare_preview_rerenders_next_hint_ip_from_current_chain(monkeypatch, tmp_path):
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    scenario = f"prepare-hint-consistency-{uuid.uuid4().hex[:8]}"

    full_preview = {
        'seed': 123,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'host_router_map': {},
        'hosts': [
            {'node_id': 'n1', 'name': 'node-1', 'role': 'Docker', 'ip4': '10.0.1.2', 'vulnerabilities': [{'id': 'v1'}]},
            {'node_id': 'n2', 'name': 'node-2', 'role': 'Docker', 'ip4': '10.0.2.2', 'vulnerabilities': [{'id': 'v2'}]},
        ],
    }

    stale_ip = '192.0.2.99'
    flow_state = {
        'scenario': scenario,
        'length': 2,
        'chain': [
            {'id': 'n1', 'name': 'node-1', 'type': 'docker'},
            {'id': 'n2', 'name': 'node-2', 'type': 'docker'},
        ],
        'flag_assignments': [
            {
                'node_id': 'n1',
                'id': 'fake_gen',
                'name': 'Fake Generator',
                'type': 'flag-generator',
                'hint_template': 'Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}',
                'hint_templates': ['Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}'],
                'hint': f'Next: node-2 @ {stale_ip}',
                'hints': [f'Next: node-2 @ {stale_ip}'],
            },
            {
                'node_id': 'n2',
                'id': 'fake_gen',
                'name': 'Fake Generator',
                'type': 'flag-generator',
                'hint_template': 'Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}',
                'hint_templates': ['Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}'],
                'hint': "You've completed this sequence of challenges!",
                'hints': ["You've completed this sequence of challenges!"],
            },
        ],
        'modified_at': '2026-03-02T00:00:00Z',
    }

    xml_path = _seed_xml_with_preview_and_flow_state(tmp_path, scenario, full_preview, flow_state)

    monkeypatch.setattr(
        app_backend,
        '_build_topology_graph_from_preview_plan',
        lambda _preview: (
            [
                {'id': 'n1', 'name': 'node-1', 'type': 'docker', 'is_vuln': True, 'ip4': '10.0.1.2', 'interfaces': []},
                {'id': 'n2', 'name': 'node-2', 'type': 'docker', 'is_vuln': True, 'ip4': '10.0.2.2', 'interfaces': []},
            ],
            [{'node1': 'n1', 'node2': 'n2'}],
            {'n1': {'n2'}, 'n2': {'n1'}},
        ),
    )
    monkeypatch.setattr(
        app_backend,
        '_flag_generators_from_enabled_sources',
        lambda: (
            [
                {
                    'id': 'fake_gen',
                    'plugin_type': 'flag-generator',
                    'hint_templates': ['Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}'],
                    'inputs': [],
                    'outputs': [],
                }
            ],
            [],
        ),
    )
    monkeypatch.setattr(app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(app_backend, '_flow_validate_chain_order_by_requires_produces', lambda *args, **kwargs: (True, []))

    resp = client.post(
        '/api/flag-sequencing/prepare_preview_for_execute',
        data=json.dumps(
            {
                'scenario': scenario,
                'preview_plan': xml_path,
                'length': 2,
                'mode': 'preview',
            }
        ),
        content_type='application/json',
    )

    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data.get('ok') is True

    chain = data.get('chain') or []
    assert [str(n.get('id') or '') for n in chain] == ['n1', 'n2']
    chain_ip_by_id = {str(n.get('id') or ''): str(n.get('ip4') or '') for n in chain if isinstance(n, dict)}

    assignments = data.get('flag_assignments') or []
    assert len(assignments) >= 2
    first = assignments[0]
    assert str(first.get('node_id') or '') == 'n1'
    assert str(first.get('next_node_id') or '') == 'n2'

    expected_next_ip = chain_ip_by_id.get('n2')
    assert expected_next_ip == '10.0.2.2'

    hint_values = []
    if isinstance(first.get('hint'), str) and first.get('hint').strip():
        hint_values.append(first.get('hint').strip())
    if isinstance(first.get('hints'), list):
        hint_values.extend([str(x).strip() for x in first.get('hints') if isinstance(x, str) and str(x).strip()])

    next_hints = [text for text in hint_values if 'Next' in text]
    assert next_hints, 'expected at least one Next hint in first assignment'
    for text in next_hints:
        m = IP_AT_RE.search(text)
        assert m, f'expected an @ip token in hint: {text}'
        assert m.group(1) == expected_next_ip
        assert stale_ip not in text

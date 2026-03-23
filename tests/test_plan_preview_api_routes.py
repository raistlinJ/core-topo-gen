from flask import Flask

from webapp.routes import plan_preview_api


def test_persist_flow_plan_route_returns_payload_from_planner():
    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_planner_persist_flow_plan': staticmethod(
                    lambda **kwargs: {
                        'xml_path': kwargs.get('xml_path'),
                        'scenario': kwargs.get('scenario'),
                        'seed': kwargs.get('seed'),
                        'preview_plan_path': '/tmp/plan.xml',
                    }
                ),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/persist_flow_plan', json={'xml_path': '/tmp/demo.xml', 'scenario': 'Demo', 'seed': 17})

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload == {
        'ok': True,
        'xml_path': '/tmp/demo.xml',
        'scenario': 'Demo',
        'seed': 17,
        'preview_plan_path': '/tmp/plan.xml',
    }


def test_persist_flow_plan_route_requires_xml_path():
    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_planner_persist_flow_plan': staticmethod(lambda **kwargs: kwargs),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/persist_flow_plan', json={'scenario': 'Demo'})

    assert resp.status_code == 400
    payload = resp.get_json()
    assert payload == {'ok': False, 'error': 'xml_path missing'}


def test_preview_full_route_requires_xml_path_when_no_inline_scenarios():
    app = Flask(__name__)
    plan_preview_api.register(app, backend_module=object())

    client = app.test_client()
    resp = client.post('/api/plan/preview_full', json={'scenario': 'Demo'})

    assert resp.status_code == 400
    payload = resp.get_json()
    assert payload == {'ok': False, 'error': 'xml_path missing'}


def test_preview_full_route_returns_embedded_preview_without_recompute():
    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_load_preview_payload_from_path': staticmethod(
                    lambda xml_path, scenario=None: {
                        'full_preview': {'seed': 7, 'hosts': [{'node_id': 1}]},
                        'metadata': {'seed': 7},
                    }
                ),
                '_flow_state_from_xml_path': staticmethod(lambda xml_path, scenario=None: {'chain_ids': ['1']}),
                '_attach_latest_flow_into_full_preview': staticmethod(lambda preview, scenario=None: {'attached': True}),
                '_flow_repair_saved_flow_for_preview': staticmethod(lambda preview, flow_meta: {'repaired': True}),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/preview_full', json={'xml_path': __file__, 'scenario': 'Demo'})

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload['ok'] is True
    assert payload['full_preview'] == {'seed': 7, 'hosts': [{'node_id': 1}]}
    assert payload['plan'] == {}
    assert payload['breakdowns'] is None
    assert payload['flow_meta'] == {'repaired': True}
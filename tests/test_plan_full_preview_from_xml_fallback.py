import json

from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_plan_full_preview_from_xml_falls_back_to_latest_scenario_xml(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))
    monkeypatch.setattr(backend, 'render_template', lambda *args, **kwargs: 'ok')

    scenario = 'FallbackScenario'

    stale_xml = tmp_path / 'stale.xml'
    stale_xml.write_text(
        (
            '<Scenarios>'
            f'<Scenario name="{scenario}"><ScenarioEditor></ScenarioEditor></Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    payload = {
        'full_preview': {
            'seed': 123,
            'hosts': [],
            'routers': [],
            'switches': [],
            'switches_detail': [],
            'host_router_map': {},
        },
        'metadata': {
            'scenario': scenario,
            'seed': 123,
            'xml_path': str(tmp_path / 'latest.xml'),
            'updated_at': '2026-02-25T00:00:00Z',
        },
    }
    latest_xml = tmp_path / 'latest.xml'
    latest_xml.write_text(
        (
            '<Scenarios>'
            f'<Scenario name="{scenario}"><ScenarioEditor>'
            f'<PlanPreview>{json.dumps(payload)}</PlanPreview>'
            '</ScenarioEditor></Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _norm: str(latest_xml))

    resp = client.post(
        '/plan/full_preview_from_xml',
        data={
            'xml_path': str(stale_xml),
            'scenario': scenario,
        },
    )

    assert resp.status_code == 200
    assert resp.data == b'ok'


def test_plan_full_preview_from_xml_recomputes_when_planpreview_missing(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))
    monkeypatch.setattr(backend, 'render_template', lambda *args, **kwargs: 'ok')

    scenario = 'RecomputeScenario'
    xml_path = tmp_path / 'recompute.xml'
    xml_path.write_text(
        (
            '<Scenarios>'
            f'<Scenario name="{scenario}"><ScenarioEditor></ScenarioEditor></Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    def _fake_recompute(**kwargs):
        return {
            'full_preview': {
                'seed': 321,
                'hosts': [],
                'routers': [],
                'switches': [],
                'switches_detail': [],
                'host_router_map': {},
            },
            'metadata': {
                'scenario': scenario,
                'seed': 321,
                'xml_path': str(xml_path),
            },
        }

    monkeypatch.setattr(backend, '_planner_persist_flow_plan', _fake_recompute)

    resp = client.post(
        '/plan/full_preview_from_xml',
        data={
            'xml_path': str(xml_path),
            'scenario': scenario,
        },
    )

    assert resp.status_code == 200
    assert resp.data == b'ok'

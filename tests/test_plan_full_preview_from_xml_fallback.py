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


def test_plan_full_preview_from_xml_ignores_no_scenario_fallback_when_metadata_mismatch(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))
    monkeypatch.setattr(backend, 'render_template', lambda *args, **kwargs: 'ok')

    requested = 'RequestedScenario'
    other = 'OtherScenario'
    xml_path = tmp_path / 'mismatch.xml'

    # XML contains only a PlanPreview for a different scenario.
    mismatch_payload = {
        'full_preview': {
            'seed': 111,
            'hosts': [],
            'routers': [{'node_id': 1, 'name': 'router-only'}],
            'switches': [],
            'switches_detail': [],
            'host_router_map': {},
        },
        'metadata': {
            'scenario': other,
            'seed': 111,
            'xml_path': str(xml_path),
        },
    }
    xml_path.write_text(
        (
            '<Scenarios>'
            f'<Scenario name="{other}"><ScenarioEditor>'
            f'<PlanPreview>{json.dumps(mismatch_payload)}</PlanPreview>'
            '</ScenarioEditor></Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    calls = {'recompute': 0}

    def _fake_recompute(**kwargs):
        calls['recompute'] += 1
        assert kwargs.get('scenario') == requested
        return {
            'full_preview': {
                'seed': 222,
                'hosts': [{'node_id': 'h1', 'name': 'host-1', 'role': 'Docker'}],
                'routers': [],
                'switches': [],
                'switches_detail': [],
                'host_router_map': {},
            },
            'metadata': {
                'scenario': requested,
                'seed': 222,
                'xml_path': str(xml_path),
            },
        }

    monkeypatch.setattr(backend, '_planner_persist_flow_plan', _fake_recompute)

    resp = client.post(
        '/plan/full_preview_from_xml',
        data={
            'xml_path': str(xml_path),
            'scenario': requested,
        },
    )

    assert resp.status_code == 200
    assert resp.data == b'ok'
    assert calls['recompute'] == 1


def test_plan_full_preview_from_xml_recomputes_when_embedded_planpreview_effectively_empty(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))
    monkeypatch.setattr(backend, 'render_template', lambda *args, **kwargs: 'ok')

    scenario = 'Anatest'
    xml_path = tmp_path / 'anatest.xml'
    stale_payload = {
        'full_preview': {
            'seed': 101,
            'hosts': [],
            'routers': [],
            'switches': [],
            'switches_detail': [],
            'host_router_map': {},
            'role_counts': {},
        },
        'metadata': {
            'scenario': scenario,
            'seed': 101,
            'xml_path': str(xml_path),
        },
    }
    xml_path.write_text(
        (
            '<Scenarios>'
            f'<Scenario name="{scenario}" scenario_total_nodes="10">'
            '<ScenarioEditor>'
            f'<PlanPreview>{json.dumps(stale_payload)}</PlanPreview>'
            '<section name="Node Information" density_count="10">'
            '<item selected="Docker" v_metric="Count" v_count="5" />'
            '</section>'
            '</ScenarioEditor>'
            '</Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    calls = {'recompute': 0}

    def _fake_recompute(**kwargs):
        calls['recompute'] += 1
        assert kwargs.get('scenario') == scenario
        assert kwargs.get('xml_path') == str(xml_path)
        return {
            'full_preview': {
                'seed': 202,
                'hosts': [{'node_id': 'h1', 'name': 'docker-1', 'role': 'Docker'}],
                'routers': [],
                'switches': [],
                'switches_detail': [],
                'host_router_map': {},
            },
            'metadata': {
                'scenario': scenario,
                'seed': 202,
                'xml_path': str(xml_path),
            },
        }

    monkeypatch.setattr(
        'core_topo_gen.planning.orchestrator.compute_full_plan',
        lambda *args, **kwargs: {'routers_planned': 5},
    )
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
    assert calls['recompute'] == 1


def test_plan_full_preview_from_xml_recomputes_when_routers_missing_but_plan_expects_them(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))
    monkeypatch.setattr(backend, 'render_template', lambda *args, **kwargs: 'ok')

    scenario = 'Anatest'
    xml_path = tmp_path / 'anatest_missing_routers.xml'
    stale_payload = {
        'full_preview': {
            'seed': 303,
            'hosts': [
                {'node_id': 'h1', 'name': 'docker-1', 'role': 'Docker'},
                {'node_id': 'h2', 'name': 'docker-2', 'role': 'Docker'},
            ],
            'routers': [],
            'switches': [],
            'switches_detail': [],
            'host_router_map': {},
            'role_counts': {'Docker': 2},
        },
        'metadata': {
            'scenario': scenario,
            'seed': 303,
            'xml_path': str(xml_path),
        },
    }
    xml_path.write_text(
        (
            '<Scenarios>'
            f'<Scenario name="{scenario}" scenario_total_nodes="7">'
            '<ScenarioEditor>'
            f'<PlanPreview>{json.dumps(stale_payload)}</PlanPreview>'
            '<section name="Node Information" density_count="7">'
            '<item selected="Docker" v_metric="Count" v_count="5" />'
            '</section>'
            '<section name="Routing">'
            '<item selected="RIP" factor="1.000" v_metric="Weight" />'
            '</section>'
            '</ScenarioEditor>'
            '</Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    calls = {'recompute': 0}

    def _fake_recompute(**kwargs):
        calls['recompute'] += 1
        assert kwargs.get('scenario') == scenario
        assert kwargs.get('xml_path') == str(xml_path)
        return {
            'full_preview': {
                'seed': 404,
                'hosts': [{'node_id': 'h1', 'name': 'docker-1', 'role': 'Docker'}],
                'routers': [{'node_id': 'r1', 'name': 'r1'}],
                'switches': [],
                'switches_detail': [],
                'host_router_map': {},
            },
            'metadata': {
                'scenario': scenario,
                'seed': 404,
                'xml_path': str(xml_path),
            },
        }

    monkeypatch.setattr(
        'core_topo_gen.planning.orchestrator.compute_full_plan',
        lambda *args, **kwargs: {'routers_planned': 5},
    )
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
    assert calls['recompute'] == 1


def test_plan_full_preview_from_xml_recomputes_even_when_embedded_plan_exists_by_default(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))
    monkeypatch.setattr(backend, 'render_template', lambda *args, **kwargs: 'ok')

    scenario = 'Anatest'
    xml_path = tmp_path / 'anatest_existing_plan.xml'
    embedded_payload = {
        'full_preview': {
            'seed': 111,
            'hosts': [{'node_id': 'h1', 'name': 'docker-1', 'role': 'Docker'}],
            'routers': [{'node_id': 'r1', 'name': 'r1'}],
            'switches': [],
            'switches_detail': [],
            'host_router_map': {},
            'role_counts': {'Docker': 1},
        },
        'metadata': {
            'scenario': scenario,
            'seed': 111,
            'xml_path': str(xml_path),
        },
    }
    xml_path.write_text(
        (
            '<Scenarios>'
            f'<Scenario name="{scenario}">'
            '<ScenarioEditor>'
            f'<PlanPreview>{json.dumps(embedded_payload)}</PlanPreview>'
            '</ScenarioEditor>'
            '</Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    calls = {'recompute': 0}

    def _fake_recompute(**kwargs):
        calls['recompute'] += 1
        assert kwargs.get('scenario') == scenario
        assert kwargs.get('xml_path') == str(xml_path)
        return {
            'full_preview': {
                'seed': 222,
                'hosts': [{'node_id': 'h1', 'name': 'docker-1', 'role': 'Docker'}],
                'routers': [{'node_id': 'r1', 'name': 'r1'}],
                'switches': [],
                'switches_detail': [],
                'host_router_map': {},
                'role_counts': {'Docker': 1},
            },
            'metadata': {
                'scenario': scenario,
                'seed': 222,
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
    assert calls['recompute'] == 1


def test_plan_full_preview_from_xml_sets_preview_source_recomputed_on_read(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))

    captured: dict[str, object] = {}

    def _capture_render(*args, **kwargs):
        captured.update(kwargs)
        return 'ok'

    monkeypatch.setattr(backend, 'render_template', _capture_render)

    scenario = 'Anatest'
    xml_path = tmp_path / 'anatest_source_flag.xml'
    embedded_payload = {
        'full_preview': {
            'seed': 1,
            'hosts': [{'node_id': 'h1', 'name': 'docker-1', 'role': 'Docker'}],
            'routers': [{'node_id': 'r1', 'name': 'r1'}],
            'switches': [],
            'switches_detail': [],
            'host_router_map': {},
            'role_counts': {'Docker': 1},
        },
        'metadata': {
            'scenario': scenario,
            'seed': 1,
            'xml_path': str(xml_path),
        },
    }
    xml_path.write_text(
        (
            '<Scenarios>'
            f'<Scenario name="{scenario}">'
            '<ScenarioEditor>'
            f'<PlanPreview>{json.dumps(embedded_payload)}</PlanPreview>'
            '</ScenarioEditor>'
            '</Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_planner_persist_flow_plan',
        lambda **kwargs: {
            'full_preview': {
                'seed': 2,
                'hosts': [{'node_id': 'h1', 'name': 'docker-1', 'role': 'Docker'}],
                'routers': [{'node_id': 'r1', 'name': 'r1'}],
                'switches': [],
                'switches_detail': [],
                'host_router_map': {},
                'role_counts': {'Docker': 1},
            },
            'metadata': {
                'scenario': scenario,
                'seed': 2,
                'xml_path': str(xml_path),
            },
        },
    )

    resp = client.post(
        '/plan/full_preview_from_xml',
        data={
            'xml_path': str(xml_path),
            'scenario': scenario,
        },
    )

    assert resp.status_code == 200
    assert resp.data == b'ok'
    assert captured.get('preview_source') == 'recomputed_on_read'

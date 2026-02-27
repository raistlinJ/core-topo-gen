from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_flag_pages_use_catalog_only_source(monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    monkeypatch.setattr(
        backend,
        '_load_run_history',
        lambda: [{'scenario_names': ['NewScenario1'], 'scenario_name': 'NewScenario1'}],
    )

    def fake_catalog_for_user(history, user=None):
        if history is None:
            return (
                ['NewScenario12'],
                {'newscenario12': set()},
                {},
            )
        return (
            ['NewScenario1', 'NewScenario12'],
            {'newscenario1': set(), 'newscenario12': set()},
            {},
        )

    monkeypatch.setattr(backend, '_scenario_catalog_for_user', fake_catalog_for_user)

    resp_flow = client.get('/scenarios/flag-sequencing')
    assert resp_flow.status_code == 200
    body_flow = resp_flow.get_data(as_text=True)
    assert 'NewScenario12' in body_flow
    assert '?scenario=NewScenario1"' not in body_flow
    assert 'value="NewScenario1"' not in body_flow

    resp_preview = client.get('/scenarios/preview')
    assert resp_preview.status_code == 200
    body_preview = resp_preview.get_data(as_text=True)
    assert 'NewScenario12' in body_preview
    assert '?scenario=NewScenario1"' not in body_preview
    assert 'value="NewScenario1"' not in body_preview

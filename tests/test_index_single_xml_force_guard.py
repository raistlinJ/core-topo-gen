from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_index_does_not_force_single_scenario_xml_without_explicit_scenario(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    anatest_xml = tmp_path / 'Anatest.xml'
    anatest_xml.write_text(
        '<Scenarios><Scenario name="Anatest"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda _history, user=None: (
            ['Scenario A', 'Anatest'],
            {'scenario a': set(), 'anatest': {str(anatest_xml)}},
            {},
        ),
    )
    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda norm: str(anatest_xml) if norm == 'scenario a' else '')

    resp = client.get('/')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '"Scenario A"' in body
    assert '"Anatest"' in body


def test_index_prefers_explicit_xml_path_query(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    xml_a = tmp_path / 'A.xml'
    xml_b = tmp_path / 'B.xml'
    xml_a.write_text('<Scenarios><Scenario name="Scenario A"><ScenarioEditor/></Scenario></Scenarios>', encoding='utf-8')
    xml_b.write_text('<Scenarios><Scenario name="Anatest"><ScenarioEditor/></Scenario></Scenarios>', encoding='utf-8')

    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda _history, user=None: (
            ['Scenario A', 'Anatest'],
            {'scenario a': {str(xml_a)}, 'anatest': {str(xml_b)}},
            {},
        ),
    )

    resp = client.get('/?xml_path=' + str(xml_b))
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '"Anatest"' in body

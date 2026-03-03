from pathlib import Path

from webapp.app_backend import app


TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_flow_page_prefers_latest_xml_over_query_and_catalog(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    old_xml = tmp_path / "old.xml"
    latest_xml = tmp_path / "latest.xml"
    old_xml.write_text('<Scenarios><Scenario name="Anatest"><ScenarioEditor/></Scenario></Scenarios>', encoding='utf-8')
    latest_xml.write_text('<Scenarios><Scenario name="Anatest"><ScenarioEditor/></Scenario></Scenarios>', encoding='utf-8')

    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda _history, user=None: (
            ['Anatest'],
            {'anatest': {str(old_xml)}},
            {},
        ),
    )
    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _norm: str(latest_xml))

    resp = client.get('/scenarios/flag-sequencing?scenario=Anatest&xml_path=' + str(old_xml))
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert f'id="scenariosPreviewXmlPath" value="{latest_xml}"' in body


def test_preview_page_prefers_latest_xml_over_query_and_catalog(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    old_xml = tmp_path / "old.xml"
    latest_xml = tmp_path / "latest.xml"
    old_xml.write_text('<Scenarios><Scenario name="Anatest"><ScenarioEditor/></Scenario></Scenarios>', encoding='utf-8')
    latest_xml.write_text('<Scenarios><Scenario name="Anatest"><ScenarioEditor/></Scenario></Scenarios>', encoding='utf-8')

    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda _history, user=None: (
            ['Anatest'],
            {'anatest': {str(old_xml)}},
            {},
        ),
    )
    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _norm: str(latest_xml))

    resp = client.get('/scenarios/preview?scenario=Anatest&xml_path=' + str(old_xml))
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'id="scenariosPreviewLoadXmlPath"' in body
    assert f'value="{latest_xml}"' in body


def test_scenarios_tabs_refreshes_latest_state_from_xml_on_load():
    text = TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "async function refreshScenarioStateFromXml(scenarioName, opts)",
        "fetch('/api/scenario/latest_state?scenario=' + encodeURIComponent(scenario)",
        "setLatestXmlPathForScenario(scenario, xmlPath);",
        "window.coretgRefreshScenarioStateFromXml = refreshScenarioStateFromXml;",
        "await refreshScenarioStateFromXml(scen, { updateHidden: true });",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing XML-first scenarios tab hydration snippets: " + "; ".join(missing)


def test_scenarios_tabs_xml_refresh_does_not_clobber_hitl_with_empty_payload() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "const hasCorePayload = !!(incomingCoreRaw && Object.values(incomingCoreRaw).some((entry) => hasMeaningfulValue(entry)));",
        "if (!(hasCorePayload || hasProxPayload || hasInterfacesPayload || hasParticipantPayload || hasEnabledPayload)) {",
        "mergedScenario.hitl = { ...existingScenario.hitl };",
        "mergedHitl.core = { ...currentCore, ...incomingHitlRaw.core };",
        "mergedHitl.proxmox = { ...currentProx, ...incomingHitlRaw.proxmox };",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing HITL-safe XML refresh merge snippets in scenarios tabs: " + "; ".join(missing)

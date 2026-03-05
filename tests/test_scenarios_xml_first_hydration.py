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
        "latestStateUrl += '&xml_path=' + encodeURIComponent(explicitXmlPath);",
        "const resp = await fetch(latestStateUrl, { credentials: 'same-origin' });",
        "setLatestXmlPathForScenario(scenario, xmlPath);",
        "window.coretgRefreshScenarioStateFromXml = refreshScenarioStateFromXml;",
        "await refreshScenarioStateFromXml(scen, { updateHidden: true });",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing XML-first scenarios tab hydration snippets: " + "; ".join(missing)


def test_scenarios_tabs_xml_refresh_does_not_clobber_hitl_with_empty_payload() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "const mergeScenarioWithHitlGuard = (existingScenarioRaw, incomingScenarioRaw) => {",
        "const mergeHitlSectionGuarded = (currentSectionRaw, incomingSectionRaw, sectionType) => {",
        "const hasCorePayload = !!(incomingCoreRaw && Object.values(incomingCoreRaw).some((entry) => hasMeaningfulValue(entry)));",
        "if (!(hasCorePayload || hasProxPayload || hasInterfacesPayload || hasParticipantPayload || hasEnabledPayload)) {",
        "mergedScenario.hitl = { ...existingScenario.hitl };",
        "mergedHitl.core = mergeHitlSectionGuarded(currentCore, incomingHitlRaw.core, 'core');",
        "mergedHitl.proxmox = mergeHitlSectionGuarded(currentProx, incomingHitlRaw.proxmox, 'proxmox');",
        "scenarios[idx] = mergeScenarioWithHitlGuard(existingScenario, incomingScenario);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing HITL-safe XML refresh merge snippets in scenarios tabs: " + "; ".join(missing)


def test_scenarios_tabs_xml_refresh_updates_live_window_state() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "if (scenarioKey && incomingScenario && window.state && typeof window.state === 'object' && Array.isArray(window.state.scenarios)) {",
        "scenarios[idx] = mergeScenarioWithHitlGuard(existingScenario, incomingScenario);",
        "if (typeof window.renderMain === 'function') window.renderMain();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing live window.state XML rehydrate snippets: " + "; ".join(missing)


def test_scenarios_tabs_xml_refresh_prefers_latest_scenario_xml_path() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    latest_snippet = "explicitXmlPath = (getLatestXmlPathForScenario(scenario) || '').toString().trim();"
    hidden_snippet = "explicitXmlPath = (document.getElementById('scenariosPreviewXmlPath')?.value || '').toString().trim();"

    latest_idx = text.find(latest_snippet)
    hidden_idx = text.find(hidden_snippet)

    assert latest_idx != -1, "Missing latest per-scenario XML path lookup snippet"
    assert hidden_idx != -1, "Missing hidden XML path lookup snippet"
    assert latest_idx < hidden_idx, "Latest per-scenario XML path must be preferred over hidden XML path"

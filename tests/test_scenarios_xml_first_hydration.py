from pathlib import Path

from webapp.app_backend import app


TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"
LAYOUT_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "layout.html"
CORE_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "core.html"
INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
FULL_PREVIEW_SCRIPTS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "full_preview_scripts.html"
FLAG_CATALOG_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "flag_catalog.html"


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


def test_scenarios_tabs_exposes_retrieving_page_details_loading_attributes() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'data-coretg-nav-loading="1"',
        'data-coretg-nav-loading-title="Retrieving Page Details"',
        'data-coretg-nav-loading-message="Retrieving page details…"',
        "window.CORETG_NAVIGATE_WITH_LOADING(url, {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing scenarios tab retrieving-page-details loading snippets: " + "; ".join(missing)


def test_layout_exposes_shared_navigation_loading_helper() -> None:
    text = LAYOUT_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'id="navLoadingTitle"',
        'window.CORETG_NAVIGATE_WITH_LOADING = navigateWithLoading;',
        'window.CORETG_NAVIGATE_PAGE_DETAILS = navigatePageDetails;',
        "const wantsLoading = target.hasAttribute('data-coretg-nav-loading') || target.id === 'navCoreLink';",
        "if (!shouldUseDefaultPageLoading(target)) return;",
        "window.addEventListener('focus', hideNavLoading);",
        "if (!document.hidden) hideNavLoading();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing shared navigation loading helper snippets: " + "; ".join(missing)


def test_core_template_uses_retrieving_page_details_text() -> None:
    text = CORE_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'Retrieving Page Details',
        'Retrieving page details…',
        "window.CORETG_NAVIGATE_WITH_LOADING(href, {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing core details loading snippets: " + "; ".join(missing)


def test_index_template_uses_page_details_navigation_helper() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'window.CORETG_NAVIGATE_PAGE_DETAILS(targetUrl);',
        'window.CORETG_NAVIGATE_PAGE_DETAILS(href);',
        'window.CORETG_NAVIGATE_PAGE_DETAILS(url);',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing index page-details navigation snippets: " + "; ".join(missing)
    assert "window.CORETG_NAVIGATE_PAGE_DETAILS(href);\n        const hitlState = ensureHitlStateForScenario(scenario);" not in text


def test_full_preview_scripts_uses_page_details_navigation_helper() -> None:
    text = FULL_PREVIEW_SCRIPTS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        '(window.top || window).CORETG_NAVIGATE_PAGE_DETAILS(url);',
        'window.CORETG_NAVIGATE_PAGE_DETAILS(reportsHref);',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing full preview page-details navigation snippets: " + "; ".join(missing)


def test_flag_catalog_success_redirect_uses_page_details_navigation_helper() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "window.CORETG_NAVIGATE_PAGE_DETAILS('{{ url_for('flag_catalog_page') }}');",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flag catalog page-details navigation snippet: " + "; ".join(missing)


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
        "if (!liveScenarioChangedDuringRefresh && scenarioKey && incomingScenario && window.state && typeof window.state === 'object' && Array.isArray(window.state.scenarios)) {",
        "scenarios[idx] = mergeScenarioWithHitlGuard(existingScenario, incomingScenario);",
        "if (typeof window.renderMain === 'function') window.renderMain();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing live window.state XML rehydrate snippets: " + "; ".join(missing)


def test_scenarios_tabs_xml_refresh_skips_live_overwrite_when_local_state_changed() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "const liveScenarioSignatureBeforeFetch = getLiveScenarioRefreshSignature();",
        "const liveScenarioSignatureAfterFetch = getLiveScenarioRefreshSignature();",
        "const liveScenarioChangedDuringRefresh = !!(",
        "if (!liveScenarioChangedDuringRefresh && !STRICT_XML_STATE_MODE) {",
        "if (!liveScenarioChangedDuringRefresh && scenarioKey && incomingScenario && window.state && typeof window.state === 'object' && Array.isArray(window.state.scenarios)) {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing live-overwrite guard snippets in scenarios tab XML refresh: " + "; ".join(missing)


def test_index_rehydrate_skips_overwrite_when_scenario_changed_mid_fetch() -> None:
    text = (Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html").read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "const liveScenarioSignatureBeforeFetch = (() => {",
        "const liveScenarioSignatureAfterFetch = (() => {",
        "const liveScenarioChangedDuringRefresh = !!(",
        "if (liveScenarioChangedDuringRefresh) {",
        "return false;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing index rehydrate overwrite guard snippets: " + "; ".join(missing)


def test_scenarios_tabs_xml_refresh_prefers_latest_scenario_xml_path() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    latest_snippet = "explicitXmlPath = (getLatestXmlPathForScenario(scenario) || '').toString().trim();"
    hidden_snippet = "explicitXmlPath = (document.getElementById('scenariosPreviewXmlPath')?.value || '').toString().trim();"

    latest_idx = text.find(latest_snippet)
    hidden_idx = text.find(hidden_snippet)

    assert latest_idx != -1, "Missing latest per-scenario XML path lookup snippet"
    assert hidden_idx != -1, "Missing hidden XML path lookup snippet"
    assert latest_idx < hidden_idx, "Latest per-scenario XML path must be preferred over hidden XML path"

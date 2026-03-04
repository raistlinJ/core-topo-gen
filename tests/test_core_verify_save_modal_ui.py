from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
FLOW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "flow.html"


def _extract_verify_core_setup_block(text: str) -> str:
    start_token = "async function verifyScenarioCoreSetup"
    end_token = "async function clearScenarioCoreVmSelection"
    start = text.find(start_token)
    end = text.find(end_token)
    if start < 0 or end < 0 or end <= start:
        return text
    return text[start:end]


def test_core_verify_save_uses_direct_local_save() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const runSave = async () => {",
        "if (typeof autoSaveXml !== 'function') {",
        "throw new Error('Save is unavailable on this page.');",
        "await autoSaveXml();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing direct local save snippets in modal path: " + "; ".join(missing)


def test_core_verify_save_does_not_refresh_interfaces_in_step2() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    verify_block = _extract_verify_core_setup_block(text)

    forbidden_snippets = [
        "verifySetStatus('Loading CORE VM interfaces…');",
        "const refreshRes = await refreshHostInterfacesForScenario(sidx, {",
        "One or more selected HITL interfaces no longer exist on the CORE VM",
    ]

    present = [snippet for snippet in forbidden_snippets if snippet in verify_block]
    assert not present, "Unexpected Step 2 interface-refresh gating snippets still present: " + "; ".join(present)


def test_save_xml_button_uses_direct_local_save() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (typeof autoSaveXml !== 'function') {",
        "throw new Error('Save is unavailable on this page.');",
        "await autoSaveXml();",
        "const xmlPath = await autoSaveXml();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing direct local Save XML snippets: " + "; ".join(missing)

    forbidden = [
        "async function saveXmlViaAvailableHelper(opts = {}) {",
        "await saveXmlViaAvailableHelper();",
        "const xmlPath = await saveXmlViaAvailableHelper();",
    ]
    present = [snippet for snippet in forbidden if snippet in text]
    assert not present, "Unexpected helper-fallback snippets still present: " + "; ".join(present)


def test_topology_save_xml_ajax_uses_local_autosave() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "async function saveXmlAjax() {",
        "if (typeof autoSaveXml !== 'function') {",
        "const xmlPath = await autoSaveXml();",
    ]
    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing local saveXmlAjax snippets: " + "; ".join(missing)

    forbidden = [
        "if (typeof window.coretgSaveXmlViaApi !== 'function')",
        "const xmlPath = await window.coretgSaveXmlViaApi();",
    ]
    present = [snippet for snippet in forbidden if snippet in text]
    assert not present, "Unexpected shared-helper usage in saveXmlAjax: " + "; ".join(present)


def test_flow_save_xml_uses_xml_path_fallback_resolver() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "async function saveXmlViaFlowState(scenarioName) {",
        "const resp = await fetch('/save_xml_api', {",
        "async function resolveXmlPathForSaveWithFallback(scenarioName, options) {",
        "window.coretgGetLatestXmlPathForScenario",
        "xmlPath = await saveXmlViaFlowState(scenario);",
        "'/api/scenario/latest_xml?scenario=' + encodeURIComponent(scenario)",
        "xmlPath = await resolveXmlPathForSaveWithFallback(scenario, { attemptSave: true });",
        "No XML path available. Save XML from Topology/VM Access first.",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow Save XML fallback snippets: " + "; ".join(missing)

    forbidden = [
        "window.coretgSaveXmlViaApi",
        "Save helper unavailable; refresh and try again.",
    ]
    present = [snippet for snippet in forbidden if snippet in text]
    assert not present, "Unexpected shared-helper dependency snippets in flow save paths: " + "; ".join(present)

from pathlib import Path


TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"


def test_save_xml_triggers_xml_rehydrate_sync() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const scenarioName = resolveScenarioNameForSave();",
        "await refreshScenarioStateFromXml(scenarioName, { updateHidden: true });",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing post-save XML rehydrate snippets: " + "; ".join(missing)

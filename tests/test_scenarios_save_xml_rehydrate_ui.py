from pathlib import Path


TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"


def test_save_xml_updates_xml_state_without_postsave_rehydrate() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "window.coretgSaveXmlViaApi = function(opts){",
        "const hinted = resolveScenarioNameHint();",
        "const scenarioName = resolveScenarioNameForSave();",
        "syncCurrentScenarioUrl(scenarioName, xmlPath);",
        "if (hidden && typeof hidden.value === 'string') hidden.value = xmlPath;",
        "updateStateSourceBadge({ scenario: scenarioName, xmlPath });",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing post-save XML rehydrate snippets: " + "; ".join(missing)


def test_save_xml_payload_pins_active_index_to_selected_scenario() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const scenarioName = resolveScenarioNameForSave();",
        "const idxByName = scenariosOut.findIndex((sc) => normalizeScenarioKey((sc && sc.name) ? sc.name : '') === scenarioNorm);",
        "active_index = idxByName;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing active scenario index pinning snippets: " + "; ".join(missing)

from pathlib import Path


SCENARIO_TABS_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"


def test_scenarios_tabs_flow_state_does_not_persist_localstorage_fallback() -> None:
    text = SCENARIO_TABS_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const FLOW_STATE_STORAGE_KEY = 'coretg_flow_state_by_scenario_v1';",
        "function readFlowStateMap(){",
        "return readJsonFromLocalStorage(FLOW_STATE_STORAGE_KEY, {});",
        "const map = readFlowStateMap();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow state helpers should still read fallback map shape for compatibility: " + "; ".join(missing)
    assert "localStorage.setItem(FLOW_STATE_STORAGE_KEY, JSON.stringify(next));" not in text

from pathlib import Path


SCENARIO_TABS_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"


def test_scenarios_tabs_flow_state_uses_localstorage_fallback() -> None:
    text = SCENARIO_TABS_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const FLOW_STATE_STORAGE_KEY = 'coretg_flow_state_by_scenario_v1';",
        "function readFlowStateMap(){",
        "return readJsonFromLocalStorage(FLOW_STATE_STORAGE_KEY, {});",
        "const map = readFlowStateMap();",
        "localStorage.setItem(FLOW_STATE_STORAGE_KEY, JSON.stringify(next));",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow state should persist and restore via localStorage fallback: " + "; ".join(missing)

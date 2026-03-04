from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
FLOW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "flow.html"
TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"


def test_index_disables_local_editor_snapshot_mode() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    assert "const USE_LOCAL_EDITOR_STATE = false;" in text
    assert "const ALLOW_LOCAL_EDITOR_PERSISTENCE = false;" in text


def test_flow_restore_has_no_local_fallback() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    forbidden = [
        "fromLocal = window.coretgGetSavedFlowStateForScenario(scenarioName);",
        "if (localUsable) return fromLocal;",
    ]
    present = [s for s in forbidden if s in text]
    assert not present, "Flow restore should not use local cache fallback: " + "; ".join(present)


def test_tabs_flow_state_helpers_use_window_state_not_localstorage() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    assert "const scenarios = (window.state && Array.isArray(window.state.scenarios)) ? window.state.scenarios : [];" in text
    assert "localStorage.setItem(FLOW_STATE_STORAGE_KEY" not in text

from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_topology_refresh_prefers_scenario_name_over_stale_index() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const findScenarioIndexByName = (name) => {",
        "const resolvePreferredScenarioNameOnLoad = () => {",
        "localStorage.getItem('coretg_last_selected_scenario_v3')",
        "const preferredScenarioName = resolvePreferredScenarioNameOnLoad();",
        "const preferredIdx = findScenarioIndexByName(preferredScenarioName);",
        "if (preferredIdx >= 0) {",
        "activeIdx = preferredIdx;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing active-scenario-on-refresh guard snippets: " + "; ".join(missing)

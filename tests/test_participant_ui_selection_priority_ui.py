from pathlib import Path


PARTICIPANT_UI_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "participant_ui.html"


def test_participant_ui_initial_selection_priority_incoming_then_last_then_first() -> None:
    text = PARTICIPANT_UI_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const incomingScenarioRequested = (() => {",
        "const hasIncomingScenario = !!incomingScenarioRequested;",
        "const initialTarget = (hasIncomingScenario",
        "? scenarioItems.find(el => el.getAttribute('data-scenario-norm') === currentNorm)",
        "|| scenarioItems.find(el => storedNorm && el.getAttribute('data-scenario-norm') === storedNorm)",
        "|| scenarioItems[0];",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing participant UI selection-priority snippets: " + "; ".join(missing)

from pathlib import Path


TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"


def test_state_source_badge_present_and_wired() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected = [
        'id="coretgStateSourceBadge"',
        'function updateStateSourceBadge(opts){',
        "State source: XML",
        "updateStateSourceBadge({ scenario, xmlPath });",
        "const isScenarioTabRoute = (",
        "badge.classList.add('text-bg-danger');",
        "No XML path available (state cannot be confirmed from XML).",
        "window.coretgUpdateStateSourceBadge = updateStateSourceBadge;",
    ]

    missing = [s for s in expected if s not in text]
    assert not missing, "Missing state-source badge wiring snippets: " + "; ".join(missing)

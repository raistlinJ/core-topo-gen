from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_run_progress_filters_nonfatal_ss_warning_lines() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function shouldSuppressRunProgressLine(rawLine) {",
        "const hasSsToken = /(^|[^a-z0-9_])ss([^a-z0-9_]|$)/.test(lower);",
        "(lower.includes('not found') || lower.includes('command not found') || lower.includes('warning'));",
        "const fatalOrError = /(\\bfatal\\b|\\berror\\b|\\btraceback\\b|\\bexception\\b)/.test(lower);",
        "if (shouldSuppressRunProgressLine(line)) return;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing non-fatal ss warning suppression snippets in run progress log UI: " + "; ".join(missing)

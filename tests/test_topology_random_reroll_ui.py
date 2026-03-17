from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_random_switches_use_reroll_tokens_and_reset_dependents() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'function resetItemForRandomSelection(sectionName, item, fieldName)',
        'function markRandomReroll(item, key)',
        "getRandomRerollSalt(it, 'selected')",
        "getRandomRerollSalt(it, 'content_type')",
        "getRandomRerollSalt(it, 'pattern')",
        "if (String(el.value || '').trim().toLowerCase() === 'random') {",
        "item.content_type = 'Random';",
        "delete item.rate_kbps;",
        "delete item.period_s;",
        "delete item.jitter_pct;",
        "delete item.v_name;",
        "delete item.v_path;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing random reroll UI snippets: ' + '; '.join(missing)
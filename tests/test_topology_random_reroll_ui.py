from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_random_switches_use_reroll_tokens_and_reset_dependents() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'function resetItemForRandomSelection(sectionName, item, fieldName)',
        'function markRandomReroll(item, key)',
        'function pickDeterministicTrafficNumericValue(seedText, fieldName)',
        "getRandomRerollSalt(it, 'selected')",
        "getRandomRerollSalt(it, 'content_type')",
        "getRandomRerollSalt(it, 'pattern')",
        "'rate_kbps',",
        "'period_s',",
        "'jitter_pct',",
        "if (String(el.value || '').trim().toLowerCase() === 'random') {",
        "item.content_type = 'Random';",
        "delete item.rate_kbps;",
        "delete item.period_s;",
        "delete item.jitter_pct;",
        "markRandomReroll(item, 'rate_kbps');",
        "markRandomReroll(item, 'period_s');",
        "markRandomReroll(item, 'jitter_pct');",
        'const showPayloadDependents = payloadValue !== \'Random\';',
        "const showPatternDependents = showPayloadDependents && patternValue !== 'Random';",
        "} else if (field === 'content_type' || field === 'pattern') {",
        "if (sec === 'Traffic') {",
        'renderMain();',
        "delete item.v_name;",
        "delete item.v_path;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing random reroll UI snippets: ' + '; '.join(missing)


def test_traffic_random_visibility_hierarchy_is_explicit() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (field === 'selected') {",
        "item.content_type = 'Random';",
        "item.pattern = 'Random';",
        "if (field === 'content_type') {",
        "if (field === 'pattern') {",
        "const payloadValue = (it.content_type || 'Random');",
        "const patternValue = (it.pattern || 'Random');",
        "const showPayloadDependents = payloadValue !== 'Random';",
        "const showPatternDependents = showPayloadDependents && patternValue !== 'Random';",
        "style=\"display:${showPayloadDependents ? 'block' : 'none'};\"",
        "style=\"display:${showPatternDependents ? 'block' : 'none'};\"",
        "} else if (field === 'content_type' || field === 'pattern') {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing traffic random visibility hierarchy snippets: ' + '; '.join(missing)


def test_random_reset_helpers_are_not_nested_inside_save_concretizer() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    concretize_idx = text.find('function concretizeRandomSelectionsForSave(scenarios) {')
    reroll_idx = text.find('function nextRandomRerollToken() {')
    reset_idx = text.find('function resetItemForRandomSelection(sectionName, item, fieldName) {')

    assert concretize_idx != -1, 'Missing concretizeRandomSelectionsForSave function'
    assert reroll_idx != -1, 'Missing nextRandomRerollToken helper'
    assert reset_idx != -1, 'Missing resetItemForRandomSelection helper'
    assert reroll_idx < concretize_idx, 'Random reroll helper must be top-level, not nested inside concretizeRandomSelectionsForSave'
    assert reset_idx < concretize_idx, 'Random reset helper must be top-level, not nested inside concretizeRandomSelectionsForSave'
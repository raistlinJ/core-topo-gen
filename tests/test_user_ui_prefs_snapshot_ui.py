from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_user_ui_prefs_are_hydrated_and_collected_via_server_snapshot() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'const initialEditorSnapshot = (initialPayload && typeof initialPayload.editor_snapshot === \'object\')',
        'function hydrateBrowserUiPrefsFromServerSnapshot(snapshot) {',
        'hydrateBrowserUiPrefsFromServerSnapshot(initialEditorSnapshot);',
        'function collectUserScopedUiPrefs() {',
        'function persistUserScopedUiPrefsSoon() {',
        'function getAiGeneratorScenarioKeys(scenario, idx = null) {',
        'const candidateKeys = getAiGeneratorScenarioKeys(scenario, idx);',
        'for (const key of getAiGeneratorScenarioKeys(scenario, idx)) {',
        'ui_prefs: collectUserScopedUiPrefs(),',
        'localStorage.setItem(USER_UI_PREFS_SECTION_COLLAPSE_KEY, JSON.stringify(prefs.section_collapse_state));',
        'localStorage.setItem(AI_GENERATOR_STATE_STORAGE_KEY, JSON.stringify(prefs.ai_generator_state));',
        'sessionStorage.setItem(USER_UI_PREFS_GRAPH_LABELS_STATE_KEY, graphLabelsState);',
        'try { persistUserScopedUiPrefsSoon(); } catch (err) { }',
        'try { persistUserScopedUiPrefsSoon(); } catch (e) { }',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing user-scoped UI preference snapshot wiring: ' + '; '.join(missing)
from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
LAYOUT_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "layout.html"


def test_logout_waits_for_editor_snapshot_persist() -> None:
    layout_text = LAYOUT_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    index_text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_layout_snippets = [
        'data-coretg-logout-form="1"',
        'const handler = window.CORETG_PREPARE_LOGOUT;',
        "const result = await prepareBeforeLogout();",
        "'Logout blocked'",
        'HTMLFormElement.prototype.submit.call(form);',
    ]
    expected_index_snippets = [
        'window.CORETG_PREPARE_LOGOUT = async function () {',
        'persistEditorState({ skipXml: true });',
        'storeCorePasswordInSession();',
        'const result = await persistEditorSnapshotToServerNow();',
    ]

    missing_layout = [snippet for snippet in expected_layout_snippets if snippet not in layout_text]
    missing_index = [snippet for snippet in expected_index_snippets if snippet not in index_text]

    assert not missing_layout, 'Missing logout persistence wiring in layout.html: ' + '; '.join(missing_layout)
    assert not missing_index, 'Missing pre-logout snapshot flush hook in index.html: ' + '; '.join(missing_index)
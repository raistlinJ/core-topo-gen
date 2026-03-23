from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_user_snapshot_autosave_is_enabled_and_serialized() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'let serverSnapshotPersistPromise = null;',
        'const ENABLE_SERVER_SNAPSHOT_AUTOSAVE = true;',
        'async function persistNextQueuedServerSnapshot() {',
        'if (serverSnapshotPersistPromise) {',
        'return serverSnapshotPersistPromise;',
        'if (serverSnapshotPendingPayload) {',
        'await persistNextQueuedServerSnapshot();',
        'void persistNextQueuedServerSnapshot();',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing continuous user snapshot autosave snippets: ' + '; '.join(missing)
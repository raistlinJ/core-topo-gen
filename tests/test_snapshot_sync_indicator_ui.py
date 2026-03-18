from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_snapshot_sync_indicator_is_bound_to_snapshot_lifecycle() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'id="snapshotSyncStatus" class="snapshot-sync-indicator is-idle"',
        "let snapshotSyncState = { status: 'idle', lastSuccessAt: null, error: '' };",
        'function renderSnapshotSyncIndicator() {',
        "label = 'Unsynced changes';",
        "label = 'Syncing...';",
        "label = 'Sync failed';",
        "updateSnapshotSyncState('syncing');",
        "updateSnapshotSyncState('saved', { lastSuccessAt: Date.now(), error: '' });",
        "updateSnapshotSyncState('pending', { error: '' });",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing snapshot sync indicator wiring: ' + '; '.join(missing)
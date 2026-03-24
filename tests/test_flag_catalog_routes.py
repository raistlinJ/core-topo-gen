import json
from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


FLAG_CATALOG_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'flag_catalog.html'
GENERATOR_CATALOG_TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'partials' / 'generator_catalog_tabs.html'


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_flag_catalog_page_groups_installed_ids_by_kind(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(
        backend,
        '_load_installed_generator_packs_state',
        lambda: {
            'packs': [
                {
                    'id': 'pack-1',
                    'installed': [
                        {'kind': 'flag-generator', 'id': 'alpha'},
                        {'kind': 'flag-generator', 'id': 'alpha'},
                        {'kind': 'flag-node-generator', 'id': 'beta'},
                    ],
                }
            ]
        },
    )

    resp = client.get('/flag_catalog')

    assert resp.status_code == 200
    page = resp.get_data(as_text=True)
    assert 'pack-1' in page
    assert 'flag-generator' in page
    assert 'flag-node-generator' in page
    assert 'Batch Test' in page
    assert 'packInstallSuccessAlert' in page
    assert 'packImportUrlForm' in page
    assert 'packUploadProgressTitle' in page


def test_flag_catalog_batch_status_skips_fetch_without_active_run() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert "if (!targetRunId) {" in text
    assert "renderFlagBatchStatus(null);" in text
    assert "return;" in text


def test_flag_catalog_template_handles_duplicate_conflict_rows() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'submitPackUninstall(packId, packLabel)' in text
    assert 'Duplicate ID' in text
    assert 'Uninstall Pack' in text


def test_generator_catalog_tabs_use_bootstrap_tab_triggers() -> None:
    text = GENERATOR_CATALOG_TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'id="flagGeneratorsTab"' in text
    assert 'data-bs-toggle="tab"' in text
    assert 'href="#flagGenerators"' in text
    assert 'aria-controls="flagGenerators"' in text
    assert 'href="#flagGenSources"' in text
    assert 'href="#flagNodeGenerators"' in text
    assert 'href="#flagBatch"' in text


def test_flag_catalog_template_redacts_sensitive_test_log_lines() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'function _redactSensitiveTestLine(line, extraTokens = [])' in text
    assert '_redactSensitiveTestLine(line)' in text


def test_flag_generators_data_includes_duplicate_installed_pack_entries(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    duplicate_a = install_root / 'flag_generators' / 'p_pack_a__5'
    duplicate_b = install_root / 'flag_generators' / 'p_pack_b__6'
    duplicate_a.mkdir(parents=True)
    duplicate_b.mkdir(parents=True)

    manifest_text = """manifest_version: 1
id: 5
kind: flag-generator
name: Mario HTTP Drop
description: duplicate test entry
language: python
inputs:
  - name: seed
    type: string
artifacts:
  produces:
    - Flag(flag_id)
injects: []
"""
    (duplicate_a / 'manifest.yaml').write_text(manifest_text, encoding='utf-8')
    (duplicate_b / 'manifest.yaml').write_text(manifest_text.replace('id: 5', 'id: 6'), encoding='utf-8')
    (duplicate_a / '.coretg_pack.json').write_text(json.dumps({
        'pack_id': 'pack-a',
        'pack_label': 'Pack A',
        'generator_id': '5',
        'source_generator_id': 'mario_http_drop',
    }), encoding='utf-8')
    (duplicate_b / '.coretg_pack.json').write_text(json.dumps({
        'pack_id': 'pack-b',
        'pack_label': 'Pack B',
        'generator_id': '6',
        'source_generator_id': 'mario_http_drop',
    }), encoding='utf-8')

    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([], [
        {'error': 'duplicate generator id: mario_http_drop', 'path': str(duplicate_a / 'manifest.yaml')},
        {'error': 'duplicate generator id: mario_http_drop', 'path': str(duplicate_b / 'manifest.yaml')},
    ]))
    monkeypatch.setattr(backend, '_load_installed_generator_packs_state', lambda: {
        'packs': [
            {
                'id': 'pack-a',
                'label': 'Pack A',
                'installed': [
                    {'kind': 'flag-generator', 'path': str(duplicate_a), 'id': '5'},
                ],
            },
            {
                'id': 'pack-b',
                'label': 'Pack B',
                'installed': [
                    {'kind': 'flag-generator', 'path': str(duplicate_b), 'id': '6'},
                ],
            },
        ]
    })

    client = app.test_client()
    _login(client)
    resp = client.get('/flag_generators_data')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('errors') == []
    generators = payload.get('generators') or []
    assert len(generators) == 2
    assert {g.get('id') for g in generators if isinstance(g, dict)} == {'mario_http_drop'}
    assert {g.get('_pack_id') for g in generators if isinstance(g, dict)} == {'pack-a', 'pack-b'}
    assert all(g.get('_duplicate_conflict') is True for g in generators if isinstance(g, dict))


def test_data_sources_page_is_still_renderable(monkeypatch):
    client = app.test_client()
    _login(client)

    resp = client.get('/data_sources')

    assert resp.status_code == 200
    assert 'data' in resp.get_data(as_text=True).lower()
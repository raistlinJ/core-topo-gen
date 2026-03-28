from __future__ import annotations

from copy import deepcopy

from flask import Flask

from webapp.routes import vuln_catalog_mutations


def _build_app(initial_state):
    app = Flask(__name__)
    app.secret_key = 'test-secret'
    state = deepcopy(initial_state)
    writes = []
    csv_calls = []
    rmtree_calls = []

    @app.route('/vuln_catalog_page')
    def vuln_catalog_page():
        return 'catalog page'

    def load_state():
        return deepcopy(state)

    def write_state(new_state):
        state.clear()
        state.update(deepcopy(new_state))
        writes.append(deepcopy(new_state))

    def active_entry(current_state):
        active_id = str(current_state.get('active_id') or '').strip()
        for catalog in current_state.get('catalogs') or []:
            if str(catalog.get('id') or '').strip() == active_id:
                return catalog
        return None

    def normalize_items(entry):
        return [dict(item) for item in (entry.get('compose_items') or [])]

    def write_csv_from_items(**kwargs):
        csv_calls.append(kwargs)
        return [f"generated/{kwargs['catalog_id']}.csv"]

    shutil_module = type(
        'ShutilModule',
        (),
        {'rmtree': lambda self, path, ignore_errors=True: rmtree_calls.append((path, ignore_errors))},
    )()

    vuln_catalog_mutations.register(
        app,
        require_builder_or_admin=lambda: None,
        load_vuln_catalogs_state=load_state,
        write_vuln_catalogs_state=write_state,
        get_active_vuln_catalog_entry=active_entry,
        normalize_vuln_catalog_items=normalize_items,
        write_vuln_catalog_csv_from_items=write_csv_from_items,
        vuln_catalog_pack_dir=lambda catalog_id: f'/tmp/catalogs/{catalog_id}',
        shutil_module=shutil_module,
    )
    return app, state, writes, csv_calls, rmtree_calls


def test_vuln_catalog_packs_set_active_updates_state_and_redirects():
    app, state, writes, _, _ = _build_app(
        {
            'active_id': 'pack-1',
            'catalogs': [
                {'id': 'pack-1', 'compose_items': []},
                {'id': 'pack-2', 'compose_items': []},
            ],
        }
    )
    client = app.test_client()

    response = client.post('/vuln_catalog_packs/set_active/pack-2')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/vuln_catalog_page')
    assert state['active_id'] == 'pack-2'
    assert writes[-1]['active_id'] == 'pack-2'


def test_vuln_catalog_packs_delete_removes_catalog_and_pack_dir():
    app, state, writes, _, rmtree_calls = _build_app(
        {
            'active_id': 'pack-1',
            'catalogs': [
                {'id': 'pack-1', 'compose_items': []},
                {'id': 'pack-2', 'compose_items': []},
            ],
        }
    )
    client = app.test_client()

    response = client.post('/vuln_catalog_packs/delete/pack-1')

    assert response.status_code == 302
    assert [catalog['id'] for catalog in state['catalogs']] == ['pack-2']
    assert state['active_id'] == 'pack-2'
    assert writes[-1]['active_id'] == 'pack-2'
    assert rmtree_calls == [('/tmp/catalogs/pack-1', True)]


def test_vuln_catalog_items_set_disabled_updates_item_and_regenerates_csv():
    app, state, writes, csv_calls, _ = _build_app(
        {
            'active_id': 'pack-1',
            'catalogs': [
                {
                    'id': 'pack-1',
                    'compose_items': [
                        {'id': 11, 'disabled': False},
                        {'id': 12, 'disabled': False},
                    ],
                }
            ],
        }
    )
    client = app.test_client()

    response = client.post('/vuln_catalog_items/set_disabled', json={'item_id': 12, 'disabled': True})

    assert response.status_code == 200
    assert response.get_json() == {'ok': True}
    items = state['catalogs'][0]['compose_items']
    assert items[1]['disabled'] is True
    assert state['catalogs'][0]['csv_paths'] == ['generated/pack-1.csv']
    assert writes[-1]['catalogs'][0]['compose_items'][1]['disabled'] is True
    assert csv_calls[-1]['catalog_id'] == 'pack-1'


def test_vuln_catalog_items_delete_removes_item_and_updates_compose_count():
    app, state, writes, csv_calls, _ = _build_app(
        {
            'active_id': 'pack-1',
            'catalogs': [
                {
                    'id': 'pack-1',
                    'compose_items': [
                        {'id': 11, 'disabled': False},
                        {'id': 12, 'disabled': True},
                    ],
                }
            ],
        }
    )
    client = app.test_client()

    response = client.post('/vuln_catalog_items/delete', json={'item_id': 11})

    assert response.status_code == 200
    assert response.get_json() == {'ok': True}
    assert state['catalogs'][0]['compose_count'] == 1
    assert state['catalogs'][0]['compose_items'] == [{'id': 12, 'disabled': True}]
    assert writes[-1]['catalogs'][0]['compose_count'] == 1
    assert csv_calls[-1]['items'] == [{'id': 12, 'disabled': True}]


def test_vuln_catalog_items_set_disabled_returns_404_for_missing_item():
    app, _, writes, _, _ = _build_app(
        {
            'active_id': 'pack-1',
            'catalogs': [{'id': 'pack-1', 'compose_items': [{'id': 11, 'disabled': False}]}],
        }
    )
    client = app.test_client()

    response = client.post('/vuln_catalog_items/set_disabled', json={'item_id': 99, 'disabled': True})

    assert response.status_code == 404
    assert response.get_json() == {'ok': False, 'error': 'Unknown item id'}
    assert writes == []


def test_vuln_catalog_items_batch_override_fail_updates_multiple_items():
    app, state, writes, csv_calls, _ = _build_app(
        {
            'active_id': 'pack-1',
            'catalogs': [
                {
                    'id': 'pack-1',
                    'compose_items': [
                        {'id': 11, 'disabled': False, 'validated_ok': True},
                        {'id': 12, 'disabled': False, 'validated_ok': None, 'validated_incomplete': True},
                        {'id': 13, 'disabled': False, 'validated_ok': True},
                    ],
                }
            ],
        }
    )
    client = app.test_client()

    response = client.post('/vuln_catalog_items/batch_mutate', json={'item_ids': [11, 12], 'action': 'override_fail'})

    assert response.status_code == 200
    payload = response.get_json() or {}
    assert payload['ok'] is True
    assert payload['updated'] == [11, 12]
    assert payload['message'] == 'Applied override_fail to 2 item(s).'
    items = state['catalogs'][0]['compose_items']
    assert items[0]['validated_ok'] is False
    assert items[0]['validated_incomplete'] is False
    assert items[0]['validated_at']
    assert items[1]['validated_ok'] is False
    assert items[1]['validated_incomplete'] is False
    assert items[1]['validated_at']
    assert writes[-1]['catalogs'][0]['compose_items'][0]['validated_ok'] is False
    assert csv_calls[-1]['catalog_id'] == 'pack-1'
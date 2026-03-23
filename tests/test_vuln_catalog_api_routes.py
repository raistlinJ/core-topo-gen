from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_vuln_catalog_returns_pack_backed_items(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_load_vuln_catalogs_state', lambda: {'active_id': 'cat-1', 'catalogs': [{'id': 'cat-1'}]})
    monkeypatch.setattr(backend, '_get_active_vuln_catalog_entry', lambda state: {'id': 'cat-1', 'label': 'Pack Label'})
    monkeypatch.setattr(
        backend,
        '_normalize_vuln_catalog_items',
        lambda entry: [
            {
                'id': 10,
                'name': 'root-service',
                'rel_dir': 'items/web/auth',
                'validated_ok': True,
                'validated_at': '2026-03-19 10:00:00',
            },
            {
                'id': 12,
                'name': 'blocked-service',
                'rel_dir': 'items/web/blocked',
                'validated_ok': False,
                'validated_at': '2026-03-18 11:00:00',
            },
            {
                'id': 11,
                'name': 'skip-me',
                'rel_dir': 'items/web/skip',
                'disabled': True,
            },
        ],
    )
    monkeypatch.setattr(
        backend,
        '_vuln_catalog_item_abs_compose_path',
        lambda **kwargs: f"/abs/{kwargs['catalog_id']}/{kwargs['item']['id']}/docker-compose.yml",
    )

    resp = client.get('/vuln_catalog')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['types'] == ['docker-compose']
    assert payload['vectors'] == []
    assert payload['items'] == [
        {
            'Name': 'web/auth',
            'Path': '/abs/cat-1/10/docker-compose.yml',
            'Type': 'docker-compose',
            'Vector': '',
            'Startup': '',
            'CVE': '',
            'Description': '',
            'References': '',
            'id': '10',
            'from_source': 'Pack Label',
            'files_api_url': '/vuln_catalog_packs/item_files/cat-1/10',
            'validated_ok': True,
            'validated_at': '2026-03-19 10:00:00',
            'eligible_for_selection': True,
        },
        {
            'Name': 'web/blocked',
            'Path': '/abs/cat-1/12/docker-compose.yml',
            'Type': 'docker-compose',
            'Vector': '',
            'Startup': '',
            'CVE': '',
            'Description': '',
            'References': '',
            'id': '12',
            'from_source': 'Pack Label',
            'files_api_url': '/vuln_catalog_packs/item_files/cat-1/12',
            'validated_ok': False,
            'validated_at': '2026-03-18 11:00:00',
            'eligible_for_selection': False,
        },
    ]


def test_load_backend_vuln_catalog_items_returns_only_validated_selectable_items(monkeypatch):
    monkeypatch.setattr(backend, '_load_vuln_catalogs_state', lambda: {'active_id': 'cat-1', 'catalogs': [{'id': 'cat-1'}]})
    monkeypatch.setattr(backend, '_get_active_vuln_catalog_entry', lambda state: {'id': 'cat-1', 'label': 'Pack Label'})
    monkeypatch.setattr(
        backend,
        '_normalize_vuln_catalog_items',
        lambda entry: [
            {'id': 10, 'name': 'alpha', 'rel_dir': 'items/web/alpha', 'validated_ok': True},
            {'id': 11, 'name': 'beta', 'rel_dir': 'items/web/beta', 'validated_ok': False},
            {'id': 12, 'name': 'gamma', 'rel_dir': 'items/web/gamma', 'validated_incomplete': True, 'validated_ok': None},
            {'id': 13, 'name': 'delta', 'rel_dir': 'items/web/delta', 'validated_ok': True, 'disabled': True},
        ],
    )
    monkeypatch.setattr(
        backend,
        '_vuln_catalog_item_abs_compose_path',
        lambda **kwargs: f"/abs/{kwargs['catalog_id']}/{kwargs['item']['id']}/docker-compose.yml",
    )

    items = backend._load_backend_vuln_catalog_items()

    assert items == [
        {
            'Name': 'web/alpha',
            'Path': '/abs/cat-1/10/docker-compose.yml',
            'Type': 'docker-compose',
            'Vector': '',
            'Startup': '',
            'CVE': '',
            'Description': '',
            'References': '',
            'id': '10',
            'validated_ok': True,
            'validated_at': None,
            'eligible_for_selection': True,
        }
    ]
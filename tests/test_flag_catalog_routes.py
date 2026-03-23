from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


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


def test_data_sources_page_is_still_renderable(monkeypatch):
    client = app.test_client()
    _login(client)

    resp = client.get('/data_sources')

    assert resp.status_code == 200
    assert 'data' in resp.get_data(as_text=True).lower()
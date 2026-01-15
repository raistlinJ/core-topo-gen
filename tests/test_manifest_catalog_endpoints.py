from webapp.app_backend import app


def test_flag_generators_data_comes_from_manifests():
    client = app.test_client()
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (200, 302)
    resp = client.get('/flag_generators_data')
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)

    errors = data.get('errors')
    assert errors == [] or errors is None

    gens = data.get('generators')
    assert isinstance(gens, list)

    ids = {g.get('id') for g in gens if isinstance(g, dict)}
    # Canary manifests that should always exist in-repo.
    assert 'binary_embed_text' in ids
    assert 'textfile_username_password' in ids


def test_flag_node_generators_data_comes_from_manifests():
    client = app.test_client()
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (200, 302)
    resp = client.get('/flag_node_generators_data')
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)

    errors = data.get('errors')
    assert errors == [] or errors is None

    gens = data.get('generators')
    assert isinstance(gens, list)

    ids = {g.get('id') for g in gens if isinstance(g, dict)}
    assert 'nfs_sensitive_file' in ids

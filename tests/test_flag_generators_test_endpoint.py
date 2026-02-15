import webapp.app_backend as app_backend


class _DummyProcess:
    pid = 4242

    def wait(self):
        return 0


def test_flag_generators_test_run_returns_json_ok(monkeypatch, tmp_path):
    monkeypatch.setattr(
        app_backend,
        "_find_enabled_generator_by_id",
        lambda _generator_id: {"id": "textfile_username_password", "inputs": []},
    )
    monkeypatch.setattr(app_backend.subprocess, "Popen", lambda *args, **kwargs: _DummyProcess())
    monkeypatch.setattr(app_backend, "_get_repo_root", lambda: str(tmp_path))

    client = app_backend.app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/flag_generators_test/run",
        data={
            "generator_id": "textfile_username_password",
            "flag_prefix": "FLAG",
            "seed": "123",
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get("ok") is True
    run_id = payload.get("run_id")
    assert isinstance(run_id, str) and run_id

    app_backend.RUNS.pop(run_id, None)


def test_flag_node_generators_test_run_returns_json_ok(monkeypatch, tmp_path):
    monkeypatch.setattr(
        app_backend,
        "_find_enabled_node_generator_by_id",
        lambda _generator_id: {"id": "sample_node_generator", "inputs": []},
    )
    monkeypatch.setattr(app_backend.subprocess, "Popen", lambda *args, **kwargs: _DummyProcess())
    monkeypatch.setattr(app_backend, "_get_repo_root", lambda: str(tmp_path))

    client = app_backend.app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/flag_node_generators_test/run",
        data={
            "generator_id": "sample_node_generator",
            "flag_prefix": "FLAG",
            "seed": "123",
        },
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get("ok") is True
    run_id = payload.get("run_id")
    assert isinstance(run_id, str) and run_id

    app_backend.RUNS.pop(run_id, None)

from pathlib import Path

from flask import Flask

from webapp.routes import admin_cleanup_pycore


def test_admin_cleanup_pycore_removes_only_stale_inactive_dirs(tmp_path):
    stale = tmp_path / 'pycore.1001'
    active = tmp_path / 'pycore.2002'
    recent = tmp_path / 'pycore.3003'
    invalid = tmp_path / 'pycore.not-a-session'
    for path in [stale, active, recent, invalid]:
        path.mkdir()

    fake_now = 10_000.0
    old_ts = fake_now - 120.0
    recent_ts = fake_now - 5.0
    active.touch()
    stale.touch()
    recent.touch()
    invalid.touch()
    old_ns = int(old_ts * 1_000_000_000)
    recent_ns = int(recent_ts * 1_000_000_000)
    for path in [stale, active, invalid]:
        path.touch()
        path.chmod(0o755)
        import os
        os.utime(path, ns=(old_ns, old_ns))
    import os
    os.utime(recent, ns=(recent_ns, recent_ns))

    removed: list[str] = []
    app = Flask(__name__)
    admin_cleanup_pycore.register(
        app,
        core_config_for_request=lambda **kwargs: {'host': 'core.example', 'port': 6000},
        list_active_core_sessions=lambda *_args, **_kwargs: [{'id': 2002}],
        core_host_default='127.0.0.1',
        core_port_default=50051,
        pycore_globber=lambda: [stale, active, recent, invalid],
        time_func=lambda: fake_now,
        rmtree_func=lambda path: removed.append(path),
    )

    client = app.test_client()
    resp = client.post('/admin/cleanup_pycore')

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload['ok'] is True
    assert payload['removed'] == [str(stale)]
    assert sorted(payload['kept']) == sorted([str(active), str(recent), str(invalid)])
    assert payload['active_session_ids'] == [2002]
    assert removed == [str(stale)]


def test_admin_cleanup_pycore_returns_json_error_on_config_failure():
    app = Flask(__name__)
    admin_cleanup_pycore.register(
        app,
        core_config_for_request=lambda **kwargs: (_ for _ in ()).throw(RuntimeError('boom')),
        list_active_core_sessions=lambda *_args, **_kwargs: [],
        core_host_default='127.0.0.1',
        core_port_default=50051,
        pycore_globber=lambda: [],
    )

    client = app.test_client()
    resp = client.post('/admin/cleanup_pycore')

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload['ok'] is False
    assert payload['error'] == 'boom'
import os

from webapp import app_backend
from webapp.app_backend import app


class _ImmediateThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args or ()
        self._kwargs = kwargs or {}

    def start(self):
        if self._target:
            self._target(*self._args, **self._kwargs)


def test_vuln_catalog_stop_cleanup_removes_local_run_dir(tmp_path, monkeypatch):
    run_dir = tmp_path / 'vuln-test-run'
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / 'run.log'
    log_path.write_text('seed\n', encoding='utf-8')

    meta = {
        'kind': 'vuln_test',
        'run_dir': str(run_dir),
        'log_path': str(log_path),
        'remote_run_dir': '/tmp/tests/test-abc123',
        'remote_compose_path': '/tmp/tests/test-abc123/docker-compose.runtime.yml',
        'project_name': 'coretg-vuln-test-1',
        'catalog_id': 'cat-1',
        'item_id': 1,
        'core_cfg': {'ssh_host': '127.0.0.1', 'ssh_username': 'u', 'ssh_password': 'p'},
        'cleanup_started': False,
        'cleanup_done': False,
        'cleanup_generated_artifacts': True,
        'done': False,
    }

    monkeypatch.setattr(app_backend.threading, 'Thread', _ImmediateThread)
    monkeypatch.setattr(app_backend, '_open_ssh_client', lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError('no ssh in test')))
    monkeypatch.setattr(app_backend, '_load_vuln_catalogs_state', lambda: {'catalogs': []})
    monkeypatch.setattr(app_backend, '_write_vuln_catalogs_state', lambda _state: None)

    with app.app_context():
        response = app_backend._stop_vuln_test_meta(meta, user_ok=True)
        data = response.get_json() or {}

    assert data.get('ok') is True
    assert meta.get('cleanup_started') is True
    assert meta.get('cleanup_done') is True
    assert meta.get('done') is True
    assert not run_dir.exists()


def test_vuln_catalog_stop_cleanup_can_preserve_local_run_dir_when_disabled(tmp_path, monkeypatch):
    run_dir = tmp_path / 'vuln-test-run-keep'
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / 'run.log'
    log_path.write_text('seed\n', encoding='utf-8')

    meta = {
        'kind': 'vuln_test',
        'run_dir': str(run_dir),
        'log_path': str(log_path),
        'remote_run_dir': '/tmp/tests/test-def456',
        'remote_compose_path': '/tmp/tests/test-def456/docker-compose.runtime.yml',
        'project_name': 'coretg-vuln-test-2',
        'catalog_id': 'cat-2',
        'item_id': 2,
        'core_cfg': {'ssh_host': '127.0.0.1', 'ssh_username': 'u', 'ssh_password': 'p'},
        'cleanup_started': False,
        'cleanup_done': False,
        'cleanup_generated_artifacts': False,
        'done': False,
    }

    monkeypatch.setattr(app_backend.threading, 'Thread', _ImmediateThread)
    monkeypatch.setattr(app_backend, '_open_ssh_client', lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError('no ssh in test')))
    monkeypatch.setattr(app_backend, '_load_vuln_catalogs_state', lambda: {'catalogs': []})
    monkeypatch.setattr(app_backend, '_write_vuln_catalogs_state', lambda _state: None)

    with app.app_context():
        response = app_backend._stop_vuln_test_meta(meta, user_ok=False)
        data = response.get_json() or {}

    assert data.get('ok') is True
    assert meta.get('cleanup_started') is True
    assert meta.get('cleanup_done') is True
    assert meta.get('done') is True
    assert run_dir.exists()

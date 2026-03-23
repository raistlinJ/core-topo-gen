from pathlib import Path

from webapp import app_backend as backend
from webapp.routes import flag_compose as flag_compose_routes
from webapp.routes import vuln_compose as vuln_compose_routes


app = backend.app
app.config.setdefault('TESTING', True)
app.config['TESTING'] = True


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_flag_compose_remove_uses_rmi_all_for_local_compose(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    compose_path = tmp_path / 'docker-compose.yml'
    compose_path.write_text('services:\n  demo:\n    image: alpine:3.19\n', encoding='utf-8')

    calls = []

    class _Proc:
        def __init__(self, returncode=0, stdout=''):
            self.returncode = returncode
            self.stdout = stdout

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _Proc(0, '')

    monkeypatch.setattr(flag_compose_routes.shutil, 'which', lambda name: '/usr/bin/docker' if name == 'docker' else None)
    monkeypatch.setattr(flag_compose_routes.subprocess, 'run', fake_run)

    resp = client.post('/flag_compose/remove', json={
        'items': [{
            'name': 'Local Flag Compose',
            'path': str(compose_path),
            'compose_name': 'docker-compose.yml',
        }]
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('items', [{}])[0].get('ok') is True
    assert calls == [[
        'docker', 'compose', '-f', str(compose_path), 'down', '--volumes', '--remove-orphans', '--rmi', 'all'
    ]]
    assert compose_path.exists()


def test_vuln_compose_remove_uses_rmi_all_and_removes_listed_images(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))

    vuln_dir = tmp_path / 'vuln-local'
    vuln_dir.mkdir(parents=True, exist_ok=True)
    compose_path = vuln_dir / 'docker-compose.yml'
    compose_path.write_text('services:\n  web:\n    image: nginx:alpine\n', encoding='utf-8')

    calls = []

    class _Proc:
        def __init__(self, returncode=0, stdout=''):
            self.returncode = returncode
            self.stdout = stdout

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:6] == ['docker', 'compose', '-f', str(compose_path), 'config', '--images']:
            return _Proc(0, 'nginx:alpine\ncustom/demo:latest\n')
        return _Proc(0, '')

    monkeypatch.setattr(vuln_compose_routes.shutil, 'which', lambda name: '/usr/bin/docker' if name == 'docker' else None)
    monkeypatch.setattr(vuln_compose_routes.subprocess, 'run', fake_run)

    resp = client.post('/vuln_compose/remove', json={
        'items': [{
            'Name': 'Local Vuln Compose',
            'Path': str(vuln_dir),
            'compose': 'docker-compose.yml',
        }]
    })

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('items', [{}])[0].get('ok') is True
    assert ['docker', 'compose', '-f', str(compose_path), 'down', '--volumes', '--remove-orphans', '--rmi', 'all'] in calls
    assert ['docker', 'compose', '-f', str(compose_path), 'config', '--images'] in calls
    assert ['docker', 'image', 'rm', '-f', 'nginx:alpine'] in calls
    assert ['docker', 'image', 'rm', '-f', 'custom/demo:latest'] in calls
    assert compose_path.exists()

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


class _FakeChannel:
    def __init__(self, code):
        self._code = code

    def recv_exit_status(self):
        return self._code


class _FakeStream:
    def __init__(self, data, code=0):
        self._data = data
        self.channel = _FakeChannel(code)

    def read(self):
        return self._data


class _FakeStdin:
    def close(self):
        return None


class _FakeSSHClient:
    stdout_payload = b''
    stderr_payload = b''
    exit_code = 0

    def set_missing_host_key_policy(self, *_args, **_kwargs):
        return None

    def connect(self, **_kwargs):
        self.connect_kwargs = _kwargs
        return None

    def exec_command(self, _cmd, timeout=30.0):
        return _FakeStdin(), _FakeStream(self.stdout_payload, self.exit_code), _FakeStream(self.stderr_payload, self.exit_code)

    def close(self):
        return None


class _FakeParamiko:
    SSHClient = _FakeSSHClient

    class AutoAddPolicy:
        pass


def test_test_core_venv_requires_ssh_host(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko)

    resp = client.post('/test_core_venv', json={'venv_bin': '/opt/core/bin'})

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert 'SSH host' in str(payload.get('error') or '')


def test_test_core_venv_success(monkeypatch):
    client = app.test_client()
    _login(client)

    _FakeSSHClient.stdout_payload = b'::VENVCHECK::{"python":"/opt/core/bin/python3","version":"3.12.2","status":"ok"}\n'
    _FakeSSHClient.stderr_payload = b''
    _FakeSSHClient.exit_code = 0

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda: None)

    resp = client.post(
        '/test_core_venv',
        json={
            'venv_bin': '/opt/core/bin',
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('ok') is True
    assert payload.get('python_executable') == '/opt/core/bin/python3'
    assert payload.get('ssh_host') == 'core-host'
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
    def __init__(self, text, code=0):
        self._text = text
        self.channel = _FakeChannel(code)

    def read(self):
        return self._text.encode('utf-8')


class _FakeStdin:
    def __init__(self):
        self.writes = []
        self.closed = False

    def write(self, value):
        self.writes.append(value)

    def flush(self):
        return None

    def close(self):
        self.closed = True


class _FakeSSHClient:
    def __init__(self):
        self.commands = []
        self.closed = False

    def exec_command(self, command, timeout=None, get_pty=False):
        self.commands.append((command, timeout, get_pty))
        if 'systemctl restart core-daemon' in command:
            return _FakeStdin(), _FakeStream('', 0), _FakeStream('', 0)
        if 'systemctl is-active core-daemon' in command:
            return _FakeStdin(), _FakeStream('active\n', 0), _FakeStream('', 0)
        raise AssertionError(f'unexpected command: {command}')

    def close(self):
        self.closed = True


def test_restart_core_daemon_requires_ssh_host(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_select_core_config_for_page', lambda *args, **kwargs: {'ssh_host': ''})

    resp = client.post('/core/restart_core_daemon')

    assert resp.status_code == 400
    assert (resp.get_json() or {}).get('error') == 'No CORE VM configured via SSH.'


def test_restart_core_daemon_succeeds(monkeypatch):
    client = app.test_client()
    _login(client)

    ssh_client = _FakeSSHClient()

    monkeypatch.setattr(backend, '_normalize_scenario_label', lambda value: value)
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda *args, **kwargs: {'ssh_host': '127.0.0.1', 'ssh_password': 'pw'},
    )
    monkeypatch.setattr(backend, '_open_ssh_client', lambda core_cfg: ssh_client)
    monkeypatch.setattr(backend.time, 'sleep', lambda _seconds: None)

    resp = client.post('/core/restart_core_daemon?scenario=Scenario%202')

    payload = resp.get_json() or {}
    assert resp.status_code == 200
    assert payload.get('status') == 'ok'
    assert ssh_client.closed is True
    assert len(ssh_client.commands) == 2
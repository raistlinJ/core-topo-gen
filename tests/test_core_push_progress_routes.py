from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


class _FakeSSHClient:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_core_push_repo_status_reports_unknown_when_missing(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_get_repo_push_progress', lambda progress_id: None)

    resp = client.get('/core/push_repo/status/demo')

    assert resp.status_code == 404
    assert (resp.get_json() or {}).get('status') == 'unknown'


def test_core_push_repo_cancel_reports_remote_cleanup(monkeypatch):
    client = app.test_client()
    _login(client)

    updates = []
    ssh_client = _FakeSSHClient()

    monkeypatch.setattr(backend, '_get_repo_push_progress', lambda progress_id: {'status': 'running'})
    monkeypatch.setattr(
        backend,
        '_get_repo_push_cancel_ctx',
        lambda progress_id: {
            'core_cfg': {'ssh_host': '127.0.0.1'},
            'remote_pidfile': '/tmp/push.pid',
            'remote_archive': '/tmp/push.tgz',
        },
    )
    monkeypatch.setattr(backend, '_update_repo_push_progress', lambda *args, **kwargs: updates.append((args, kwargs)))
    monkeypatch.setattr(backend, '_open_ssh_client', lambda core_cfg: ssh_client)
    monkeypatch.setattr(
        backend,
        '_exec_ssh_command',
        lambda client, command, timeout=25.0: (
            0,
            'PIDFILE_FOUND="1"\nPID="812"\nTERM_SENT="1"\nKILL_SENT="1"\nPIDFILE_REMOVED="1"\nARCHIVE_EXISTED_BEFORE="1"\nARCHIVE_EXISTS_AFTER="0"\n',
            '',
        ),
    )

    resp = client.post('/core/push_repo/cancel/demo')

    payload = resp.get_json() or {}
    assert resp.status_code == 200
    assert payload.get('status') == 'cancelled'
    assert payload.get('remote', {}).get('pid') == '812'
    assert payload.get('remote', {}).get('term_sent') is True
    assert payload.get('remote', {}).get('archive_exists_after') is False
    assert ssh_client.closed is True
    assert updates == [
        (
            ('demo',),
            {
                'cancel_requested': True,
                'status': 'cancelled',
                'stage': 'cancelled',
                'detail': 'Cancelled by user.',
            },
        )
    ]
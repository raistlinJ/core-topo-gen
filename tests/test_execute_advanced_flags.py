import json
import os

import pytest

from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


class _DummyTunnel:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        # local bind host/port for the tunnel
        return '127.0.0.1', 50051

    def close(self):
        return None


class _DummySSHClient:
    def close(self):
        return None


def test_run_cli_async_adv_auto_kill_sessions_invokes_delete(tmp_path, monkeypatch):
    """When adv_auto_kill_sessions is enabled, /run_cli_async should attempt to delete
    active sessions instead of returning 423 immediately."""

    from webapp import app_backend as backend

    # Create a dummy XML file to satisfy input validation.
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios></Scenarios>', encoding='utf-8')

    # Keep logs under tmp.
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(tmp_path / 'outputs'))

    # Provide a minimal CORE config without relying on saved editor state.
    fake_core_cfg = {
        'host': '127.0.0.1',
        'port': 50051,
        'ssh_enabled': True,
        'ssh_host': '127.0.0.1',
        'ssh_port': 22,
        'ssh_username': 'core',
        'ssh_password': 'pw',
        'auto_start_daemon': False,
        'venv_bin': '',
    }
    monkeypatch.setattr(backend, '_merge_core_configs', lambda *a, **k: dict(fake_core_cfg))
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(backend, '_scenario_names_from_xml', lambda _p: [])

    # Avoid real SSH/tunnel behavior.
    monkeypatch.setattr(backend, '_SshTunnel', _DummyTunnel)
    monkeypatch.setattr(backend, '_open_ssh_client', lambda _cfg: _DummySSHClient())
    monkeypatch.setattr(backend, '_check_remote_daemon_before_setup', lambda **_k: None)

    # Simulate active sessions on first query, then no sessions after deletion.
    calls = {'list': 0}

    def fake_list_sessions(host, port, core_cfg=None, **kwargs):
        calls['list'] += 1
        if calls['list'] <= 2:
            return [{'id': 7, 'state': 'running', 'nodes': 1, 'file': None}]
        return []

    deleted = []

    def fake_session_action(core_cfg, action, sid, logger=None):
        assert action == 'delete'
        deleted.append(int(sid))

    monkeypatch.setattr(backend, '_list_active_core_sessions', fake_list_sessions)
    monkeypatch.setattr(backend, '_execute_remote_core_session_action', fake_session_action)

    # Abort after advanced kill step by simulating missing remote repo.
    monkeypatch.setattr(backend, '_prepare_remote_cli_context', lambda **_k: (_ for _ in ()).throw(backend.RemoteRepoMissingError('/missing/repo')))

    client = app.test_client()
    _login(client)

    resp = client.post(
        '/run_cli_async',
        data={
            'xml_path': str(xml_path),
            'adv_auto_kill_sessions': '1',
        },
    )

    # Expect the flow to proceed past the session-block check and hit our RemoteRepoMissingError.
    assert resp.status_code == 409
    assert deleted == [7]


def test_run_cli_async_blocks_when_sessions_present_and_no_adv_kill(tmp_path, monkeypatch):
    """Without adv_auto_kill_sessions, active sessions should block /run_cli_async with 423."""

    from webapp import app_backend as backend

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios></Scenarios>', encoding='utf-8')

    fake_core_cfg = {
        'host': '127.0.0.1',
        'port': 50051,
        'ssh_enabled': True,
        'ssh_host': '127.0.0.1',
        'ssh_port': 22,
        'ssh_username': 'core',
        'ssh_password': 'pw',
        'auto_start_daemon': False,
        'venv_bin': '',
    }
    monkeypatch.setattr(backend, '_merge_core_configs', lambda *a, **k: dict(fake_core_cfg))
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)

    monkeypatch.setattr(
        backend,
        '_list_active_core_sessions',
        lambda *a, **k: [{'id': 9, 'state': 'running', 'nodes': 1, 'file': None}],
    )

    client = app.test_client()
    _login(client)

    resp = client.post(
        '/run_cli_async',
        data={
            'xml_path': str(xml_path),
        },
    )
    assert resp.status_code == 423
    payload = resp.get_json()
    assert payload and payload.get('session_count') == 1

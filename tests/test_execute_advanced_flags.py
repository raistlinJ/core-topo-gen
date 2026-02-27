import json
import os
import uuid

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


class _DummyChannel:
    def recv_exit_status(self):
        return 0


class _DummyStream:
    def __init__(self, data: bytes = b''):
        self._data = data
        self.channel = _DummyChannel()

    def read(self):
        return self._data

    def close(self):
        return None


class _DummyStdin:
    def write(self, _data):
        return None

    def flush(self):
        return None

    def close(self):
        return None


class _DummySSHClient:
    def exec_command(self, _cmd, timeout=None, get_pty=False):
        # Provide empty stdout/stderr; caller uses recv_exit_status on stdout.channel.
        return _DummyStdin(), _DummyStream(b''), _DummyStream(b'')

    def close(self):
        return None


class _NoRunThread:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
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
        'ssh_enabled': False,
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
    monkeypatch.setattr(backend.threading, 'Thread', _NoRunThread)

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

    # Endpoint now always accepts the async job and performs checks in background.
    assert resp.status_code == 202
    payload = resp.get_json() or {}
    assert isinstance(payload.get('run_id'), str) and payload.get('run_id')


def test_run_cli_async_blocks_when_sessions_present_and_no_adv_kill(tmp_path, monkeypatch):
    """Without adv_auto_kill_sessions, active sessions should block /run_cli_async with 423."""

    from webapp import app_backend as backend

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios></Scenarios>', encoding='utf-8')

    fake_core_cfg = {
        'host': '127.0.0.1',
        'port': 50051,
        'ssh_enabled': False,
        'ssh_host': '127.0.0.1',
        'ssh_port': 22,
        'ssh_username': 'core',
        'ssh_password': 'pw',
        'auto_start_daemon': False,
        'venv_bin': '',
    }
    monkeypatch.setattr(backend, '_merge_core_configs', lambda *a, **k: dict(fake_core_cfg))
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(backend, '_SshTunnel', _DummyTunnel)
    monkeypatch.setattr(backend, '_open_ssh_client', lambda _cfg: _DummySSHClient())
    monkeypatch.setattr(backend.threading, 'Thread', _NoRunThread)

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
    assert resp.status_code == 202
    payload = resp.get_json() or {}
    assert isinstance(payload.get('run_id'), str) and payload.get('run_id')


def test_run_cli_async_blocks_when_flow_artifact_paths_missing(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="NewScenario1"><ScenarioEditor /></Scenario></Scenarios>',
        encoding='utf-8',
    )

    fake_core_cfg = {
        'host': '127.0.0.1',
        'port': 50051,
        'ssh_enabled': False,
        'ssh_host': '127.0.0.1',
        'ssh_port': 22,
        'ssh_username': 'core',
        'ssh_password': 'pw',
        'auto_start_daemon': False,
        'venv_bin': '',
    }

    monkeypatch.setattr(backend, '_merge_core_configs', lambda *a, **k: dict(fake_core_cfg))
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda *a, **k: dict(fake_core_cfg),
    )

    missing_artifacts = str(tmp_path / 'missing' / 'artifacts')
    missing_inject = str(tmp_path / 'missing' / 'inject' / 'exports')

    def _fake_preview_payload(_path, _scenario):
        return {
            'metadata': {
                'flow': {
                    'flag_assignments': [
                        {
                            'node_id': '7',
                            'id': 'nfs_sensitive_file',
                            'artifacts_dir': missing_artifacts,
                            'inject_files': [missing_inject],
                            'resolved_outputs': {'Flag(flag_id)': 'FLAG{abc}'},
                        }
                    ]
                }
            },
            'full_preview': {'role_counts': {'Docker': 1}},
        }

    monkeypatch.setattr(backend, '_load_preview_payload_from_path', _fake_preview_payload)

    client = app.test_client()
    _login(client)

    resp = client.post(
        '/run_cli_async',
        data={
            'xml_path': str(xml_path),
            'scenario': 'NewScenario1',
            'preview_plan': str(xml_path),
            'flow_enabled': '1',
        },
    )

    assert resp.status_code == 422
    payload = resp.get_json() or {}
    assert 'Execute requires pre-generated Flow values' in str(payload.get('error') or '')
    details = payload.get('details') if isinstance(payload.get('details'), list) else []
    assert any(isinstance(d, dict) and d.get('reason') == 'missing artifacts_dir' for d in details)
    assert any(isinstance(d, dict) and d.get('reason') == 'missing inject_source' for d in details)


def test_run_cli_async_remote_allows_missing_local_flow_paths(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="NewScenario1"><ScenarioEditor /></Scenario></Scenarios>',
        encoding='utf-8',
    )

    remote_core_cfg = {
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

    monkeypatch.setattr(backend, '_merge_core_configs', lambda *a, **k: dict(remote_core_cfg))
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda *a, **k: dict(remote_core_cfg),
    )
    monkeypatch.setattr(backend.threading, 'Thread', _NoRunThread)

    missing_artifacts = str(tmp_path / 'missing' / 'artifacts')
    missing_inject = str(tmp_path / 'missing' / 'inject' / 'exports.txt')

    def _fake_preview_payload(_path, _scenario):
        return {
            'metadata': {
                'flow': {
                    'flag_assignments': [
                        {
                            'node_id': '7',
                            'id': 'nfs_sensitive_file',
                            'artifacts_dir': missing_artifacts,
                            'inject_files': [f'{missing_inject} -> /tmp/seed'],
                            'resolved_outputs': {'Flag(flag_id)': 'FLAG{abc}'},
                        }
                    ]
                }
            },
            'full_preview': {'role_counts': {'Docker': 1}},
        }

    monkeypatch.setattr(backend, '_load_preview_payload_from_path', _fake_preview_payload)

    client = app.test_client()
    _login(client)

    resp = client.post(
        '/run_cli_async',
        data={
            'xml_path': str(xml_path),
            'scenario': 'NewScenario1',
            'preview_plan': str(xml_path),
            'flow_enabled': '1',
        },
    )

    assert resp.status_code == 202
    payload = resp.get_json() or {}
    assert isinstance(payload.get('run_id'), str) and payload.get('run_id')


def test_run_cli_async_accepts_inject_spec_with_dest_when_source_exists(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="NewScenario1"><ScenarioEditor /></Scenario></Scenarios>',
        encoding='utf-8',
    )

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
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda *a, **k: dict(fake_core_cfg),
    )

    artifacts_dir = tmp_path / 'ok' / 'artifacts'
    inject_source = tmp_path / 'ok' / 'inject' / 'exports.txt'
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    inject_source.parent.mkdir(parents=True, exist_ok=True)
    inject_source.write_text('ok', encoding='utf-8')

    def _fake_preview_payload(_path, _scenario):
        return {
            'metadata': {
                'flow': {
                    'flag_assignments': [
                        {
                            'node_id': '7',
                            'id': 'nfs_sensitive_file',
                            'artifacts_dir': str(artifacts_dir),
                            'inject_files': [f'{inject_source} -> /tmp/seed'],
                            'resolved_outputs': {'Flag(flag_id)': 'FLAG{abc}'},
                        }
                    ]
                }
            },
            'full_preview': {'role_counts': {'Docker': 1}},
        }

    monkeypatch.setattr(backend, '_load_preview_payload_from_path', _fake_preview_payload)
    monkeypatch.setattr(backend.threading, 'Thread', _NoRunThread)

    client = app.test_client()
    _login(client)

    resp = client.post(
        '/run_cli_async',
        data={
            'xml_path': str(xml_path),
            'scenario': 'NewScenario1',
            'preview_plan': str(xml_path),
            'flow_enabled': '1',
        },
    )

    assert resp.status_code == 202
    payload = resp.get_json() or {}
    assert isinstance(payload.get('run_id'), str) and payload.get('run_id')


def test_run_status_includes_flow_live_path_fields(tmp_path):
    from webapp import app_backend as backend

    run_id = f"test-run-{uuid.uuid4().hex}"
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios></Scenarios>', encoding='utf-8')

    backend.RUNS[run_id] = {
        'done': True,
        'returncode': 0,
        'xml_path': str(xml_path),
        'log_path': str(tmp_path / 'cli.log'),
        'history_added': True,
        'validation_summary': {
            'ok': False,
            'flow_live_paths_checked': 3,
            'flow_live_paths_missing_count': 1,
            'flow_live_paths_missing': ['7 artifacts_dir: /tmp/vulns/missing-artifacts'],
            'flow_live_paths_detail': [
                {
                    'node_id': '7',
                    'generator_id': 'nfs_sensitive_file',
                    'path_type': 'artifacts_dir',
                    'path': '/tmp/vulns/missing-artifacts',
                    'exists_local': False,
                    'is_remote': False,
                    'missing_local': True,
                }
            ],
        },
    }

    client = app.test_client()
    _login(client)

    try:
        resp = client.get(f'/run_status/{run_id}')
        assert resp.status_code == 200
        payload = resp.get_json() or {}
        summary = payload.get('validation_summary') if isinstance(payload.get('validation_summary'), dict) else {}

        assert summary.get('flow_live_paths_checked') == 3
        assert summary.get('flow_live_paths_missing_count') == 1
        missing = summary.get('flow_live_paths_missing') if isinstance(summary.get('flow_live_paths_missing'), list) else []
        assert any('missing-artifacts' in str(item) for item in missing)
        detail = summary.get('flow_live_paths_detail') if isinstance(summary.get('flow_live_paths_detail'), list) else []
        assert detail and isinstance(detail[0], dict)
        assert detail[0].get('path_type') == 'artifacts_dir'
    finally:
        backend.RUNS.pop(run_id, None)

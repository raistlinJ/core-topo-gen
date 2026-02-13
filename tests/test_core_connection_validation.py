from contextlib import contextmanager

import pytest

from webapp import app_backend as backend

app = backend.app
app.config.setdefault('TESTING', True)


class _NoRunThread:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        return None


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


@pytest.fixture()
def client():
    client = app.test_client()
    _login(client)
    return client


class _FakeSocket:
    def __init__(self, *args, **kwargs):
        self._args = args
        self.connected = None

    def settimeout(self, *_args, **_kwargs):
        return None

    def connect(self, address):
        self.connected = address

    def close(self):
        return None


@contextmanager
def _fake_core_connection(_cfg):
    yield '127.0.0.1', 6000


def test_require_core_ssh_credentials_requires_username():
    with pytest.raises(RuntimeError) as exc:
        backend._require_core_ssh_credentials({'host': 'core-host', 'port': 50051, 'ssh_password': 'pw'})
    assert 'SSH username is required' in str(exc.value)


def test_require_core_ssh_credentials_requires_password():
    with pytest.raises(RuntimeError) as exc:
        backend._require_core_ssh_credentials({'host': 'core-host', 'port': 50051, 'ssh_username': 'core'})
    assert 'SSH password is required' in str(exc.value)


def test_require_core_ssh_credentials_trims_fields():
    cfg = backend._require_core_ssh_credentials({
        'host': 'core-host',
        'port': 50051,
        'ssh_username': ' core ',
        'ssh_password': ' pw ',
    })
    # Config normalization preserves original values; validation trims only for checks.
    assert cfg['ssh_username'] == ' core '
    assert cfg['ssh_password'] == ' pw '


def test_test_core_requires_vm_selection(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)

    def _fail_save(_payload):  # pragma: no cover - safety net
        raise AssertionError('Should not attempt to store credentials when VM selection is missing')

    monkeypatch.setattr(backend, '_save_core_credentials', _fail_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        'scenario_name': 'Scenario Alpha',
        'scenario_index': 0,
        'hitl_core': {
            'vm_name': 'CORE VM',
            'vm_node': 'pve1',
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['ok'] is False
    assert 'Select a CORE VM' in data['error']


def test_test_core_rejects_mismatched_secret(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)

    def _fake_load(identifier):
        assert identifier == 'secret-mismatch'
        return {
            'identifier': identifier,
            'ssh_password_plain': 'stored-pw',
            'ssh_username': 'core',
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'host': 'core-host',
            'port': 50051,
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE-OLD',
        }

    monkeypatch.setattr(backend, '_load_core_credentials', _fake_load)

    def _fail_save(_payload):  # pragma: no cover - should not be called
        raise AssertionError('Should not persist credentials on mismatch')

    monkeypatch.setattr(backend, '_save_core_credentials', _fail_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': '',
            'core_secret_id': 'secret-mismatch',
        },
        'scenario_name': 'Scenario Beta',
        'scenario_index': 0,
        'hitl_core': {
            'vm_key': 'pve1::202',
            'vm_node': 'pve1',
            'vm_name': 'CORE-NEW',
            'core_secret_id': 'secret-mismatch',
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 409
    data = resp.get_json()
    assert data['ok'] is False
    assert data.get('vm_mismatch') is True
    assert 'CORE-NEW' in data['error']
    assert 'CORE-OLD' in data['error']


def test_test_core_success_includes_vm_metadata(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)

    saved_payloads = []

    def _fake_save(payload):
        saved_payloads.append(payload.copy())
        return {
            'identifier': 'secret-success',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2025-10-28T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        'scenario_name': 'Scenario Gamma',
        'scenario_index': 1,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert data['core_summary']['vm_key'] == 'pve1::101'
    assert data['core_summary']['vmid'] == 101 or data['core_summary']['vmid'] == '101'
    assert 'VM CORE VM' in data['message']
    assert saved_payloads and saved_payloads[0]['vm_key'] == 'pve1::101'
    assert saved_payloads[0]['vmid'] == 101


def test_test_core_install_custom_services_triggers_installer(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda *_args, **_kwargs: None)

    # Avoid depending on process inspection details.
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [123])

    installer_calls = []

    def _fake_installer(ssh_client, *, sudo_password, logger):
        installer_calls.append({'ssh_client': ssh_client, 'sudo_password': sudo_password})
        return {'services_dir': '/opt/core/services', 'modules': ['TrafficService']}

    monkeypatch.setattr(backend, '_install_custom_services_to_core_vm', _fake_installer)

    class _FakeSSH:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def close(self):
            return None

    class _FakeParamiko:
        @staticmethod
        def SSHClient():
            return _FakeSSH()

        @staticmethod
        def AutoAddPolicy():
            return object()

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko())

    def _fake_save(payload):
        return {
            'identifier': 'secret-install-services',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2025-10-28T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'install_custom_services': True,
        },
        'scenario_name': 'Scenario Install',
        'scenario_index': 2,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert installer_calls and installer_calls[0]['sudo_password'] == 'pw'


def test_test_core_daemon_conflict_prompts_with_pids(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda *_args, **_kwargs: None)

    # Force a daemon conflict.
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [18263, 78479])

    def _fail_save(_payload):  # pragma: no cover - should not be called
        raise AssertionError('Should not persist credentials when daemon conflict exists')

    monkeypatch.setattr(backend, '_save_core_credentials', _fail_save)

    class _FakeSSH:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def close(self):
            return None

    class _FakeParamiko:
        @staticmethod
        def SSHClient():
            return _FakeSSH()

        @staticmethod
        def AutoAddPolicy():
            return object()

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko())

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'auto_start_daemon': True,
        },
        'scenario_name': 'Scenario Conflict',
        'scenario_index': 0,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 409
    data = resp.get_json()
    assert data['ok'] is False
    assert data.get('daemon_conflict') is True
    assert data.get('code') == 'core_daemon_conflict'
    assert data.get('daemon_pids') == [18263, 78479]
    assert data.get('can_stop_daemons') is True


def test_test_core_daemon_conflict_can_be_auto_stopped(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda *_args, **_kwargs: None)

    pid_calls = {'count': 0}

    def _fake_collect(*_args, **_kwargs):
        pid_calls['count'] += 1
        return [18263, 78479] if pid_calls['count'] == 1 else [18263]

    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', _fake_collect)

    stop_calls = []

    def _fake_stop(ssh_client, *, sudo_password, pids, logger):
        stop_calls.append({'sudo_password': sudo_password, 'pids': list(pids)})
        return {'status': 'attempted'}

    monkeypatch.setattr(backend, '_stop_remote_core_daemon_conflict', _fake_stop)

    class _FakeSSH:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def close(self):
            return None

    class _FakeParamiko:
        @staticmethod
        def SSHClient():
            return _FakeSSH()

        @staticmethod
        def AutoAddPolicy():
            return object()

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko())

    def _fake_save(payload):
        return {
            'identifier': 'secret-conflict-fixed',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2025-10-28T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'stop_duplicate_daemons': True,
        },
        'scenario_name': 'Scenario Conflict Fixed',
        'scenario_index': 0,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert stop_calls and stop_calls[0]['sudo_password'] == 'pw'
    assert stop_calls[0]['pids'] == [18263, 78479]


def test_test_core_advanced_checks_fail_as_warning(client, monkeypatch):
    # Force the handler down the non-pytest code path so we exercise warning behavior.
    # (The backend intentionally skips remote checks during pytest.)
    monkeypatch.delenv('PYTEST_CURRENT_TEST', raising=False)
    monkeypatch.delitem(backend.sys.modules, 'pytest', raising=False)

    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda *_args, **_kwargs: None)

    def _fake_adv(_cfg, **_kwargs):
        return {
            'adv_check_core_version': {'enabled': True, 'ok': False, 'message': 'CORE version mismatch'},
            'adv_fix_docker_daemon': {'enabled': False, 'ok': None, 'message': ''},
            'adv_run_core_cleanup': {'enabled': True, 'ok': True, 'message': 'completed'},
            'adv_restart_core_daemon': {'enabled': False, 'ok': None, 'message': ''},
            'adv_start_core_daemon': {'enabled': False, 'ok': None, 'message': ''},
            'adv_auto_kill_sessions': {'enabled': False, 'ok': None, 'message': ''},
        }

    monkeypatch.setattr(backend, '_run_core_connection_advanced_checks', _fake_adv)

    def _fake_save(payload):
        return {
            'identifier': 'secret-adv-warning',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2025-10-28T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'adv_check_core_version': True,
            'adv_run_core_cleanup': True,
        },
        'scenario_name': 'Scenario Advanced',
        'scenario_index': 3,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert isinstance(data.get('advanced_checks'), dict)
    assert data['advanced_checks']['adv_check_core_version']['enabled'] is True
    assert data['advanced_checks']['adv_check_core_version']['ok'] is False
    assert isinstance(data.get('warnings'), list)
    assert data['warnings'] and 'Advanced checks failed' in data['warnings'][0]


def test_run_cli_async_requires_ssh_credentials(client, tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text('<Scenarios></Scenarios>')

    # Avoid heavy parsing during the test
    monkeypatch.setattr(backend, '_parse_scenarios_xml', lambda *_args, **_kwargs: {})
    monkeypatch.setattr(backend.threading, 'Thread', _NoRunThread)

    resp = client.post('/run_cli_async', data={'xml_path': str(xml_path)})
    # run_cli_async now accepts and validates execution prerequisites in background.
    assert resp.status_code == 202
    data = resp.get_json()
    assert isinstance(data.get('run_id'), str) and data.get('run_id')

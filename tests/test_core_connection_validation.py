from contextlib import contextmanager

import pytest

from webapp import app_backend as backend

app = backend.app
app.config.setdefault('TESTING', True)


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
    with pytest.raises(backend._SSHTunnelError) as exc:
        backend._require_core_ssh_credentials({'host': 'core-host', 'port': 50051, 'ssh_password': 'pw'})
    assert 'SSH username is required' in str(exc.value)


def test_require_core_ssh_credentials_requires_password():
    with pytest.raises(backend._SSHTunnelError) as exc:
        backend._require_core_ssh_credentials({'host': 'core-host', 'port': 50051, 'ssh_username': 'core'})
    assert 'SSH password is required' in str(exc.value)


def test_require_core_ssh_credentials_trims_fields():
    cfg = backend._require_core_ssh_credentials({
        'host': 'core-host',
        'port': 50051,
        'ssh_username': ' core ',
        'ssh_password': ' pw ',
    })
    assert cfg['ssh_username'] == 'core'
    assert cfg['ssh_password'] == 'pw'


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


def test_run_cli_async_requires_ssh_credentials(client, tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text('<Scenarios></Scenarios>')

    # Avoid heavy parsing during the test
    monkeypatch.setattr(backend, '_parse_scenarios_xml', lambda *_args, **_kwargs: {})

    resp = client.post('/run_cli_async', data={'xml_path': str(xml_path)})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['error'].startswith('SSH username is required')

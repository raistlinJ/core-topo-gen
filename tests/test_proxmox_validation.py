import json
from types import SimpleNamespace

import pytest

from webapp import app_backend


pytestmark = pytest.mark.skipif(app_backend.Fernet is None, reason="cryptography not installed")


@pytest.fixture(autouse=True)
def _clean_secret_cache(tmp_path, monkeypatch):
    outputs_dir = tmp_path / "outputs"
    outputs_dir.mkdir(parents=True, exist_ok=True)

    def fake_outputs_dir():
        return str(outputs_dir)

    monkeypatch.setattr(app_backend, "_outputs_dir", fake_outputs_dir)

    key = app_backend.Fernet.generate_key().decode()  # type: ignore[attr-defined]
    monkeypatch.setenv("PROXMOX_SECRET_KEY", key)

    # Ensure we use fresh cipher per test
    yield


class DummyProxmoxAPI:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.version = SimpleNamespace(get=lambda: {"version": "8.0"})


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app_backend, "ProxmoxAPI", DummyProxmoxAPI)
    with app_backend.app.test_client() as client:  # type: ignore[attr-defined]
        with client.session_transaction() as sess:
            sess['user'] = {'username': 'tester', 'role': 'admin'}
        yield client


def test_proxmox_validate_success(client, tmp_path):
    payload = {
        "url": "https://pve.example.local",
        "port": 8443,
        "username": "root@pam",
        "password": "secret",
        "scenario_index": 0,
        "scenario_name": "Scenario 1",
    }
    resp = client.post("/api/proxmox/validate", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["secret_id"]
    saved_path = tmp_path / "outputs" / "secrets" / "proxmox"
    files = list(saved_path.glob("*.json"))
    assert files, "Expected credential file to be created"
    stored = json.loads(files[0].read_text())
    assert stored["username"] == payload["username"]
    assert stored["port"] == payload["port"]

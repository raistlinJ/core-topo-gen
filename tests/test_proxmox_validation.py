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


class DummyVmConfig:
    def __init__(self, data):
        self._data = data

    def get(self):
        return self._data


class DummyQemuVm:
    def __init__(self, inventory_entry):
        self.entry = inventory_entry
        self.config = DummyVmConfig(inventory_entry.get("config", {}))


class DummyNodeQemu:
    def __init__(self, node_name, inventory):
        self.node_name = node_name
        self.inventory = inventory

    def get(self):
        return [
            {
                "vmid": vm["vmid"],
                "name": vm.get("name"),
                "status": vm.get("status", "stopped"),
            }
            for vm in self.inventory.get(self.node_name, [])
        ]

    def __call__(self, vmid):
        for vm in self.inventory.get(self.node_name, []):
            if str(vm["vmid"]) == str(vmid):
                return DummyQemuVm(vm)
        return DummyQemuVm({"config": {}})


class DummyNode:
    def __init__(self, node_name, inventory):
        self.node_name = node_name
        self.inventory = inventory
        self.qemu = DummyNodeQemu(node_name, inventory)


class DummyNodes:
    def __init__(self, inventory):
        self.inventory = inventory

    def get(self):
        return [{"node": name} for name in self.inventory.keys()]

    def __call__(self, node_name):
        return DummyNode(node_name, self.inventory)


class DummyProxmoxAPI:
    inventory = {
        "pve1": [
            {
                "vmid": 101,
                "name": "Router",
                "status": "running",
                "config": {
                    "net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,tag=10",
                    "net1": "e1000=AA:BB:CC:DD:EE:02,bridge=vmbr1",
                },
            },
            {
                "vmid": 102,
                "name": "Analyzer",
                "status": "stopped",
                "config": {
                    "net0": "virtio=AA:BB:CC:DD:EE:03,bridge=vmbr0",
                },
            },
        ]
    }

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.version = SimpleNamespace(get=lambda: {"version": "8.0"})
        self.nodes = DummyNodes(self.inventory)


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


def test_proxmox_inventory_requires_secret(client):
    resp = client.post("/api/proxmox/vms", json={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["success"] is False


def test_proxmox_inventory_success(client):
    validate_payload = {
        "url": "https://pve.example.local",
        "port": 8443,
        "username": "root@pam",
        "password": "secret",
        "scenario_index": 0,
        "scenario_name": "Scenario 1",
    }
    resp = client.post("/api/proxmox/validate", json=validate_payload)
    assert resp.status_code == 200
    secret_id = resp.get_json()["secret_id"]

    inventory_resp = client.post("/api/proxmox/vms", json={"secret_id": secret_id})
    assert inventory_resp.status_code == 200
    payload = inventory_resp.get_json()
    assert payload["success"] is True
    inventory = payload["inventory"]
    assert inventory["vms"], "Expected VM inventory to be returned"
    assert len(inventory["vms"]) == sum(len(vms) for vms in DummyProxmoxAPI.inventory.values())
    first_vm = inventory["vms"][0]
    assert first_vm["interfaces"], "Expected interfaces to be parsed"
    iface = first_vm["interfaces"][0]
    assert iface["id"] == "net0"
    assert iface["bridge"] == "vmbr0"
    assert iface["macaddr"].lower().startswith("aa:bb:cc:dd:ee")

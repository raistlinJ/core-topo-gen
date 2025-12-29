import types

import pytest

from webapp import app_backend as backend


class _FakeChannel:
    def __init__(self, exit_status: int = 0):
        self._exit_status = exit_status

    def recv_exit_status(self):
        return self._exit_status


class _FakeStream:
    def __init__(self, data: bytes = b"", exit_status: int = 0):
        self._data = data
        self.channel = _FakeChannel(exit_status)

    def read(self):
        return self._data


class _FakeStdin:
    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    def flush(self):
        return None

    def close(self):
        return None


class _FakeSFTP:
    def __init__(self):
        self.put_calls = []

    def put(self, localpath, remotepath):
        self.put_calls.append((str(localpath), str(remotepath)))

    def close(self):
        return None


class _FakeSSHClient:
    def __init__(self, *, services_dir: str = "/usr/local/lib/python3/dist-packages/core/services"):
        self.commands = []
        self.sftp = _FakeSFTP()
        self.services_dir = services_dir

    def open_sftp(self):
        return self.sftp

    def exec_command(self, cmd, timeout=None, get_pty=None):
        self.commands.append(str(cmd))

        stdin = _FakeStdin()
        stdout_data = b""
        stderr_data = b""

        if "import os, core.services" in cmd:
            stdout_data = (self.services_dir + "\n").encode("utf-8")
        elif "::SERVICESCHECK::" in cmd or "SERVICESCHECK" in cmd:
            # Simulate successful discovery/scan on the remote VM.
            payload = {
                "custom_modules": ["TrafficService", "Segmentation", "DockerComposeService"],
                "module_service_names": {
                    "TrafficService": ["Traffic"],
                    "Segmentation": ["Segmentation"],
                    "DockerComposeService": ["DockerCompose"],
                },
                "custom_service_names": ["DockerCompose", "Segmentation", "Traffic"],
                "missing_modules": [],
                "modules_without_services": [],
                "all_service_names_count": 123,
                "custom_names_missing_from_scan": [],
            }
            stdout_data = ("::SERVICESCHECK::" + __import__("json").dumps(payload) + "\n").encode("utf-8")
        else:
            stdout_data = b""

        return stdin, _FakeStream(stdout_data, 0), _FakeStream(stderr_data, 0)


def test_install_custom_services_to_core_vm_copies_and_verifies(tmp_path, monkeypatch):
    # Provide temp custom services so the test does not depend on repo files.
    files = []
    for name in ("TrafficService.py", "Segmentation.py", "DockerComposeService.py"):
        p = tmp_path / name
        p.write_text("# test service\n")
        files.append(str(p))

    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: files)

    client = _FakeSSHClient()
    meta = backend._install_custom_services_to_core_vm(
        client,
        sudo_password="pw",
        logger=types.SimpleNamespace(info=lambda *_a, **_k: None),
    )

    assert meta["services_dir"] == client.services_dir
    assert set(meta["modules"]) == {"DockerComposeService", "Segmentation", "TrafficService"}
    assert set(meta.get("service_names") or []) == {"DockerCompose", "Segmentation", "Traffic"}

    # Uploaded all .py files into /tmp/coretg_custom_services.
    remote_targets = [dst for _src, dst in client.sftp.put_calls]
    assert all(dst.startswith("/tmp/coretg_custom_services/") for dst in remote_targets)
    assert {dst.split("/")[-1] for dst in remote_targets} == {"TrafficService.py", "Segmentation.py", "DockerComposeService.py"}

    # Ran install + restart + import verification.
    assert any("install -m 0644" in cmd for cmd in client.commands)
    assert any("systemctl restart core-daemon" in cmd for cmd in client.commands)
    assert any("SERVICESCHECK" in cmd for cmd in client.commands)


def test_install_custom_services_requires_sudo_password(tmp_path, monkeypatch):
    p = tmp_path / "TrafficService.py"
    p.write_text("# test\n")
    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: [str(p)])

    client = _FakeSSHClient()
    with pytest.raises(RuntimeError) as exc:
        backend._install_custom_services_to_core_vm(
            client,
            sudo_password=None,
            logger=types.SimpleNamespace(info=lambda *_a, **_k: None),
        )
    assert "requires sudo" in str(exc.value).lower()

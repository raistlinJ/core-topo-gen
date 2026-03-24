from __future__ import annotations

import contextlib

from webapp import app_backend as backend


def test_remote_core_target_host_rewrites_same_machine_public_host_to_loopback():
    assert backend._remote_core_target_host(
        {
            'host': '129.108.4.37',
            'port': 50051,
            'ssh_host': '129.108.4.37',
            'ssh_port': 10000,
            'ssh_username': 'corevm',
            'ssh_password': 'pw',
        }
    ) == '127.0.0.1'


def test_remote_core_target_host_preserves_distinct_grpc_host():
    assert backend._remote_core_target_host(
        {
            'host': '10.10.10.20',
            'port': 50051,
            'ssh_host': '129.108.4.37',
            'ssh_port': 10000,
            'ssh_username': 'corevm',
            'ssh_password': 'pw',
        }
    ) == '10.10.10.20'


def test_grpc_save_current_session_xml_falls_back_to_remote_python(tmp_path, monkeypatch):
    @contextlib.contextmanager
    def _broken_core_connection(_cfg):
        raise RuntimeError("local grpc failed")
        yield

    downloaded = {}
    removed = []

    monkeypatch.setattr(backend, "_core_connection", _broken_core_connection)
    monkeypatch.setattr(backend, "_require_core_ssh_credentials", lambda cfg: cfg)

    def _fake_run_remote_python_json(core_cfg, script, logger=None, label=None, command_desc=None, timeout=None):
        assert label == "core.save_xml"
        assert "save_xml" in str(command_desc or "")
        return {
            "session_id": "1",
            "output_path": "/tmp/core-topo-gen/core-post/session-1.xml",
        }

    monkeypatch.setattr(backend, "_run_remote_python_json", _fake_run_remote_python_json)

    def _fake_download(core_cfg, remote_path, local_path):
        downloaded["remote_path"] = remote_path
        downloaded["local_path"] = local_path
        with open(local_path, "w", encoding="utf-8") as handle:
            handle.write("<scenario />\n")

    monkeypatch.setattr(backend, "_download_remote_file", _fake_download)
    monkeypatch.setattr(backend, "_remove_remote_file", lambda core_cfg, remote_path: removed.append(remote_path))

    out = backend._grpc_save_current_session_xml_with_config(
        {
            "host": "localhost",
            "port": 50051,
            "ssh_host": "core-vm",
            "ssh_port": 22,
            "ssh_username": "core",
            "ssh_password": "pw",
        },
        str(tmp_path),
        session_id="1",
    )

    assert out == str(tmp_path / "session-1.xml")
    assert downloaded["remote_path"] == "/tmp/core-topo-gen/core-post/session-1.xml"
    assert downloaded["local_path"] == str(tmp_path / "session-1.xml")
    assert removed == ["/tmp/core-topo-gen/core-post/session-1.xml"]


def test_grpc_save_current_session_xml_reraises_when_fallback_unavailable(tmp_path, monkeypatch):
    @contextlib.contextmanager
    def _broken_core_connection(_cfg):
        raise RuntimeError("local grpc failed")
        yield

    monkeypatch.setattr(backend, "_core_connection", _broken_core_connection)
    monkeypatch.setattr(backend, "_require_core_ssh_credentials", lambda cfg: (_ for _ in ()).throw(RuntimeError("missing ssh")))

    try:
        backend._grpc_save_current_session_xml_with_config({"host": "localhost", "port": 50051}, str(tmp_path), session_id="1")
        assert False, "expected helper to re-raise original exception"
    except RuntimeError as exc:
        assert str(exc) == "local grpc failed"
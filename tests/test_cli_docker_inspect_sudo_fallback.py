import types

import core_topo_gen.cli as cli


class _Proc:
    def __init__(self, returncode: int, stdout: str):
        self.returncode = returncode
        self.stdout = stdout


def test_docker_container_state_retries_with_sudo_on_permission_denied(monkeypatch):
    calls = []

    def which(name: str):
        if name in ("docker", "sudo"):
            return f"/usr/bin/{name}"
        return None

    def run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        calls.append({"args": list(args), "input": input})
        # First attempt: plain docker inspect fails with permission denied.
        if args[:2] == ["docker", "inspect"]:
            return _Proc(1, "Got permission denied while trying to connect to the Docker daemon socket")
        # Second attempt: sudo docker inspect succeeds.
        if args[:4] == ["sudo", "-n", "docker", "inspect"]:
            return _Proc(0, '{"Running": true, "Status": "running", "ExitCode": 0}')
        raise AssertionError(f"unexpected args: {args}")

    monkeypatch.setenv("CORETG_DOCKER_USE_SUDO", "0")
    monkeypatch.delenv("CORETG_DOCKER_SUDO_PASSWORD", raising=False)
    monkeypatch.setattr(cli.shutil, "which", which)
    monkeypatch.setattr(cli.subprocess, "run", run)

    st = cli._docker_container_state("docker-1")
    assert st["exists"] is True
    assert st["running"] is True
    # Ensure we attempted plain docker first, then sudo -n.
    assert calls[0]["args"][:2] == ["docker", "inspect"]
    assert calls[1]["args"][:4] == ["sudo", "-n", "docker", "inspect"]

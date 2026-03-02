import types


def test_images_pulled_for_compose_ignores_compose_warning_lines(monkeypatch):
    from core_topo_gen.utils import vuln_process

    calls = []

    def fake_run(cmd, stdout=None, stderr=None, text=None):
        calls.append(list(cmd))
        if cmd[:6] == ['docker', 'compose', '-f', '/tmp/docker-compose.yml', 'config', '--images']:
            return types.SimpleNamespace(
                returncode=0,
                stdout='time="2026-03-01T20:00:55-07:00" level=warning msg="The "RPCBIND_PID" variable is not set. Defaulting to a blank string."\nubuntu:22.04\n',
            )
        if cmd[:3] == ['docker', 'image', 'inspect']:
            image = cmd[3]
            if image == 'ubuntu:22.04':
                return types.SimpleNamespace(returncode=0)
            return types.SimpleNamespace(returncode=1)
        return types.SimpleNamespace(returncode=1, stdout='')

    monkeypatch.setattr(vuln_process, 'os', vuln_process.os)
    monkeypatch.setattr(vuln_process, 're', vuln_process.re)

    import shutil
    import subprocess

    monkeypatch.setattr(shutil, 'which', lambda _name: '/usr/bin/docker')
    monkeypatch.setattr(subprocess, 'run', fake_run)

    assert vuln_process._images_pulled_for_compose('/tmp/docker-compose.yml') is True
    inspect_calls = [c for c in calls if c[:3] == ['docker', 'image', 'inspect']]
    assert inspect_calls == [['docker', 'image', 'inspect', 'ubuntu:22.04']]

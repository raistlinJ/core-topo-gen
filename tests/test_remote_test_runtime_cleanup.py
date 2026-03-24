from webapp import app_backend as backend


def test_cleanup_remote_test_runtime_removes_container_images(monkeypatch, tmp_path):
    log_path = tmp_path / 'cleanup.log'
    calls = []

    class _DummyClient:
        def close(self):
            return None

    def fake_open_ssh_client(core_cfg):
        assert core_cfg['ssh_host'] == 'core-vm'
        return _DummyClient()

    def fake_exec_ssh_sudo_command(client, command, *, password, timeout):
        calls.append(command)
        if command.startswith("docker inspect -f '{{.Image}}' docker-5"):
            return 0, 'sha256:testimage\n', ''
        return 0, '', ''

    monkeypatch.setattr(backend, '_open_ssh_client', fake_open_ssh_client)
    monkeypatch.setattr(backend, '_exec_ssh_sudo_command', fake_exec_ssh_sudo_command)
    monkeypatch.setattr(backend, '_list_active_core_sessions', lambda *args, **kwargs: [])

    backend._cleanup_remote_test_runtime({
        'core_cfg': {
            'host': 'core-vm',
            'port': 50051,
            'ssh_host': 'core-vm',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'secret',
        },
        'log_path': str(log_path),
        'test_docker_node_id': '5',
        'test_docker_node_name': 'docker-5',
    })

    assert any(cmd.startswith("docker inspect -f '{{.Image}}' docker-5") for cmd in calls)
    assert any(cmd == 'docker rm -f docker-5 >/dev/null 2>&1 || true' for cmd in calls)
    assert any(cmd == 'docker rmi -f sha256:testimage >/dev/null 2>&1 || true' for cmd in calls)
    assert any(cmd == 'docker container prune -f' for cmd in calls)
    assert any(cmd == 'docker image prune -f' for cmd in calls)
    assert any(cmd == 'docker network prune -f' for cmd in calls)
    assert any(cmd == 'docker system prune -af --volumes' for cmd in calls)
    assert any("grep '_wrapper'" in cmd for cmd in calls)
    log_text = log_path.read_text(encoding='utf-8')
    assert 'deep cleanup start: docker system prune -af --volumes' in log_text
    assert 'deep cleanup complete: docker system prune -af --volumes rc=0' in log_text


def test_cleanup_remote_workspace_runs_shared_remote_cleanup(monkeypatch):
    removed = []
    cleanup_calls = []

    class _DummyClient:
        def close(self):
            return None

    monkeypatch.setattr(backend, '_open_ssh_client', lambda *_a, **_k: _DummyClient())
    monkeypatch.setattr(backend, '_remote_remove_path', lambda _client, path: removed.append(path))
    monkeypatch.setattr(backend, '_run_postrun_remote_maintenance', lambda meta, _client=None: cleanup_calls.append(dict(meta)))

    meta = {
        'remote': True,
        'remote_run_dir': '/tmp/coretg/run-123',
        'core_cfg': {'ssh_host': 'core-vm', 'ssh_username': 'core', 'ssh_password': 'secret'},
    }

    backend._cleanup_remote_workspace(meta)

    assert removed == ['/tmp/coretg/run-123']
    assert len(cleanup_calls) == 1
    assert meta.get('remote_workspace_cleaned') is True


def test_remote_docker_remove_all_containers_script_removes_images():
    script = backend._remote_docker_remove_all_containers_script('secret')

    assert "['inspect', '-f', '{{.Image}}', cid]" in script
    assert "['image', 'rm', '-f'] + list(chunk)" in script
    assert "'removed_attempted': images_removed_attempted" in script
    assert "'skipped': False" in script

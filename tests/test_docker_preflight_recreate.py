from pathlib import Path

import core_topo_gen.builders.topology as topo


class _Proc:
    def __init__(self, returncode: int, stdout: str = ''):
        self.returncode = returncode
        self.stdout = stdout


def test_docker_compose_preflight_force_recreates_stale_restarting_container(tmp_path, monkeypatch):
    compose_path = tmp_path / 'docker-compose.yml'
    compose_path.write_text(
        'services:\n'
        '  docker-3:\n'
        '    image: alpine:3.20\n'
        '    container_name: docker-3\n',
        encoding='utf-8',
    )

    calls = []
    inspect_calls = {'count': 0}

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        calls.append(argv)

        if argv[:3] == ['docker', 'compose', '-p']:
            if argv[-1:] == ['build']:
                return _Proc(0, '')
            if 'pull' in argv:
                return _Proc(0, '')
            if argv[-2:] == ['up', '--no-start']:
                return _Proc(0, '')
            if argv[-4:] == ['up', '-d', '--no-build', 'docker-3']:
                return _Proc(0, '')
            if argv[-5:] == ['up', '-d', '--force-recreate', '--no-build', 'docker-3']:
                return _Proc(0, '')
            if argv[-4:] == ['rm', '-f', '-s', 'docker-3']:
                return _Proc(0, '')
        if argv[:3] == ['docker', 'inspect', '--format']:
            fmt = argv[3]
            if fmt == '{{.State.Pid}} {{.State.Status}}':
                inspect_calls['count'] += 1
                if inspect_calls['count'] <= 5:
                    return _Proc(0, '0 restarting')
                return _Proc(0, '123 running')
            if fmt == '{{json .State}}':
                return _Proc(0, '{"Status":"running","Pid":123}')
        if argv[:3] == ['docker', 'rm', '-f']:
            return _Proc(0, '')
        raise AssertionError(f'unexpected args: {argv}')

    monkeypatch.setattr(topo, '_docker_compose_cmd', lambda: ['docker', 'compose'])
    monkeypatch.setattr(topo, '_docker_cmd', lambda: ['docker'])
    monkeypatch.setattr(topo.subprocess, 'run', fake_run)
    monkeypatch.setattr(topo.time, 'sleep', lambda _s: None)
    monkeypatch.setenv('CORETG_DOCKER_PREFLIGHT_WAIT_SECONDS', '1')
    monkeypatch.setenv('CORETG_DOCKER_PREFLIGHT_POLL_SECONDS', '1')
    topo._PREFLIGHTED_DOCKER_NODE_COMPOSES.discard(str(Path(compose_path).resolve()))

    topo._docker_compose_preflight(str(compose_path), node_name='docker-3')

    assert ['docker', 'rm', '-f', 'docker-3'] in calls
    assert ['docker', 'compose', '-p', 'docker-3conf', '-f', str(compose_path), 'up', '-d', '--force-recreate', '--no-build', 'docker-3'] in calls
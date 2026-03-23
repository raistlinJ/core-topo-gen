import io
from pathlib import Path

from webapp import app_backend as backend


class _FakeSFTP:
    def __init__(self, existing_paths):
        self._existing_paths = set(existing_paths)
        self.put_calls = []
        self.uploaded_bytes = {}

    def put(self, localpath, remotepath):
        local_path = Path(localpath)
        remote_path = str(remotepath)
        self.put_calls.append((str(local_path), remote_path))
        self.uploaded_bytes[remote_path] = local_path.read_bytes()

    def stat(self, path):
        if str(path) not in self._existing_paths:
            raise FileNotFoundError(str(path))
        return object()

    def close(self):
        return None


class _FakeSSHClient:
    def __init__(self, sftp):
        self._sftp = sftp

    def open_sftp(self):
        return self._sftp


def test_prepare_remote_cli_context_keeps_rewritten_xml_when_preview_matches_xml(tmp_path, monkeypatch):
    wrapper_dir = tmp_path / 'docker-wrap-vuln-test-1-vuln-test-1'
    wrapper_dir.mkdir()
    (wrapper_dir / 'Dockerfile').write_text('FROM alpine:3.19\n', encoding='utf-8')

    compose_path = tmp_path / 'docker-compose-docker-1.yml'
    compose_path.write_text(
        '\n'.join(
            [
                'services:',
                '  app:',
                '    image: coretg/vuln-test-1-vuln-test-1:iproute2',
                '    labels:',
                f'      coretg.wrapper_build_context: {wrapper_dir}',
                '      coretg.wrapper_build_dockerfile: Dockerfile',
            ]
        )
        + '\n',
        encoding='utf-8',
    )

    xml_path = tmp_path / 'ephemeral.xml'
    xml_path.write_text(
        '\n'.join(
            [
                '<?xml version="1.0" encoding="utf-8"?>',
                '<Scenarios>',
                '  <Scenario name="demo">',
                '    <ScenarioEditor>',
                '      <Section name="Vulnerabilities">',
                f'        <item v_path="{compose_path}" />',
                '      </Section>',
                '    </ScenarioEditor>',
                '  </Scenario>',
                '</Scenarios>',
            ]
        ),
        encoding='utf-8',
    )

    remote_repo = '/remote/repo'
    fake_sftp = _FakeSFTP(
        {
            remote_repo,
            f'{remote_repo}/core_topo_gen',
            f'{remote_repo}/core_topo_gen/__init__.py',
        }
    )
    client = _FakeSSHClient(fake_sftp)

    monkeypatch.setattr(backend, '_remote_base_dir', lambda _sftp: '/remote/base')
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: remote_repo)
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_upload_flow_artifacts_for_plan_to_remote', lambda **_kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path / 'empty-repo'))

    log_handle = io.StringIO()

    context = backend._prepare_remote_cli_context(
        client=client,
        run_id='run-123',
        xml_path=str(xml_path),
        preview_plan_path=str(xml_path),
        log_handle=log_handle,
    )

    remote_xml_path = context['xml_path']
    assert context['preview_plan_path'] == remote_xml_path

    uploaded_xml = fake_sftp.uploaded_bytes[remote_xml_path].decode('utf-8')
    assert str(compose_path) not in uploaded_xml
    assert '/remote/base/runs/run-123/docker-compose-docker-1.yml' in uploaded_xml

    remote_compose_path = '/remote/base/runs/run-123/docker-compose-docker-1.yml'
    uploaded_compose = fake_sftp.uploaded_bytes[remote_compose_path].decode('utf-8')
    assert str(wrapper_dir) not in uploaded_compose
    assert '/remote/base/runs/run-123/docker-wrap-vuln-test-1-vuln-test-1' in uploaded_compose

    remote_wrapper_dockerfile = '/remote/base/runs/run-123/docker-wrap-vuln-test-1-vuln-test-1/Dockerfile'
    assert fake_sftp.uploaded_bytes[remote_wrapper_dockerfile].decode('utf-8') == 'FROM alpine:3.19\n'

    xml_upload_count = sum(1 for _local, remote in fake_sftp.put_calls if remote == remote_xml_path)
    assert xml_upload_count == 1

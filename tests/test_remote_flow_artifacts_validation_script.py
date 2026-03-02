import io
import json
import shutil
from contextlib import redirect_stdout
from pathlib import Path

from webapp import app_backend as backend


def _run_validation_script(assignments):
    script = backend._remote_flow_artifacts_validation_script(assignments, scenario_label='LiveTopologySmoke')
    ns = {'__name__': '__main__'}
    out = io.StringIO()
    with redirect_stdout(out):
        exec(script, ns, ns)
    payload = json.loads(out.getvalue().strip())
    return payload


def test_remote_validator_resolves_relative_outputs_in_artifacts_and_outputs_dirs(tmp_path):
    run_dir = tmp_path / 'flow-run'
    artifacts_dir = run_dir / 'artifacts'
    outputs_dir = run_dir / 'outputs'
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    secret_path = artifacts_dir / 'secrets.txt'
    secret_path.write_text('demo-secret', encoding='utf-8')

    compose_path = outputs_dir / 'docker-compose.yml'
    compose_path.write_text('services: {}\n', encoding='utf-8')

    manifest_flag = run_dir / 'outputs_flag.json'
    manifest_flag.write_text(
        json.dumps({'outputs': {'secret_file': 'secrets.txt'}}),
        encoding='utf-8',
    )

    manifest_node = run_dir / 'outputs_node.json'
    manifest_node.write_text(
        json.dumps({'outputs': {'File(path)': 'docker-compose.yml'}}),
        encoding='utf-8',
    )

    payload = _run_validation_script(
        [
            {
                'node_id': 'docker-34',
                'generator_id': 'textfile_username_password',
                'generator_type': 'flag-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'outputs_manifest': str(manifest_flag),
                'inject_files_detail': [],
                'inject_files': [],
            },
            {
                'node_id': 'docker-31',
                'generator_id': 'nfs_sensitive_file',
                'generator_type': 'flag-node-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'outputs_manifest': str(manifest_node),
                'inject_files_detail': [],
                'inject_files': [],
            },
        ]
    )

    items = payload.get('items') or []
    by_id = {str(it.get('generator_id')): it for it in items if isinstance(it, dict)}

    fg_item = by_id.get('textfile_username_password')
    assert fg_item is not None
    assert fg_item.get('outputs_missing') == []
    assert str(secret_path) in (fg_item.get('outputs_checked') or [])

    node_item = by_id.get('nfs_sensitive_file')
    assert node_item is not None
    assert node_item.get('outputs_missing') == []
    assert str(compose_path) in (node_item.get('outputs_checked') or [])


def test_listener_snapshot_script_includes_tcp_udp_and_ss_checks():
    script = backend._remote_docker_exec_listener_snapshot_script(
        containers=['docker-40'],
        sudo_password='pw',
    )

    assert '/proc/net/tcp' in script
    assert '/proc/net/tcp6' in script
    assert '/proc/net/udp' in script
    assert '/proc/net/udp6' in script
    assert 'ss -lntu' in script
    assert 'docker-40' in script


def test_remote_validator_prefers_resolved_inject_sources_and_skips_legacy_tmp_flag_txt(tmp_path):
    run_dir = tmp_path / 'flow-run'
    run_dir.mkdir(parents=True, exist_ok=True)
    real_inject = run_dir / 'flag.txt'
    real_inject.write_text('FLAG{demo}', encoding='utf-8')

    payload = _run_validation_script(
        [
            {
                'node_id': 'docker-1',
                'generator_id': 'textfile_username_password',
                'generator_type': 'flag-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                # Legacy/stale path that should not be treated as required host source.
                'inject_files': ['/tmp/flag.txt'],
                # Authoritative generation-time resolved source should be used.
                'resolved_paths': {
                    'inject_sources': [
                        {'path': str(real_inject), 'is_remote': True},
                    ]
                },
            }
        ]
    )

    items = payload.get('items') or []
    assert len(items) == 1
    item = items[0]

    assert item.get('inject_missing') == []
    checked = item.get('inject_checked') or []
    assert (str(real_inject) in checked) or (checked == [])
    assert '/tmp/flag.txt' not in (item.get('inject_missing') or [])


def test_remote_validator_skips_legacy_tmp_flag_when_resolved_source_is_run_dir_flag_missing(tmp_path):
    run_dir = tmp_path / 'flow-run'
    run_dir.mkdir(parents=True, exist_ok=True)
    compose_file = run_dir / 'artifacts' / 'docker-compose.yml'
    compose_file.parent.mkdir(parents=True, exist_ok=True)
    compose_file.write_text('services: {}\n', encoding='utf-8')

    payload = _run_validation_script(
        [
            {
                'node_id': 'docker-2',
                'generator_id': 'binary_embed_text',
                'generator_type': 'flag-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'inject_files': ['/tmp/flag.txt'],
                'resolved_paths': {
                    'inject_sources': [
                        {'path': str(compose_file), 'is_remote': True},
                        {'path': str(run_dir / 'flag.txt'), 'is_remote': True},
                    ]
                },
            }
        ]
    )

    items = payload.get('items') or []
    assert len(items) == 1
    item = items[0]
    missing = item.get('inject_missing') or []
    checked = item.get('inject_checked') or []

    assert str(compose_file) in checked
    assert str(run_dir / 'flag.txt') not in missing


def test_remote_validator_sample_preset_mirrored_generators_respect_delivery_contract(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]

    mirror_specs = [
        (
            'binary_embed_text',
            'flag-generator',
            repo_root / 'flag_generators' / 'py_sample_binary_embed_text',
        ),
        (
            'nfs_sensitive_file',
            'flag-node-generator',
            repo_root / 'flag_node_generators' / 'py_sample_nfs_sensitive_file',
        ),
        (
            'textfile_username_password',
            'flag-generator',
            repo_root / 'flag_generators' / 'py_sample_textfile_username_password',
        ),
    ]

    assignments = []
    for generator_id, generator_type, source_dir in mirror_specs:
        mirror_dir = tmp_path / f'mirror_{generator_id}'
        shutil.copytree(source_dir, mirror_dir)

        run_dir = mirror_dir / 'run'
        artifacts_dir = run_dir / 'artifacts'
        outputs_dir = run_dir / 'outputs'
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        outputs_dir.mkdir(parents=True, exist_ok=True)

        outputs_payload = {'outputs': {}}
        inject_files = []

        if generator_id == 'binary_embed_text':
            (artifacts_dir / 'payload.bin').write_bytes(b'ELFMOCK')
            outputs_payload['outputs'] = {
                'FlagDelivery(mode)': 'embedded',
                'Binary(path)': 'payload.bin',
            }
            inject_files = ['/tmp/flag.txt']
        elif generator_id == 'nfs_sensitive_file':
            (outputs_dir / 'docker-compose.yml').write_text('services: {}\n', encoding='utf-8')
            (artifacts_dir / 'exports').mkdir(parents=True, exist_ok=True)
            (artifacts_dir / 'exports' / 'flag.txt').write_text('FLAG{nfs}\n', encoding='utf-8')
            outputs_payload['outputs'] = {
                'FlagDelivery(mode)': 'file',
                'FlagFile(path)': 'exports/flag.txt',
                'File(path)': 'docker-compose.yml',
            }
            inject_files = ['exports/flag.txt->/flow_injects']
        else:
            (artifacts_dir / 'flag.txt').write_text('FLAG{text}\n', encoding='utf-8')
            outputs_payload['outputs'] = {
                'FlagDelivery(mode)': 'file',
                'FlagFile(path)': 'flag.txt',
                'Secret(path)': 'flag.txt',
            }
            inject_files = ['flag.txt->/flow_injects']

        outputs_manifest = run_dir / 'outputs.json'
        outputs_manifest.write_text(json.dumps(outputs_payload), encoding='utf-8')

        assignments.append(
            {
                'node_id': f'docker-{len(assignments) + 1}',
                'generator_id': generator_id,
                'generator_type': generator_type,
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'inject_source_dir': str(artifacts_dir),
                'outputs_manifest': str(outputs_manifest),
                'inject_files': inject_files,
            }
        )

    payload = _run_validation_script(assignments)
    assert payload.get('ok') is True

    items = payload.get('items') or []
    by_id = {str(item.get('generator_id')): item for item in items if isinstance(item, dict)}

    embed_item = by_id.get('binary_embed_text')
    assert embed_item is not None
    assert embed_item.get('flag_delivery_mode') == 'embedded'
    assert embed_item.get('flag_file_path') in ('', None)
    assert embed_item.get('outputs_missing') == []
    assert embed_item.get('inject_missing') == []

    nfs_item = by_id.get('nfs_sensitive_file')
    assert nfs_item is not None
    assert nfs_item.get('flag_delivery_mode') == 'file'
    assert str(nfs_item.get('flag_file_path') or '').endswith('/exports/flag.txt')
    assert nfs_item.get('outputs_missing') == []
    assert nfs_item.get('inject_missing') == []

    text_item = by_id.get('textfile_username_password')
    assert text_item is not None
    assert text_item.get('flag_delivery_mode') == 'file'
    assert str(text_item.get('flag_file_path') or '').endswith('/flag.txt')
    assert text_item.get('outputs_missing') == []
    assert text_item.get('inject_missing') == []

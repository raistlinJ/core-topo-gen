import io
import json
from contextlib import redirect_stdout

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

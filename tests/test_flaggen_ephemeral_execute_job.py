import json
import os

from webapp import app_backend


def test_flaggen_build_ephemeral_execute_job_builds_flow_and_job_spec(tmp_path, monkeypatch):
    run_dir = tmp_path / 'run'
    run_dir.mkdir(parents=True, exist_ok=True)

    artifact_file = run_dir / 'artifact.txt'
    artifact_file.write_text('hello', encoding='utf-8')

    outputs = {
        'outputs': {
            'Flag(flag_id)': 'FLAG{demo}',
            'File(path)': 'artifact.txt',
        }
    }
    (run_dir / 'outputs.json').write_text(json.dumps(outputs), encoding='utf-8')

    captured = {}

    monkeypatch.setattr(
        app_backend,
        '_planner_persist_flow_plan',
        lambda **kwargs: {
            'xml_path': kwargs.get('xml_path'),
            'preview_plan_path': kwargs.get('xml_path'),
            'scenario': kwargs.get('scenario'),
            'full_preview': {},
        },
    )
    monkeypatch.setattr(
        app_backend,
        '_load_preview_payload_from_path',
        lambda _path, _scenario=None: {
            'full_preview': {
                'hosts': [
                    {'node_id': 'd1', 'name': 'docker-1', 'role': 'Docker'}
                ]
            }
        },
    )

    def _fake_update_flow(xml_path, scenario_label, flow_state):
        captured['xml_path'] = xml_path
        captured['scenario'] = scenario_label
        captured['flow_state'] = flow_state
        return True, ''

    monkeypatch.setattr(app_backend, '_update_flow_state_in_xml', _fake_update_flow)

    meta = {
        'run_dir': str(run_dir),
        'generator_id': 'binary_embed_text',
        'generator_name': 'Binary Embed Text',
        'core_cfg': {'ssh_host': '127.0.0.1', 'ssh_username': 'u', 'ssh_password': 'p', 'host': '127.0.0.1', 'port': 50051},
    }

    job_spec, err = app_backend._flaggen_build_ephemeral_execute_job(meta, run_id='abc123')

    assert err is None
    assert isinstance(job_spec, dict)
    assert os.path.exists(job_spec['xml_path'])
    assert job_spec['preview_plan_path'] == job_spec['xml_path']
    assert job_spec['flow_enabled'] is True

    flow_state = captured.get('flow_state') or {}
    assert flow_state.get('flow_enabled') is True
    assignments = flow_state.get('flag_assignments') or []
    assert len(assignments) == 1
    assignment = assignments[0]
    assert assignment.get('type') == 'flag-generator'
    assert assignment.get('id') == 'binary_embed_text'
    assert assignment.get('node_id') == 'd1'
    assert assignment.get('flag_value') == 'FLAG{demo}'

    injects = assignment.get('inject_files') or []
    assert any(os.path.abspath(str(artifact_file)) == str(p) for p in injects)

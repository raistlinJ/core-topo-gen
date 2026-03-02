import json
import os
import shutil
import tempfile
import uuid

from webapp import app_backend
from webapp.app_backend import app


def _login(client) -> None:
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def _write_min_xml(tmpdir: str, *, scenario: str) -> str:
    xml = f"""<Scenarios>
  <Scenario name='{scenario}'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' v_metric='Count' v_count='1'/>
      </section>
      <section name='Routing' density='0.0'></section>
      <section name='Services' density='0.0'></section>
      <section name='Vulnerabilities' density='0.0'></section>
      <section name='Segmentation' density='0.0'></section>
      <section name='Traffic' density='0.0'></section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    xml_path = os.path.join(tmpdir, f"{scenario}.xml")
    with open(xml_path, 'w', encoding='utf-8') as fh:
        fh.write(xml)
    return xml_path


def test_generator_test_traverses_basic_switch_plus_docker_scenario(monkeypatch):
    """End-to-end regression for generator Test flow.

    Covers the full path for a minimal scenario:
    1) Create scenario preview from XML.
    2) Persist a basic switch+docker topology in preview metadata.
    3) Compute and save flow state with a generator assignment.
    4) Prepare preview for execute (which invokes generator runner).
    5) Ensure generated artifacts are cleaned up when requested.
    """

    app.config['TESTING'] = True
    client = app.test_client()
    _login(client)

    scenario = f"zz-gen-test-flow-{uuid.uuid4().hex[:8]}"
    tmpdir = tempfile.mkdtemp(prefix='coretg-gen-flow-')

    fake_flag_generator = {
        'id': 'binary_embed_text',
        'name': 'Binary Embed Text',
        'language': 'python',
        'inputs': [],
        'outputs': [{'name': 'File(path)'}],
        'hint_templates': ['Copy from {{node_id}}'],
        '_source_name': 'test-fixture',
    }

    try:
        xml_path = _write_min_xml(tmpdir, scenario=scenario)

        preview_resp = client.post('/api/plan/preview_full', json={'xml_path': xml_path, 'scenario': scenario})
        assert preview_resp.status_code == 200
        preview_payload = preview_resp.get_json() or {}
        assert preview_payload.get('ok') is True, preview_payload

        full_preview = preview_payload.get('full_preview') or {}
        hosts = full_preview.get('hosts') or []
        docker_hosts = [h for h in hosts if str((h or {}).get('role') or '').strip().lower() == 'docker']
        assert len(docker_hosts) == 1, docker_hosts

        docker_node_id = str((docker_hosts[0] or {}).get('node_id') or '')
        assert docker_node_id
        docker_hosts[0]['is_vuln'] = True
        docker_hosts[0]['vulnerabilities'] = [{'id': 'CVE-TEST-0001'}]

        full_preview['switches'] = [{'node_id': 's1', 'name': 'switch-1'}]
        full_preview['switches_detail'] = [{'switch_id': 's1', 'router_id': '', 'hosts': [docker_node_id]}]

        ok, err = app_backend._update_plan_preview_in_xml(
            xml_path,
            scenario,
            {
                'full_preview': full_preview,
                'metadata': {
                    'xml_path': xml_path,
                    'scenario': scenario,
                    'seed': full_preview.get('seed'),
                },
            },
        )
        assert ok, err

        monkeypatch.setattr(app_backend, '_flag_generators_from_enabled_sources', lambda: ([fake_flag_generator], []))
        monkeypatch.setattr(app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))
        monkeypatch.setattr(app_backend, '_flow_enabled_plugin_contracts_by_id', lambda: {})
        monkeypatch.setattr(app_backend, '_flow_validate_chain_order_by_requires_produces', lambda *a, **k: (True, []))

        def _fake_subprocess_run(cmd, cwd=None, check=False, capture_output=False, text=False, timeout=None, env=None):
            out_dir = ''
            if isinstance(cmd, list) and '--out-dir' in cmd:
                idx = cmd.index('--out-dir')
                if idx + 1 < len(cmd):
                    out_dir = str(cmd[idx + 1])

            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
                compose_path = os.path.join(out_dir, 'docker-compose.yml')
                with open(compose_path, 'w', encoding='utf-8') as fh:
                    fh.write("version: '3.8'\nservices:\n  app:\n    image: alpine:latest\n")
                with open(os.path.join(out_dir, 'outputs.json'), 'w', encoding='utf-8') as fh:
                    json.dump({'outputs': {'File(path)': 'docker-compose.yml'}}, fh)

            class _Result:
                def __init__(self):
                    self.returncode = 0
                    self.stdout = ''
                    self.stderr = ''

            return _Result()

        monkeypatch.setattr(app_backend.subprocess, 'run', _fake_subprocess_run)

        prepare_resp = client.post(
            '/api/flag-sequencing/prepare_preview_for_execute',
            json={
                'scenario': scenario,
                'preview_plan': xml_path,
                'length': 1,
                'chain_ids': [docker_node_id],
                'best_effort': False,
                'cleanup_generated_artifacts': True,
                'timeout_s': 10,
            },
        )
        assert prepare_resp.status_code == 200, prepare_resp.get_json()
        prepare_data = prepare_resp.get_json() or {}
        assert prepare_data.get('ok') is True, prepare_data

        assignments = prepare_data.get('flag_assignments') if isinstance(prepare_data.get('flag_assignments'), list) else []
        assert len(assignments) == 1, assignments

        assignment = assignments[0]
        assert str(assignment.get('type') or '') == 'flag-generator'
        assert str(assignment.get('id') or '') == 'binary_embed_text'
        assert str(assignment.get('node_id') or '') == docker_node_id

        created_run_dirs = [str(p) for p in (prepare_data.get('created_run_dirs') or []) if str(p).strip()]
        assert created_run_dirs, prepare_data
        assert prepare_data.get('cleanup_generated_artifacts') is True
        for path in created_run_dirs:
            assert not os.path.exists(path), path

        save_resp = client.post(
            '/api/flag-sequencing/save_flow_state_to_xml',
            json={
                'xml_path': xml_path,
                'scenario': scenario,
                'flow_state': {
                    'scenario': scenario,
                    'length': 1,
                    'chain': [{'id': docker_node_id}],
                    'flag_assignments': assignments,
                    'flow_enabled': True,
                },
            },
        )
        assert save_resp.status_code == 200, save_resp.get_json()
        save_data = save_resp.get_json() or {}
        assert save_data.get('ok') is True, save_data

        flow_resp = client.get(
            '/api/flag-sequencing/attackflow_preview',
            query_string={
                'scenario': scenario,
                'length': 1,
                'preview_plan': xml_path,
            },
        )
        assert flow_resp.status_code == 200, flow_resp.get_json()
        flow_data = flow_resp.get_json() or {}
        assert flow_data.get('ok') is True, flow_data
        flow_assignments = flow_data.get('flag_assignments') if isinstance(flow_data.get('flag_assignments'), list) else []
        assert len(flow_assignments) >= 1
        assert str((flow_assignments[0] or {}).get('node_id') or '') == docker_node_id
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

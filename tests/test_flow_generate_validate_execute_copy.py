import json
import os
import shutil
import tempfile
import uuid

from webapp.app_backend import app
from webapp import app_backend as backend


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def _seed_xml_plan(scenario: str, full_preview: dict, flow_meta: dict) -> tuple[str, str]:
    tmp_dir = tempfile.mkdtemp(prefix='coretg-flow-gve-')
    xml_path = os.path.join(tmp_dir, f'{scenario}.xml')
    xml = f"""<Scenarios>
  <Scenario name=\"{scenario}\">
    <ScenarioEditor>
      <section name=\"Node Information\">
        <item selected=\"Docker\" v_metric=\"Count\" v_count=\"2\"/>
      </section>
      <section name=\"Routing\" density=\"0.0\"></section>
      <section name=\"Services\" density=\"0.0\"></section>
      <section name=\"Vulnerabilities\" density=\"0.0\"></section>
      <section name=\"Segmentation\" density=\"0.0\"></section>
      <section name=\"Traffic\" density=\"0.0\"></section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    with open(xml_path, 'w', encoding='utf-8') as f:
        f.write(xml)

    payload = {
        'full_preview': full_preview,
        'metadata': {
            'xml_path': xml_path,
            'scenario': scenario,
            'seed': full_preview.get('seed'),
            'flow': flow_meta,
        },
    }
    ok, err = backend._update_plan_preview_in_xml(xml_path, scenario, payload)
    assert ok, err
    ok2, err2 = backend._update_flow_state_in_xml(xml_path, scenario, flow_meta)
    assert ok2, err2
    return xml_path, tmp_dir


class _NoRunThread:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        return None


class _DoneProc:
    def poll(self):
        return 0


def test_generate_validate_execute_flow_copy_for_both_generator_kinds(monkeypatch):
    app.config['TESTING'] = True
    client = app.test_client()
    _login(client)

    scenario = f'zz-gve-copy-{uuid.uuid4().hex[:8]}'
    full_preview = {
        'seed': 77,
        'hosts': [
            {
                'id': 'h1',
                'node_id': 'h1',
                'name': 'h1',
                'role': 'Workstation',
                'type': 'workstation',
                'is_vuln': True,
                'vulnerabilities': ['CVE-TEST-1'],
                'ip4': '10.0.0.11',
            },
            {
                'id': 'h2',
                'node_id': 'h2',
                'name': 'h2',
                'role': 'Docker',
                'type': 'docker',
                'is_vuln': False,
                'vulnerabilities': [],
                'ip4': '10.0.0.12',
            },
        ],
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'host_router_map': {},
        'r2r_links_preview': [],
    }

    flow_meta = {
        'scenario': scenario,
        'length': 2,
    }

    xml_path, tmp_dir = _seed_xml_plan(scenario, full_preview, flow_meta)

    fg_def = {
        'id': 'fg_test',
        'name': 'FG Test',
        'language': 'python',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}, {'name': 'File(path)'}],
        'hint_templates': ['hint'],
        '_source_name': 'test',
    }
    fng_def = {
        'id': 'fng_test',
        'name': 'FNG Test',
        'language': 'python',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}, {'name': 'File(path)'}],
        'hint_templates': ['hint'],
        '_source_name': 'test',
    }

    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([fg_def], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([fng_def], []))
    monkeypatch.setattr(backend, '_flow_enabled_plugin_contracts_by_id', lambda: {})
    monkeypatch.setattr(backend, '_flow_validate_chain_order_by_requires_produces', lambda *a, **k: (True, []))
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *a, **k: {'ssh_enabled': False, 'ssh_password': 'pw'})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_a, **_k: cfg)
    monkeypatch.setattr(backend, '_build_topology_graph_from_preview_plan', lambda _preview: (full_preview['hosts'], [], {}))
    monkeypatch.setattr(backend, '_flow_compose_docker_stats', lambda _nodes: {'docker_nodes': 1, 'vulnerability_nodes': 1})
    monkeypatch.setattr(backend, '_pick_flag_chain_nodes', lambda _nodes, _adj, length=2: full_preview['hosts'][:length])

    def _fake_flow_assignments(_preview, chain_nodes, _scenario, **_kwargs):
        nodes = [n for n in (chain_nodes or []) if isinstance(n, dict)]
        assert len(nodes) >= 2
        return [
            {
                'node_id': str(nodes[0].get('id') or 'h1'),
                'id': 'fg_test',
                'name': 'FG Test',
                'type': 'flag-generator',
                'generator_catalog': 'flag_generators',
                'inject_files': [],
                'outputs': ['Flag(flag_id)', 'File(path)'],
            },
            {
                'node_id': str(nodes[1].get('id') or 'h2'),
                'id': 'fng_test',
                'name': 'FNG Test',
                'type': 'flag-node-generator',
                'generator_catalog': 'flag_node_generators',
                'inject_files': ['File(path)'],
                'outputs': ['Flag(flag_id)', 'File(path)'],
            },
        ]

    monkeypatch.setattr(backend, '_flow_compute_flag_assignments', _fake_flow_assignments)

    generator_calls: list[dict] = []

    def _fake_subprocess_run(cmd, cwd=None, check=False, capture_output=False, text=False, timeout=None, env=None):
        generator_id = ''
        generator_kind = ''
        out_dir = ''
        if isinstance(cmd, list):
            if '--generator-id' in cmd:
                i = cmd.index('--generator-id')
                if i + 1 < len(cmd):
                    generator_id = str(cmd[i + 1])
            if '--kind' in cmd:
                i = cmd.index('--kind')
                if i + 1 < len(cmd):
                    generator_kind = str(cmd[i + 1])
            if '--out-dir' in cmd:
                i = cmd.index('--out-dir')
                if i + 1 < len(cmd):
                    out_dir = str(cmd[i + 1])

        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            art_dir = os.path.join(out_dir, 'artifacts')
            os.makedirs(art_dir, exist_ok=True)
            outputs = {'Flag(flag_id)': f'FLAG{{{generator_id}}}', 'flag': f'FLAG{{{generator_id}}}'}

            if generator_id == 'fg_test':
                export_path = os.path.join(art_dir, 'exports.txt')
                with open(export_path, 'w', encoding='utf-8') as f:
                    f.write('seed-data')
                outputs['File(path)'] = 'artifacts/exports.txt'
            else:
                compose_path = os.path.join(out_dir, 'docker-compose.yml')
                with open(compose_path, 'w', encoding='utf-8') as f:
                    f.write('services: {}\n')
                outputs['File(path)'] = 'docker-compose.yml'

            manifest_path = os.path.join(out_dir, 'outputs.json')
            with open(manifest_path, 'w', encoding='utf-8') as mf:
                json.dump({'outputs': outputs}, mf)

        inject_raw = None
        if isinstance(env, dict):
            inject_raw = env.get('CORETG_INJECT_FILES_JSON')
        inject_files_override = []
        if isinstance(inject_raw, str) and inject_raw.strip():
            try:
                parsed = json.loads(inject_raw)
                if isinstance(parsed, list):
                    inject_files_override = [str(x) for x in parsed]
            except Exception:
                inject_files_override = [inject_raw]

        generator_calls.append({
            'id': generator_id,
            'kind': generator_kind,
            'out_dir': out_dir,
            'inject_files_override': inject_files_override,
        })

        class _Result:
            def __init__(self):
                self.returncode = 0
                self.stdout = ''
                self.stderr = ''

        return _Result()

    monkeypatch.setattr(backend.subprocess, 'run', _fake_subprocess_run)

    captured_revalidate_items = {'items': []}

    def _fake_validation_script(check_items, scenario_label=''):
        captured_revalidate_items['items'] = list(check_items or [])
        return 'print("ok")'

    def _fake_run_remote_python_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'flow.revalidate.artifacts':
            items = []
            for it in captured_revalidate_items['items']:
                out_checked = []
                run_dir = str(it.get('run_dir') or '').strip()
                if run_dir:
                    out_checked.append(run_dir)
                inject_checked = []
                inj = it.get('inject_files') if isinstance(it.get('inject_files'), list) else []
                for raw in inj:
                    src = str(raw).split('->', 1)[0].strip()
                    if src:
                        inject_checked.append(src)
                items.append({
                    'outputs_checked': out_checked,
                    'inject_checked': inject_checked,
                    'outputs_missing': [],
                    'inject_missing': [],
                })
            return {'ok': True, 'items': items}
        if str(label).startswith('docker.copy_flow_artifacts'):
            return {
                'ok': True,
                'assignments_count': 2,
                'assignments_keys': ['h1', 'h2'],
                'items': [
                    {'node': 'h1', 'ok': True, 'src': '/tmp/vulns/flag_generators_runs/x', 'dest': '/flow_artifacts', 'targets': ['h1']},
                    {'node': 'h2', 'ok': True, 'src': '/tmp/vulns/flag_node_generators_runs/x', 'dest': '/flow_artifacts', 'targets': ['h2']},
                ],
            }
        if str(label).startswith('docker.exec.verify_flow_artifacts'):
            return {'ok': True, 'items': []}
        if str(label).startswith('remote.vulns_inventory'):
            return {'ok': True, 'items': []}
        return {'ok': True, 'items': []}

    monkeypatch.setattr(backend, '_remote_flow_artifacts_validation_script', _fake_validation_script)
    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_run_remote_python_json)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: dict(cfg or {}, ssh_enabled=True, ssh_password='pw'))

    try:
        prepare_resp = client.post(
            '/api/flag-sequencing/prepare_preview_for_execute',
            json={
                'scenario': scenario,
                'preview_plan': xml_path,
                'length': 2,
                'best_effort': False,
                'timeout_s': 10,
            },
        )
        assert prepare_resp.status_code == 200, prepare_resp.get_json()
        prepare_data = prepare_resp.get_json() or {}
        assert prepare_data.get('ok') is True

        assignments = prepare_data.get('flag_assignments') if isinstance(prepare_data.get('flag_assignments'), list) else []
        assert len(assignments) == 2
        types = {str(a.get('type') or '') for a in assignments if isinstance(a, dict)}
        assert 'flag-generator' in types
        assert 'flag-node-generator' in types

        second = next(a for a in assignments if str(a.get('id') or '') == 'fng_test')
        second_injects = second.get('inject_files') if isinstance(second.get('inject_files'), list) else []
        assert any(os.path.isabs(str(v).split('->', 1)[0].strip()) for v in second_injects)

        assert any(c.get('id') == 'fg_test' and c.get('kind') == 'flag-generator' for c in generator_calls)
        assert any(c.get('id') == 'fng_test' and c.get('kind') == 'flag-node-generator' for c in generator_calls)
        assert any(
            c.get('id') == 'fng_test'
            and any(os.path.isabs(str(x).split('->', 1)[0].strip()) for x in (c.get('inject_files_override') or []))
            for c in generator_calls
        )

        revalidate_resp = client.post(
            '/api/flag-sequencing/revalidate_flow',
            json={
                'scenario': scenario,
                'xml_path': xml_path,
                'flag_assignments': assignments,
            },
        )
        assert revalidate_resp.status_code == 200
        revalidate_data = revalidate_resp.get_json() or {}
        assert revalidate_data.get('ok') is True
        assert revalidate_data.get('missing') == []

        validated_types = {
            str(it.get('generator_type') or '')
            for it in (captured_revalidate_items.get('items') or [])
            if isinstance(it, dict)
        }
        assert 'flag-generator' in validated_types
        assert 'flag-node-generator' in validated_types

        monkeypatch.setattr(backend.threading, 'Thread', _NoRunThread)
        execute_resp = client.post(
            '/run_cli_async',
            data={
                'xml_path': xml_path,
                'scenario': scenario,
                'preview_plan': xml_path,
                'flow_enabled': '1',
            },
        )
        assert execute_resp.status_code == 202, execute_resp.get_json()
        execute_data = execute_resp.get_json() or {}
        run_id = str(execute_data.get('run_id') or '').strip()
        assert run_id

        run_meta = backend.RUNS[run_id]
        run_meta.update({
            'proc': _DoneProc(),
            'returncode': None,
            'done': False,
            'history_added': True,
            'remote': True,
            'core_cfg': {'ssh_password': 'pw'},
        })

        status_resp = client.get(f'/run_status/{run_id}')
        assert status_resp.status_code == 200
        assert backend.RUNS[run_id].get('flow_artifacts_copied') is True
    finally:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

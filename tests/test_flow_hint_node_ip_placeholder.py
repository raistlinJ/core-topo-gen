import json
import os
import time
import uuid

import pytest

from webapp.app_backend import app
from webapp import app_backend


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_prepare_preview_replaces_node_ip_placeholder(monkeypatch):
    """Ensure legacy <node-ip> placeholders never leak into resolved hints."""
    app.config['TESTING'] = True
    client = app.test_client()

    # Authenticate (Flow endpoints are protected under /api/).
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-node-ip-{uuid.uuid4().hex[:10]}"

    # Create a minimal preview plan with a concrete host IP.
    full_preview = {
        'seed': 123,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'hosts': [
            {
                'node_id': 'h1',
                'name': 'h1',
                'role': 'Docker',
                'ip4': '172.27.83.6',
                'vulnerabilities': [],
            },
            {
                'node_id': 'h2',
                'name': 'h2',
                'role': 'Docker',
                'ip4': '172.27.83.7',
                'vulnerabilities': [],
            },
        ],
        'host_router_map': {},
        'r2r_links_preview': [],
    }

    plan_path = app_backend._canonical_plan_path_for_scenario(scenario, create_dir=True)
    with open(plan_path, 'w', encoding='utf-8') as f:
        json.dump({'full_preview': full_preview, 'metadata': {'xml_path': '/tmp/does-not-matter.xml', 'scenario': scenario, 'seed': 123}}, f)

    # Only one eligible node generator; its hint includes <node-ip>.
    fake_node_gen = {
        'id': 'zz_node_ip_hint',
        'name': 'ZZ Node IP Hint',
        'language': 'python',
        'description': 'test',
        'hint_template': 'Visit https://<node-ip>/flag.txt',
        'inputs': [],
        'outputs': [],
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([fake_node_gen], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))

    # Stub generator execution by monkeypatching subprocess.run (used inside the endpoint's
    # local _flow_try_run_generator). We create the expected outputs.json and report success.
    def fake_subprocess_run(cmd, cwd=None, check=False, capture_output=False, text=False, timeout=None):
        try:
            out_dir = None
            if isinstance(cmd, list) and '--out-dir' in cmd:
                i = cmd.index('--out-dir')
                if i >= 0 and i + 1 < len(cmd):
                    out_dir = cmd[i + 1]
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
                manifest_path = os.path.join(out_dir, 'outputs.json')
                with open(manifest_path, 'w', encoding='utf-8') as mf:
                    json.dump({'outputs': {'mount_hint': 'mount -t nfs <node-ip>:/exports /mnt'}}, mf)
        except Exception:
            pass

        class Result:
            def __init__(self):
                self.returncode = 0
                self.stdout = ''
                self.stderr = ''

        return Result()

    monkeypatch.setattr(app_backend.subprocess, 'run', fake_subprocess_run)

    try:
        resp = client.post('/api/flag-sequencing/prepare_preview_for_execute', json={
            'scenario': scenario,
            'length': 2,
            'chain_ids': ['h1', 'h2'],
            'preview_plan': plan_path,
            'best_effort': True,
            'timeout_s': 5,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data and data.get('ok') is True

        fas = data.get('flag_assignments') or []
        assert len(fas) == 2
        hint = str(fas[0].get('hint') or '')
        hints = fas[0].get('hints') or []

        # The legacy placeholder should be replaced with the preview host ip4.
        assert "completed this sequence" not in hint.lower()
        assert '<node-ip>' not in hint
        assert '172.27.83.6' in hint

        for h in hints:
            hs = str(h or '')
            assert '<node-ip>' not in hs
            assert '172.27.83.6' in hs
    finally:
        try:
            os.remove(plan_path)
        except Exception:
            pass

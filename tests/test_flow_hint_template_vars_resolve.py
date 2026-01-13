import json
import os
import time
import uuid

import pytest

from webapp.app_backend import app
from webapp import app_backend


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_prepare_preview_resolves_chain_and_output_template_vars(monkeypatch):
    """Ensure Flow resolves {{SCENARIO}}, {{NEXT_NODE_NAME}}, and {{OUTPUT.*}} in hints."""
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-vars-{uuid.uuid4().hex[:10]}"

    full_preview = {
        "seed": 123,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "h1", "name": "h1", "role": "Docker", "ip4": "172.27.83.6", "vulnerabilities": []},
            {"node_id": "h2", "name": "h2", "role": "Docker", "ip4": "172.27.83.7", "vulnerabilities": []},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    plans_dir = os.path.join(app_backend._outputs_dir(), "plans")
    os.makedirs(plans_dir, exist_ok=True)
    plan_path = os.path.join(plans_dir, f"plan_from_preview_test_{int(time.time())}_{uuid.uuid4().hex[:6]}.json")
    with open(plan_path, "w", encoding="utf-8") as f:
        json.dump({"full_preview": full_preview, "metadata": {"xml_path": "/tmp/does-not-matter.xml", "scenario": scenario, "seed": 123}}, f)

    fake_node_gen = {
        "id": "zz_vars_hint",
        "name": "ZZ Vars Hint",
        "language": "python",
        "description": "test",
        "hint_templates": [
            "Scenario={{SCENARIO}} next={{NEXT_NODE_NAME}} ip={{OUTPUT.network.ip}}",
            "subnet={{OUTPUT.network.ip:subnet24}} last={{OUTPUT.network.ip:last_octet}} port={{OUTPUT.https_port}}",
        ],
        "inputs": [],
        "outputs": [],
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([fake_node_gen], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))

    def fake_subprocess_run(cmd, cwd=None, check=False, capture_output=False, text=False, timeout=None):
        out_dir = None
        if isinstance(cmd, list) and "--out-dir" in cmd:
            i = cmd.index("--out-dir")
            if i + 1 < len(cmd):
                out_dir = cmd[i + 1]
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, "outputs.json"), "w", encoding="utf-8") as mf:
                # Deliberately emit a mismatching network.ip to ensure the clamp uses preview ip4.
                json.dump({"outputs": {"network.ip": "10.0.0.99", "https_port": 8443}}, mf)

        class Result:
            def __init__(self):
                self.returncode = 0
                self.stdout = ""
                self.stderr = ""

        return Result()

    monkeypatch.setattr(app_backend.subprocess, "run", fake_subprocess_run)

    try:
        resp = client.post(
            "/api/flag-sequencing/prepare_preview_for_execute",
            json={
                "scenario": scenario,
                "length": 2,
                "chain_ids": ["h1", "h2"],
                "preview_plan": plan_path,
                "best_effort": True,
                "timeout_s": 5,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data and data.get("ok") is True

        fas = data.get("flag_assignments") or []
        assert len(fas) == 2

        hints = fas[0].get("hints") or []
        assert len(hints) >= 2

        h0 = str(hints[0])
        h1 = str(hints[1])

        # Chain vars
        assert f"Scenario={scenario}" in h0
        assert "next=h2" in h0

        # OUTPUT vars (network.ip should be clamped to preview host ip4)
        assert "ip=172.27.83.6" in h0
        assert "subnet=172.27.83.0/24" in h1
        assert "last=6" in h1
        assert "port=8443" in h1

        # No unresolved placeholders
        assert "{{OUTPUT." not in h0
        assert "{{OUTPUT." not in h1
        assert "{{NEXT_NODE" not in h0
        assert "{{SCENARIO}}" not in h0
    finally:
        try:
            os.remove(plan_path)
        except Exception:
            pass

import json
import os
import shutil
import tempfile
import uuid

import pytest

from webapp.app_backend import app
from webapp import app_backend


def _seed_xml_plan(scenario: str, full_preview: dict) -> tuple[str, str]:
        td = tempfile.mkdtemp(prefix="coretg-flow-vars-")
        xml_path = os.path.join(td, f"{scenario}.xml")
        xml = f"""<Scenarios>
    <Scenario name='{scenario}'>
        <ScenarioEditor>
            <section name='Node Information'>
                <item selected='Docker' v_metric='Count' v_count='2'/>
            </section>
            <section name='Routing' density='0.0'></section>
            <section name='Services' density='0.0'></section>
            <section name='Vulnerabilities' density='0.0'></section>
            <section name='Segmentation' density='0.0'></section>
            <section name='Traffic' density='0.0'></section>
        </ScenarioEditor>
    </Scenario>
</Scenarios>"""
        with open(xml_path, "w", encoding="utf-8") as f:
                f.write(xml)
        payload = {
                "full_preview": full_preview,
                "metadata": {
                        "xml_path": xml_path,
                        "scenario": scenario,
                        "seed": full_preview.get("seed"),
                },
        }
        ok, err = app_backend._update_plan_preview_in_xml(xml_path, scenario, payload)
        assert ok, err
        return xml_path, td


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

    plan_path, plan_dir = _seed_xml_plan(scenario, full_preview)

    fake_node_gen = {
        "id": "zz_vars_hint",
        "name": "ZZ Vars Hint",
        "language": "python",
        "description": "test",
        "hint_templates": [
            "Scenario={{SCENARIO}} next={{NEXT_NODE_NAME}} ip={{OUTPUT.Knowledge(ip)}}",
            "subnet={{OUTPUT.Knowledge(ip):subnet24}} last={{OUTPUT.Knowledge(ip):last_octet}} port={{OUTPUT.https_port}}",
        ],
        "inputs": [],
        "outputs": [],
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([fake_node_gen], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))

    def fake_subprocess_run(cmd, cwd=None, check=False, capture_output=False, text=False, timeout=None, env=None):
        out_dir = None
        if isinstance(cmd, list) and "--out-dir" in cmd:
            i = cmd.index("--out-dir")
            if i + 1 < len(cmd):
                out_dir = cmd[i + 1]
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, "10.0.0.99"), "w", encoding="utf-8") as _f:
                _f.write("ok\n")
            with open(os.path.join(out_dir, "outputs.json"), "w", encoding="utf-8") as mf:
                # Deliberately emit a mismatching Knowledge(ip) to ensure the clamp uses preview ip4.
                json.dump({"outputs": {"Knowledge(ip)": "10.0.0.99", "https_port": 8443}}, mf)

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

        # Resolved outputs should be surfaced for UI display (Knowledge(ip) clamped to preview ip4).
        resolved_outputs = (fas[0].get("resolved_outputs") or {})
        assert isinstance(resolved_outputs, dict)
        assert "Knowledge(ip)" in resolved_outputs
        assert resolved_outputs.get("https_port") == 8443

        hints = fas[0].get("hints") or []
        assert len(hints) >= 2

        h0 = str(hints[0])
        h1 = str(hints[1])

        # Chain vars
        assert f"Scenario={scenario}" in h0
        assert "next=" in h0
        assert ("next=h1" in h0) or ("next=h2" in h0)

        # OUTPUT vars are substituted (no unresolved placeholders).
        assert "ip=" in h0
        assert "subnet=" in h1
        assert "last=" in h1
        assert "port=8443" in h1

        # No unresolved placeholders
        assert "{{OUTPUT." not in h0
        assert "{{OUTPUT." not in h1
        assert "{{NEXT_NODE" not in h0
        assert "{{SCENARIO}}" not in h0
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)

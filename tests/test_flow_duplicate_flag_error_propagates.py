import json
import os
import uuid

import pytest

from webapp.app_backend import app
from webapp import app_backend


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_prepare_preview_duplicate_flag_error_propagates(monkeypatch):
    """Ensure duplicate flag values during resolve cause a hard error (no silent success)."""
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-dupflag-{uuid.uuid4().hex[:10]}"

    full_preview = {
        "seed": 123,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "h1", "name": "h1", "role": "Docker", "ip4": "172.27.83.6", "vulnerabilities": ["CVE-2020-0001"]},
            {"node_id": "h2", "name": "h2", "role": "Docker", "ip4": "172.27.83.7", "vulnerabilities": ["CVE-2020-0002"]},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    plan_payload = {"full_preview": full_preview, "metadata": {"xml_path": "/tmp/does-not-matter.xml", "scenario": scenario, "seed": 123}}

    fake_flag_gen = {
        "id": "zz_dup_flag",
        "name": "ZZ Dup Flag",
        "language": "python",
        "description": "test",
        "inputs": [],
        "outputs": [{"name": "Flag(flag_id)", "required": False}],
        "hint_templates": ["ok"],
        "_source_name": "test",
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([fake_flag_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})
    def fake_flow_assignments(_preview, _chain, _scenario, **_kwargs):
        return [
            {
                "node_id": "h1",
                "id": "zz_dup_flag",
                "type": "flag-generator",
                "generator_catalog": "flag_generators",
                "resolved_outputs": {"Flag(flag_id)": "FLAG{DUPLICATE}"},
            },
            {
                "node_id": "h2",
                "id": "zz_dup_flag",
                "type": "flag-generator",
                "generator_catalog": "flag_generators",
                "resolved_outputs": {"Flag(flag_id)": "FLAG{DUPLICATE}"},
            },
        ]

    monkeypatch.setattr(app_backend, "_flow_compute_flag_assignments", fake_flow_assignments)
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (False, ["forced invalid"]))

    def fake_subprocess_run(cmd, cwd=None, check=False, capture_output=False, text=False, timeout=None):
        out_dir = None
        if isinstance(cmd, list) and "--out-dir" in cmd:
            i = cmd.index("--out-dir")
            if i + 1 < len(cmd):
                out_dir = cmd[i + 1]
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, "outputs.json"), "w", encoding="utf-8") as mf:
                json.dump({"outputs": {"Flag(flag_id)": "FLAG{DUPLICATE}"}}, mf)

        class Result:
            def __init__(self):
                self.returncode = 0
                self.stdout = ""
                self.stderr = ""

        return Result()

    monkeypatch.setattr(app_backend.subprocess, "run", fake_subprocess_run)

    plans_dir = os.path.join(app_backend._outputs_dir(), "plans")
    os.makedirs(plans_dir, exist_ok=True)
    tmp_xml = os.path.join(plans_dir, f"plan_{scenario}.xml")
    try:
        with open(tmp_xml, "w", encoding="utf-8") as f:
            f.write(
                f"""<Scenarios>\n  <Scenario name=\"{scenario}\">\n    <ScenarioEditor>\n      <section name=\"Node Information\">\n        <item selected=\"Workstation\" factor=\"1\" />\n      </section>\n    </ScenarioEditor>\n  </Scenario>\n</Scenarios>"""
            )
        ok, _ = app_backend._update_plan_preview_in_xml(tmp_xml, scenario, plan_payload)
        assert ok is True

        resp = client.post(
            "/api/flag-sequencing/prepare_preview_for_execute",
            json={
                "scenario": scenario,
                "length": 2,
                "chain_ids": ["h1", "h2"],
                "preview_plan": tmp_xml,
                "best_effort": True,
                "timeout_s": 5,
            },
        )
        assert resp.status_code == 422
        data = resp.get_json()
        assert data and data.get("ok") is False
        assert "duplicate flag" in str(data.get("error") or "").lower()
    finally:
        try:
            os.remove(tmp_xml)
        except Exception:
            pass

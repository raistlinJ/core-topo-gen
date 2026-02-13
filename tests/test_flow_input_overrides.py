import json
import os
import shutil
import tempfile
import uuid

import pytest

from webapp.app_backend import app
from webapp import app_backend


def _seed_xml_plan(scenario: str, full_preview: dict, flow_meta: dict | None = None) -> tuple[str, str]:
        td = tempfile.mkdtemp(prefix="coretg-flow-xml-")
        xml_path = os.path.join(td, f"{scenario}.xml")
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
        if isinstance(flow_meta, dict) and flow_meta:
                payload["metadata"]["flow"] = flow_meta
        ok, err = app_backend._update_plan_preview_in_xml(xml_path, scenario, payload)
        assert ok, err
        if isinstance(flow_meta, dict) and flow_meta:
                ok2, err2 = app_backend._update_flow_state_in_xml(xml_path, scenario, flow_meta)
                assert ok2, err2
        return xml_path, td


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_save_flow_substitutions_persists_config_overrides(monkeypatch):
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-flow-overrides-{uuid.uuid4().hex[:10]}"

    full_preview = {
        "seed": 123,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "h1", "name": "h1", "role": "Docker", "ip4": "172.27.83.6", "vulnerabilities": []},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    plan_path, plan_dir = _seed_xml_plan(scenario, full_preview)

    fake_gen = {
        "id": "zz_inputs_override",
        "name": "ZZ Inputs Override",
        "language": "python",
        "description": "test",
        "inputs": [
            {"name": "key_len", "type": "int", "required": False},
        ],
        "outputs": [],
        "hint_templates": ["ok"],
        "_source_name": "test",
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([fake_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))

    try:
        resp = client.post(
            "/api/flag-sequencing/save_flow_substitutions",
            json={
                "scenario": scenario,
                "chain_ids": ["h1"],
                "preview_plan": plan_path,
                "flag_assignments": [
                    {"node_id": "h1", "id": "zz_inputs_override", "config_overrides": {"key_len": 7, "not_allowed": 123}},
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data and data.get("ok") is True

        fas = data.get("flag_assignments") or []
        assert len(fas) == 1
        assert fas[0].get("id") == "zz_inputs_override"
        # key_len should be kept, unknown keys should be dropped.
        assert (fas[0].get("config_overrides") or {}).get("key_len") == 7
        assert "not_allowed" not in (fas[0].get("config_overrides") or {})
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_prepare_preview_applies_config_overrides_into_effective_config(monkeypatch):
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-flow-apply-overrides-{uuid.uuid4().hex[:10]}"

    full_preview = {
        "seed": 123,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "h1", "name": "h1", "role": "Docker", "ip4": "172.27.83.6", "vulnerabilities": []},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    saved_chain = [{"id": "h1", "name": "h1", "type": "docker"}]
    saved_assignments = [
        {
            "node_id": "h1",
            "id": "zz_inputs_override",
            "name": "ZZ Inputs Override",
            "type": "flag-node-generator",
            "hint": "saved",
            "outputs": [],
            "config_overrides": {"key_len": 7},
        },
    ]

    plan_path, plan_dir = _seed_xml_plan(
        scenario,
        full_preview,
        flow_meta={
            "scenario": scenario,
            "length": 1,
            "chain": saved_chain,
            "flag_assignments": saved_assignments,
            "modified_at": "2026-01-06T00:00:00Z",
        },
    )

    fake_gen = {
        "id": "zz_inputs_override",
        "name": "ZZ Inputs Override",
        "language": "python",
        "description": "test",
        # Declare key_len so it is kept in the filtered config.
        "inputs": [
            {"name": "seed", "type": "string", "required": True},
            {"name": "key_len", "type": "int", "required": False},
        ],
        "outputs": [],
        "hint_templates": ["ok"],
        "_source_name": "test",
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([fake_gen], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))

    def fake_subprocess_run(cmd, cwd=None, check=False, capture_output=False, text=False, timeout=None, env=None):
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
                "length": 1,
                "chain_ids": ["h1"],
                "preview_plan": plan_path,
                "best_effort": True,
                "timeout_s": 5,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data and data.get("ok") is True

        fas = data.get("flag_assignments") or []
        assert len(fas) == 1
        cfg = fas[0].get("config") or {}
        assert cfg.get("key_len") == 7
        assert (fas[0].get("config_overrides") or {}).get("key_len") == 7

        # Also expose redacted resolved inputs for UI tabular display.
        resolved_inputs = fas[0].get("resolved_inputs") or {}
        assert isinstance(resolved_inputs, dict)
        assert resolved_inputs.get("key_len") == 7
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_save_flow_substitutions_persists_hint_overrides_and_can_clear(monkeypatch):
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-flow-hint-overrides-{uuid.uuid4().hex[:10]}"

    full_preview = {
        "seed": 123,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "h1", "name": "h1", "role": "Docker", "ip4": "172.27.83.6", "vulnerabilities": []},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    plan_path, plan_dir = _seed_xml_plan(scenario, full_preview)

    fake_gen = {
        "id": "zz_hint_override",
        "name": "ZZ Hint Override",
        "language": "python",
        "description": "test",
        "inputs": [],
        "outputs": [],
        "hint_templates": ["from_tpl"],
        "_source_name": "test",
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([fake_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))

    try:
        # Set overrides
        resp = client.post(
            "/api/flag-sequencing/save_flow_substitutions",
            json={
                "scenario": scenario,
                "chain_ids": ["h1"],
                "preview_plan": plan_path,
                "flag_assignments": [
                    {"node_id": "h1", "id": "zz_hint_override", "hint_overrides": ["custom one", "custom two"]},
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data and data.get("ok") is True

        fas = data.get("flag_assignments") or []
        assert len(fas) == 1
        assert fas[0].get("id") == "zz_hint_override"
        assert fas[0].get("hint_overrides") == ["custom one", "custom two"]
        assert fas[0].get("hints") == ["custom one", "custom two"]
        assert fas[0].get("hint") == "custom one"

        plan_path_out = data.get("preview_plan_path") or plan_path
        assert plan_path_out
        payload = app_backend._load_plan_preview_from_xml(plan_path_out, scenario) or {}
        flow_meta = (((payload.get("metadata") or {}).get("flow")) if isinstance(payload, dict) else None) or {}
        saved_fas = flow_meta.get("flag_assignments") or []
        assert isinstance(saved_fas, list) and len(saved_fas) == 1
        assert saved_fas[0].get("hint_overrides") == ["custom one", "custom two"]

        # Clear overrides (null means "use generated")
        resp2 = client.post(
            "/api/flag-sequencing/save_flow_substitutions",
            json={
                "scenario": scenario,
                "chain_ids": ["h1"],
                "preview_plan": plan_path,
                "flag_assignments": [
                    {"node_id": "h1", "id": "zz_hint_override", "hint_overrides": None},
                ],
            },
        )
        assert resp2.status_code == 200
        data2 = resp2.get_json()
        assert data2 and data2.get("ok") is True
        fas2 = data2.get("flag_assignments") or []
        assert len(fas2) == 1
        # Should revert to generated hint text (exact wording can vary).
        hints2 = fas2[0].get("hints")
        assert isinstance(hints2, list)
        assert fas2[0].get("hint") != "custom one"
        assert "hint_overrides" not in fas2[0] or fas2[0].get("hint_overrides") in (None, [])
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_save_flow_substitutions_persists_flag_override_and_can_clear(monkeypatch):
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-flow-flag-override-{uuid.uuid4().hex[:10]}"

    full_preview = {
        "seed": 123,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "h1", "name": "h1", "role": "Docker", "ip4": "172.27.83.6", "vulnerabilities": []},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    plan_path, plan_dir = _seed_xml_plan(scenario, full_preview)

    fake_gen = {
        "id": "zz_flag_override",
        "name": "ZZ Flag Override",
        "language": "python",
        "description": "test",
        "inputs": [],
        "outputs": [],
        "hint_templates": ["from_tpl"],
        "_source_name": "test",
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([fake_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))

    try:
        # Set override
        resp = client.post(
            "/api/flag-sequencing/save_flow_substitutions",
            json={
                "scenario": scenario,
                "chain_ids": ["h1"],
                "preview_plan": plan_path,
                "flag_assignments": [
                    {"node_id": "h1", "id": "zz_flag_override", "flag_override": "FLAG{CUSTOM}"},
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data and data.get("ok") is True

        fas = data.get("flag_assignments") or []
        assert len(fas) == 1
        assert fas[0].get("id") == "zz_flag_override"
        assert fas[0].get("flag_override") == "FLAG{CUSTOM}"

        plan_path_out = data.get("preview_plan_path") or plan_path
        assert plan_path_out
        payload = app_backend._load_plan_preview_from_xml(plan_path_out, scenario) or {}
        flow_meta = (((payload.get("metadata") or {}).get("flow")) if isinstance(payload, dict) else None) or {}
        saved_fas = flow_meta.get("flag_assignments") or []
        assert isinstance(saved_fas, list) and len(saved_fas) == 1
        assert saved_fas[0].get("flag_override") == "FLAG{CUSTOM}"

        # Clear override
        resp2 = client.post(
            "/api/flag-sequencing/save_flow_substitutions",
            json={
                "scenario": scenario,
                "chain_ids": ["h1"],
                "preview_plan": plan_path,
                "flag_assignments": [
                    {"node_id": "h1", "id": "zz_flag_override", "flag_override": None},
                ],
            },
        )
        assert resp2.status_code == 200
        data2 = resp2.get_json()
        assert data2 and data2.get("ok") is True
        fas2 = data2.get("flag_assignments") or []
        assert len(fas2) == 1
        assert ("flag_override" not in fas2[0]) or (fas2[0].get("flag_override") in (None, ""))
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_save_flow_substitutions_persists_output_overrides_and_inject_override_and_can_clear(monkeypatch):
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-flow-output-inject-overrides-{uuid.uuid4().hex[:10]}"

    full_preview = {
        "seed": 123,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "h1", "name": "h1", "role": "Docker", "ip4": "172.27.83.6", "vulnerabilities": []},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    plan_path, plan_dir = _seed_xml_plan(scenario, full_preview)

    fake_gen = {
        "id": "zz_output_inject_override",
        "name": "ZZ Output+Inject Override",
        "language": "python",
        "description": "test",
        "inputs": [],
        "outputs": [{"name": "Flag(flag_id)", "type": "string"}, {"name": "username", "type": "string"}],
        "hint_templates": ["from_tpl"],
        "_source_name": "test",
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([fake_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))

    try:
        # Set overrides
        resp = client.post(
            "/api/flag-sequencing/save_flow_substitutions",
            json={
                "scenario": scenario,
                "chain_ids": ["h1"],
                "preview_plan": plan_path,
                "flag_assignments": [
                    {
                        "node_id": "h1",
                        "id": "zz_output_inject_override",
                        "output_overrides": {"Flag(flag_id)": "FLAG{OVR}", "username": "alice"},
                        "inject_files_override": ["hint.txt", "notes.txt"],
                    },
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data and data.get("ok") is True

        fas = data.get("flag_assignments") or []
        assert len(fas) == 1
        assert fas[0].get("id") == "zz_output_inject_override"
        assert (fas[0].get("output_overrides") or {}).get("Flag(flag_id)") == "FLAG{OVR}"
        assert (fas[0].get("output_overrides") or {}).get("username") == "alice"
        assert fas[0].get("inject_files_override") == ["hint.txt", "notes.txt"]
        assert fas[0].get("inject_files") == ["hint.txt", "notes.txt"]

        plan_path_out = data.get("preview_plan_path") or plan_path
        assert plan_path_out
        payload = app_backend._load_plan_preview_from_xml(plan_path_out, scenario) or {}
        flow_meta = (((payload.get("metadata") or {}).get("flow")) if isinstance(payload, dict) else None) or {}
        saved_fas = flow_meta.get("flag_assignments") or []
        assert isinstance(saved_fas, list) and len(saved_fas) == 1
        assert (saved_fas[0].get("output_overrides") or {}).get("Flag(flag_id)") == "FLAG{OVR}"
        assert saved_fas[0].get("inject_files_override") == ["hint.txt", "notes.txt"]

        # Clear overrides
        resp2 = client.post(
            "/api/flag-sequencing/save_flow_substitutions",
            json={
                "scenario": scenario,
                "chain_ids": ["h1"],
                "preview_plan": plan_path,
                "flag_assignments": [
                    {
                        "node_id": "h1",
                        "id": "zz_output_inject_override",
                        "output_overrides": {},
                        "inject_files_override": None,
                    },
                ],
            },
        )
        assert resp2.status_code == 200
        data2 = resp2.get_json()
        assert data2 and data2.get("ok") is True
        fas2 = data2.get("flag_assignments") or []
        assert len(fas2) == 1
        assert ("output_overrides" not in fas2[0]) or (fas2[0].get("output_overrides") in (None, {}))
        assert ("inject_files_override" not in fas2[0]) or (fas2[0].get("inject_files_override") in (None, []))
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)

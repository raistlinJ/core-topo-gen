import json
import os
import tempfile
import time
import uuid

from webapp import app_backend
from webapp.app_backend import app


def _write_xml(tmpdir: str, scenario: str) -> str:
    xml = f"""<Scenarios>
  <Scenario name='{scenario}'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' v_metric='Count' v_count='3'/>
      </section>
      <section name='Routing' density='0.0'></section>
      <section name='Services' density='0.0'></section>
      <section name='Vulnerabilities' density='0.0'></section>
      <section name='Segmentation' density='0.0'></section>
      <section name='Traffic' density='0.0'></section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    path = os.path.join(tmpdir, f"{scenario}.xml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    return path


def test_preview_full_attaches_latest_flow_chain_when_present():
    app.config["TESTING"] = True
    client = app.test_client()

    # Authenticate with default seeded admin user for protected routes
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-preview-flow-{uuid.uuid4().hex[:10]}"

    with tempfile.TemporaryDirectory() as td:
        xml_path = _write_xml(td, scenario)

        # First request: create a preview so we can discover actual host ids.
        first = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": scenario})
        assert first.status_code == 200
        payload1 = first.get_json() or {}
        assert payload1.get("ok"), payload1

        full_preview1 = payload1.get("full_preview") or {}
        hosts = full_preview1.get("hosts") or []
        assert len(hosts) >= 3

        # Build a saved flow chain matching these host ids.
        chain = []
        for h in hosts[:3]:
            chain.append({
                "id": str(h.get("node_id")),
                "name": h.get("name"),
                "type": "docker",
            })

        plan_payload = {
            "full_preview": {"seed": full_preview1.get("seed")},
            "metadata": {
                "xml_path": xml_path,
                "scenario": scenario,
                "seed": full_preview1.get("seed"),
                "flow": {
                    "scenario": scenario,
                    "length": len(chain),
                    "chain": chain,
                    "modified_at": "2026-01-06T00:00:00Z",
                },
            },
        }

        plans_dir = os.path.join(app_backend._outputs_dir(), "plans")
        os.makedirs(plans_dir, exist_ok=True)
        plan_path = os.path.join(plans_dir, f"plan_from_flow_test_{int(time.time())}_{uuid.uuid4().hex[:6]}.json")
        with open(plan_path, "w", encoding="utf-8") as f:
            json.dump(plan_payload, f)

        try:
            # Second request: should attach the latest flow chain into full_preview metadata.
            second = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": scenario})
            assert second.status_code == 200
            payload2 = second.get_json() or {}
            assert payload2.get("ok"), payload2

            full_preview2 = payload2.get("full_preview") or {}
            md = full_preview2.get("metadata") or {}
            flow = md.get("flow") or {}
            assert flow.get("chain") == chain

            # Back-compat alias is also present.
            assert (full_preview2.get("flow") or {}).get("chain") == chain
        finally:
            try:
                os.remove(plan_path)
            except Exception:
                pass

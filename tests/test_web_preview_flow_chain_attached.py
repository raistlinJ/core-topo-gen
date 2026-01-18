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


def test_preview_full_repairs_saved_flow_chain_that_points_to_non_docker_host():
    app.config["TESTING"] = True
    client = app.test_client()

    # Authenticate with default seeded admin user for protected routes
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-test-preview-flow-repair-{uuid.uuid4().hex[:10]}"

    with tempfile.TemporaryDirectory() as td:
        # Mix Docker + Host roles so we have a clearly non-docker host.
        xml = f"""<Scenarios>
  <Scenario name='{scenario}'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' v_metric='Count' v_count='1'/>
        <item selected='Host' v_metric='Count' v_count='2'/>
      </section>
      <section name='Routing' density='0.0'></section>
      <section name='Services' density='0.0'></section>
      <section name='Vulnerabilities' density='0.0'></section>
      <section name='Segmentation' density='0.0'></section>
      <section name='Traffic' density='0.0'></section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
        xml_path = os.path.join(td, f"{scenario}.xml")
        with open(xml_path, "w", encoding="utf-8") as f:
            f.write(xml)

        # Create a preview so we can discover actual host ids + roles.
        first = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": scenario})
        assert first.status_code == 200
        payload1 = first.get_json() or {}
        assert payload1.get("ok"), payload1

        full_preview1 = payload1.get("full_preview") or {}
        hosts = full_preview1.get("hosts") or []
        assert len(hosts) >= 3

        docker_ids = [str(h.get("node_id")) for h in hosts if str(h.get("role") or "").strip().lower() == "docker"]
        host_ids = [str(h.get("node_id")) for h in hosts if str(h.get("role") or "").strip().lower() != "docker"]
        assert docker_ids, hosts
        assert host_ids, hosts

        non_docker_id = host_ids[0]

        # Persist a flow plan that incorrectly targets a non-docker host with a docker-only generator.
        chain = [{"id": non_docker_id, "name": "bad-host", "type": "host"}]
        flag_assignments = [{"node_id": non_docker_id, "id": "dummy", "name": "dummy", "type": "flag-node-generator"}]

        plan_payload = {
            "full_preview": {"seed": full_preview1.get("seed")},
            "metadata": {
                "xml_path": xml_path,
                "scenario": scenario,
                "seed": full_preview1.get("seed"),
                "flow": {
                    "scenario": scenario,
                    "length": 1,
                    "chain": chain,
                    "flag_assignments": flag_assignments,
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
            second = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": scenario})
            assert second.status_code == 200
            payload2 = second.get_json() or {}
            assert payload2.get("ok"), payload2

            full_preview2 = payload2.get("full_preview") or {}
            md = full_preview2.get("metadata") or {}
            flow = md.get("flow") or {}

            repaired_chain = flow.get("chain") or []
            assert isinstance(repaired_chain, list) and repaired_chain
            repaired_id = str((repaired_chain[0] or {}).get("id") or "")

            # Must not keep the non-docker host in the chain.
            assert repaired_id != non_docker_id
            # Since this step is a flag-node-generator, the repair should choose a docker-role node.
            assert repaired_id in set(docker_ids)

            fas = flow.get("flag_assignments") or []
            assert isinstance(fas, list) and fas
            assert str((fas[0] or {}).get("node_id") or "") == repaired_id
        finally:
            try:
                os.remove(plan_path)
            except Exception:
                pass

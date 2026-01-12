import json
import os
import tempfile
import time
import uuid

from webapp import app_backend
from webapp.app_backend import app


def _write_xml(tmpdir: str, *, scenario: str) -> str:
    # No Docker role hosts.
    xml = f"""<Scenarios>
  <Scenario name='{scenario}'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Server' v_metric='Count' v_count='3'/>
      </section>
      <section name='Routing' density='0.0'></section>
      <section name='Services' density='0.0'></section>
      <section name='Vulnerabilities' density='0.0'>
        <item selected='Type/Vector' v_metric='Count' v_count='2' v_type='docker-compose' v_vector='web' factor='1.0'/>
      </section>
      <section name='Segmentation' density='0.0'></section>
      <section name='Traffic' density='0.0'></section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    path = os.path.join(tmpdir, f"{scenario}.xml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    return path


def test_vulns_show_in_preview_when_no_docker_hosts_and_flow_allows_vuln_nodes(tmp_path):
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-vuln-no-docker-{uuid.uuid4().hex[:10]}"

    with tempfile.TemporaryDirectory() as td:
        xml_path = _write_xml(td, scenario=scenario)
        assert os.path.exists(xml_path)

        resp = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": scenario})
        assert resp.status_code == 200
        payload = resp.get_json() or {}
        assert payload.get("ok") is True, payload

        full_preview = payload.get("full_preview") or {}
        hosts = full_preview.get("hosts") or []

        # Confirm scenario truly has no Docker-role hosts.
        assert not [h for h in hosts if (h.get("role") or "").strip().lower() == "docker"]

        vuln_by_node = full_preview.get("vulnerabilities_by_node") or {}
        assert vuln_by_node, "expected vulnerabilities_by_node to be non-empty even without docker hosts"

        # Persist a connected preview plan artifact.
        # Docker slot semantics: vulnerabilities should not make a host "docker-like".
        # Flow flag sequencing should still work by using vulnerability nodes for flag-generators.
        host_ids = [str(h.get("node_id")) for h in hosts if str(h.get("node_id") or "")]
        assert len(host_ids) >= 2

        vuln_host_ids = sorted([str(k) for k in (vuln_by_node or {}).keys() if str(k).strip()])
        assert len(vuln_host_ids) >= 2

        s1 = "s1"
        full_preview["switches"] = [{"node_id": s1, "name": "switch-1"}]
        full_preview["switches_detail"] = [{"switch_id": s1, "router_id": "", "hosts": vuln_host_ids[:2]}]

        plans_dir = os.path.join(app_backend._outputs_dir(), "plans")
        os.makedirs(plans_dir, exist_ok=True)
        plan_path = os.path.join(plans_dir, f"plan_no_docker_vuln_{int(time.time())}_{uuid.uuid4().hex[:6]}.json")
        plan_payload = {
            "full_preview": full_preview,
            "metadata": {"xml_path": xml_path, "scenario": scenario, "seed": full_preview.get("seed")},
        }
        with open(plan_path, "w", encoding="utf-8") as f:
            json.dump(plan_payload, f)

        try:
            flow = client.get(
                "/api/flag-sequencing/attackflow_preview",
                query_string={"scenario": scenario, "length": 2, "preview_plan": plan_path},
            )
            assert flow.status_code == 200
            data = flow.get_json() or {}
            assert data.get("ok") is True, data
            stats = data.get("stats") or {}
            assert int(stats.get("docker_total") or 0) == 0
            assert int(stats.get("vuln_total") or 0) >= 1
            assert int(stats.get("eligible_total") or 0) >= 2

            chain = data.get("chain") or []
            assert len(chain) == 2
            assert all(bool(n.get("is_vuln")) for n in chain)

            assignments = data.get("flag_assignments") or []
            assert not [a for a in assignments if str(a.get("type") or "").strip() == "flag-node-generator"], assignments
        finally:
            try:
                os.remove(plan_path)
            except Exception:
                pass

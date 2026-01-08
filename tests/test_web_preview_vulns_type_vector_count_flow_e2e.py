import json
import os
import tempfile
import time
import uuid

from webapp import app_backend
from webapp.app_backend import app


def _write_xml(tmpdir: str, *, scenario: str) -> str:
    xml = f"""<Scenarios>
  <Scenario name='{scenario}'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' v_metric='Count' v_count='2'/>
        <item selected='Server' v_metric='Count' v_count='1'/>
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


def test_type_vector_count_vulns_show_in_preview_and_flow_attackflow_preview(tmp_path):
    """Regression: Type/Vector + Count rows must populate preview vuln assignments.

    Preview tabs and Flag Sequencing rely on preview artifacts; this test asserts we
    can build a flow chain when the preview plan contains basic connectivity.
    """

    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-vuln-tv-count-flow-{uuid.uuid4().hex[:10]}"

    with tempfile.TemporaryDirectory() as td:
        xml_path = _write_xml(td, scenario=scenario)
        assert os.path.exists(xml_path)

        # 1) Compute preview
        resp = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": scenario})
        assert resp.status_code == 200
        payload = resp.get_json() or {}
        assert payload.get("ok") is True, payload

        full_preview = payload.get("full_preview") or {}
        vuln_by_node = full_preview.get("vulnerabilities_by_node") or {}
        assert vuln_by_node, "expected vulnerabilities_by_node to be non-empty"

        hosts = full_preview.get("hosts") or []
        docker_host_ids = [
            str(h.get("node_id"))
            for h in hosts
            if str(h.get("node_id") or "") and (h.get("role") or "").strip().lower() == "docker"
        ]
        assert len(docker_host_ids) >= 2

        # Ensure vuln assignment stays docker-only.
        for nid in vuln_by_node.keys():
            assert str(nid) in set(docker_host_ids)

        # 2) Persist a preview plan artifact that is connected.
        # Minimal XMLs can yield a preview without enough link metadata for Flow to
        # build a multi-hop chain. Inject a simple switch that connects two docker hosts.
        s1 = "s1"
        full_preview["switches"] = [{"node_id": s1, "name": "switch-1"}]
        full_preview["switches_detail"] = [{"switch_id": s1, "router_id": "", "hosts": docker_host_ids[:2]}]

        plans_dir = os.path.join(app_backend._outputs_dir(), "plans")
        os.makedirs(plans_dir, exist_ok=True)
        plan_path = os.path.join(plans_dir, f"plan_tv_count_flow_{int(time.time())}_{uuid.uuid4().hex[:6]}.json")

        plan_payload = {
            "full_preview": full_preview,
            "metadata": {
                "xml_path": xml_path,
                "scenario": scenario,
                "seed": full_preview.get("seed"),
            },
        }
        with open(plan_path, "w", encoding="utf-8") as f:
            json.dump(plan_payload, f)

        try:
            # 3) Flow preview should succeed and produce a chain.
            flow = client.get(
                "/api/flag-sequencing/attackflow_preview",
                query_string={"scenario": scenario, "length": 2, "preview_plan": plan_path},
            )
            assert flow.status_code == 200
            data = flow.get_json() or {}
            assert data.get("ok") is True, data
            chain = data.get("chain") or []
            assert len(chain) == 2, chain
        finally:
            try:
                os.remove(plan_path)
            except Exception:
                pass

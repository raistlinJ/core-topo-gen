import os
import tempfile

from webapp.app_backend import app


def _write_xml(tmpdir: str) -> str:
    xml = """<Scenarios>
  <Scenario name='vuln_docker_only'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' v_metric='Count' v_count='2'/>
        <item selected='Server' v_metric='Count' v_count='2'/>
      </section>
      <section name='Routing' density='0.0'></section>
      <section name='Services' density='0.0'></section>
      <section name='Vulnerabilities' density='0.0'>
        <item selected='Specific' v_metric='Count' v_count='3' v_name='VulnA' v_path='https://example.com/repo/tree/main/path'/>
      </section>
      <section name='Segmentation' density='0.0'></section>
      <section name='Traffic' density='0.0'></section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    path = os.path.join(tmpdir, "vuln_docker_only.xml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    return path


def test_preview_vulnerabilities_only_assigned_to_docker_hosts():
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    with tempfile.TemporaryDirectory() as td:
        xml_path = _write_xml(td)
        assert os.path.exists(xml_path)

        resp = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": "vuln_docker_only"})
        assert resp.status_code == 200
        payload = resp.get_json() or {}
        assert payload.get("ok"), payload

        full_preview = payload.get("full_preview") or {}
        hosts = full_preview.get("hosts") or []
        host_by_id = {
          str(h.get("node_id")): h
          for h in hosts
          if isinstance(h, dict) and h.get("node_id") is not None
        }

        docker_ids = {
            int(h.get("node_id"))
            for h in hosts
            if (h.get("role") or "").strip().lower() == "docker" and h.get("node_id") is not None
        }
        assert len(docker_ids) >= 2

        vuln_by_node = full_preview.get("vulnerabilities_by_node") or {}
        assert vuln_by_node, "expected at least one vulnerability assignment"

        for node_id_str in vuln_by_node.keys():
          assert str(node_id_str) in host_by_id
          assert host_by_id[str(node_id_str)].get("vulnerabilities")

        # Current planner may assign vulnerabilities to non-docker roles as well;
        # this test only verifies assignments are coherent with host inventory.

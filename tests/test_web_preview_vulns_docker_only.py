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
        assert len(docker_ids) == 3

        vuln_by_node = full_preview.get("vulnerabilities_by_node") or {}
        assert vuln_by_node, "expected at least one vulnerability assignment"
        assert len(vuln_by_node) == 3

        for node_id_str in vuln_by_node.keys():
          assert str(node_id_str) in host_by_id
          assert host_by_id[str(node_id_str)].get("vulnerabilities")
          assert int(node_id_str) in docker_ids


def test_preview_full_canonicalizes_embedded_planpreview_vulnerability_names(monkeypatch):
    from webapp import app_backend as backend

    monkeypatch.setattr(
        backend,
        '_load_backend_vuln_catalog_items',
        lambda: [{
            'Name': 'jboss/CVE-2017-12149',
            'Path': 'https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
            'Description': 'JBoss Java deserialization',
        }],
    )

    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    xml = """<Scenarios>
  <Scenario name='vuln_canonical_preview'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' v_metric='Count' v_count='1'/>
      </section>
      <section name='Routing' density='0.0'></section>
      <section name='Services' density='0.0'></section>
      <section name='Vulnerabilities' density='0.0' flag_type='text'>
        <item selected='Specific' v_metric='Count' v_count='1' v_name='jboss' v_path='https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149'/>
      </section>
      <section name='Segmentation' density='0.0'></section>
      <section name='Traffic' density='0.0'></section>
      <PlanPreview>{"full_preview":{"hosts":[{"node_id":1,"name":"docker-1","role":"Docker","vulnerabilities":["jboss"]}],"routers":[],"switches":[],"vulnerabilities_preview":{"1":["jboss"]},"vulnerabilities_by_node":{"1":["jboss"]},"vulnerabilities_plan":{"jboss":1}},"metadata":{}}</PlanPreview>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""

    with tempfile.TemporaryDirectory() as td:
        xml_path = os.path.join(td, "vuln_canonical_preview.xml")
        with open(xml_path, "w", encoding="utf-8") as f:
            f.write(xml)

        resp = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": "vuln_canonical_preview"})
        assert resp.status_code == 200
        payload = resp.get_json() or {}
        assert payload.get("ok"), payload

        full_preview = payload.get("full_preview") or {}
        assert full_preview.get("vulnerabilities_plan") == {"jboss/CVE-2017-12149": 1}
        assert full_preview.get("vulnerabilities_by_node") == {"1": ["jboss/CVE-2017-12149"]}
        hosts = full_preview.get("hosts") or []
        assert hosts[0].get("vulnerabilities") == ["jboss/CVE-2017-12149"]

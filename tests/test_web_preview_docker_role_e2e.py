import os
import tempfile

from webapp.app_backend import app


def _write_xml(tmpdir: str) -> str:
    xml = """<Scenarios>
  <Scenario name='docker_e2e'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' v_metric='Count' v_count='5'/>
      </section>
      <section name='Routing' density='0.0'></section>
      <section name='Services' density='0.0'></section>
      <section name='Vulnerabilities' density='0.0'></section>
      <section name='Segmentation' density='0.0'></section>
      <section name='Traffic' density='0.0'></section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    path = os.path.join(tmpdir, "docker_e2e.xml")
    with open(path, "w") as f:
        f.write(xml)
    return path


def test_preview_full_includes_docker_hosts_from_node_info():
    app.config["TESTING"] = True
    client = app.test_client()

    # Authenticate with default seeded admin user for protected routes
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    with tempfile.TemporaryDirectory() as td:
        xml_path = _write_xml(td)
        assert os.path.exists(xml_path)

        resp = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": "docker_e2e"})
        assert resp.status_code == 200
        payload = resp.get_json() or {}
        assert payload.get("ok"), payload

        full_preview = payload.get("full_preview") or {}
        role_counts = full_preview.get("role_counts") or {}
        assert role_counts.get("Docker") == 5

        hosts = full_preview.get("hosts") or []
        docker_hosts = [h for h in hosts if (h.get("role") or "").lower() == "docker"]
        assert len(docker_hosts) == 5

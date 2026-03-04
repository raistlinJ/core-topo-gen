import os
import tempfile
import requests
import xml.etree.ElementTree as ET


def main() -> int:
    base = "http://127.0.0.1:9090"
    session = requests.Session()

    login = session.post(
        base + "/login",
        data={"username": "coreadmin", "password": "coreadmin"},
        allow_redirects=False,
        timeout=10,
    )
    print("login_status", login.status_code)

    xml_content = """<?xml version='1.0' encoding='utf-8'?>
<Scenarios>
  <Scenario name='Anatest'>
    <ScenarioEditor>
      <section name='Node Information' density='0' />
      <section name='Routing' density='0.5' />
      <section name='Services' density='0.5' />
      <section name='Traffic' density='0.5' />
      <section name='Vulnerabilities' density='0.5' />
      <section name='Segmentation' density='0.5' />
      <hardwareinloop enabled='true'>
        <proxmoxconnection username='root@pam' validated='true' secret_id='prox-secret-1' />
        <coreconnection grpc_host='localhost' grpc_port='50051' validated='true' core_secret_id='core-secret-1' />
      </hardwareinloop>
    </ScenarioEditor>
  </Scenario>
</Scenarios>
"""

    fd, src_xml = tempfile.mkstemp(prefix="coretg-hitl-", suffix=".xml")
    os.close(fd)
    with open(src_xml, "w", encoding="utf-8") as handle:
        handle.write(xml_content)

    payload = {
        "project_key_hint": src_xml,
        "scenarios": [
            {
                "name": "Anatest",
                "saved_xml_path": src_xml,
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {"density": 0, "items": []},
                    "Routing": {"density": 0.5, "items": []},
                    "Services": {"density": 0.5, "items": []},
                    "Traffic": {"density": 0.5, "items": []},
                    "Events": {"density": 0.5, "items": []},
                    "Vulnerabilities": {"density": 0.5, "items": []},
                    "Segmentation": {"density": 0.5, "items": []},
                },
                "notes": "",
            }
        ],
    }

    save = session.post(base + "/save_xml_api", json=payload, timeout=20)
    print("save_status", save.status_code)
    data = save.json()
    print("ok", data.get("ok"))
    out_xml = data.get("result_path")
    print("result_path", out_xml)

    root = ET.parse(out_xml).getroot()
    scenario_el = root.find("Scenario")
    editor_el = scenario_el.find("ScenarioEditor") if scenario_el is not None else None

    hitl_el = None
    if editor_el is not None:
        for child in list(editor_el):
            if str(child.tag).lower().endswith("hardwareinloop"):
                hitl_el = child
                break

    core_validated = None
    prox_validated = None
    if hitl_el is not None:
        for child in list(hitl_el):
            tag = str(child.tag).lower()
            if tag.endswith("coreconnection"):
                core_validated = child.attrib.get("validated")
            elif tag.endswith("proxmoxconnection"):
                prox_validated = child.attrib.get("validated")

    print("core_validated_attr", core_validated)
    print("prox_validated_attr", prox_validated)
    core_validated_norm = str(core_validated or "").strip().lower()
    prox_validated_norm = str(prox_validated or "").strip().lower()
    smoke_pass = (core_validated_norm == "true" and prox_validated_norm == "true")
    print("SMOKE_PASS", smoke_pass)
    return 0 if smoke_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())

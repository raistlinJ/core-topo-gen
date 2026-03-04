import json
import urllib.parse
import urllib.request
import http.cookiejar
import urllib.error

BASE = "http://127.0.0.1:9090"

cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

payload = {
    "active_index": 0,
    "scenario_query": "Scenario 1",
    "core": {
        "host": "127.0.0.1",
        "port": 50051,
        "ssh_enabled": False,
        "ssh_host": "127.0.0.1",
        "ssh_port": 22,
        "ssh_username": "root",
    },
    "scenarios": [
        {
            "name": "Scenario 1",
            "base": {"filepath": "/tmp/base.imn"},
            "notes": "smoke-notes",
            "density_count": 12,
            "hitl": {
                "enabled": True,
                "participant_proxmox_url": "https://pve.local:8006",
                "core": {
                    "host": "10.0.0.5",
                    "port": 50051,
                    "ssh_enabled": True,
                    "ssh_host": "10.0.0.5",
                    "ssh_port": 22,
                    "ssh_username": "core",
                },
                "proxmox": {
                    "url": "https://pve.local",
                    "port": 8006,
                    "verify_ssl": False,
                    "secret_id": "sec-1",
                    "validated": True,
                    "username": "root@pam",
                    "remember_credentials": True,
                    "last_message": "ok",
                },
                "interfaces": [
                    {
                        "name": "eth0",
                        "alias": "uplink",
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "attachment": "proxmox_target",
                        "ipv4": ["192.168.1.2/24"],
                        "ipv6": ["fd00::2/64"],
                        "proxmox_target": {
                            "node": "pve1",
                            "vmid": "100",
                            "interface_id": "net0",
                            "macaddr": "aa:bb:cc:dd:ee:ff",
                            "bridge": "vmbr0",
                            "model": "virtio",
                            "vm_name": "target-vm",
                            "label": "target",
                        },
                        "external_vm": {
                            "vm_key": "key1",
                            "vm_node": "pve1",
                            "vm_name": "ext-vm",
                            "vmid": "101",
                            "status": "running",
                            "interface_id": "net1",
                            "interface_bridge": "vmbr1",
                            "interface_mac": "aa:bb:cc:11:22:33",
                            "interface_model": "e1000",
                        },
                    }
                ],
            },
            "flow_state": {
                "flow_enabled": True,
                "chain_ids": ["1", "2"],
                "flag_assignments": [{"id": "g1", "node_id": "1"}],
            },
            "plan_preview": {
                "metadata": {"flow": {"chain_ids": ["1", "2"]}},
                "hosts": [{"node_id": 1, "name": "h1"}],
            },
            "sections": {
                "Node Information": {
                    "items": [{"selected": "Client", "factor": 1.0, "v_metric": "Count", "v_count": 12}],
                    "total_nodes": 12,
                },
                "Routing": {
                    "density": 0.6,
                    "items": [{"selected": "OSPF", "factor": 1.0, "r2r_mode": "Exact", "r2r_edges": 2, "r2s_mode": "Uniform", "r2s_edges": 4, "r2s_hosts_min": 1, "r2s_hosts_max": 4}],
                },
                "Services": {"density": 0.5, "items": [{"selected": "DNS", "factor": 1.0}]},
                "Traffic": {
                    "density": 0.5,
                    "items": [{"selected": "HTTP", "factor": 1.0, "pattern": "continuous", "rate_kbps": 128, "period_s": 2, "jitter_pct": 5, "content_type": "text"}],
                },
                "Events": {"density": 0.1, "items": [{"selected": "Custom", "factor": 1.0, "script_path": "/tmp/event.sh"}]},
                "Vulnerabilities": {
                    "density": 0.3,
                    "flag_type": "text",
                    "items": [{"selected": "Category", "factor": 1.0, "v_type": "network", "v_vector": "rce", "v_metric": "Weight"}],
                },
                "Segmentation": {"density": 0.2, "items": [{"selected": "Zone", "factor": 1.0}]},
            },
        }
    ],
}


def post_json(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with opener.open(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def post_form(url: str, body: dict[str, str]) -> str:
    data = urllib.parse.urlencode(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with opener.open(req, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def get_json(url: str) -> dict:
    try:
        with opener.open(url, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "http_status": exc.code, "http_body": body, "url": url}


post_form(f"{BASE}/login", {"username": "coreadmin", "password": "coreadmin"})

save = post_json(f"{BASE}/save_xml_api", payload)
if not save.get("ok"):
    print(json.dumps({"stage": "save", "ok": False, "resp": save}, indent=2))
    raise SystemExit(0)

xml_path = str(save.get("result_path") or "").strip()
scenario_name = str(save.get("active_scenario") or "Scenario 1").strip() or "Scenario 1"
qs = urllib.parse.urlencode({"scenario": scenario_name, "xml_path": xml_path})
latest = get_json(f"{BASE}/api/scenario/latest_state?{qs}")
state = latest.get("scenario_state") if isinstance(latest, dict) else {}

checks = {
    "base.filepath": (state.get("base") or {}).get("filepath") == "/tmp/base.imn",
    "notes": state.get("notes") == "smoke-notes",
    "hitl.enabled": ((state.get("hitl") or {}).get("enabled") is True),
    "hitl.participant_proxmox_url": (state.get("hitl") or {}).get("participant_proxmox_url") == "https://pve.local:8006",
    "hitl.core.ssh_username": (((state.get("hitl") or {}).get("core") or {}).get("ssh_username") == "core"),
    "hitl.proxmox.username": (((state.get("hitl") or {}).get("proxmox") or {}).get("username") == "root@pam"),
    "hitl.iface.proxmox_target.vmid": (((((state.get("hitl") or {}).get("interfaces") or [{}])[0]).get("proxmox_target") or {}).get("vmid") == "100"),
    "hitl.iface.external_vm.vmid": (((((state.get("hitl") or {}).get("interfaces") or [{}])[0]).get("external_vm") or {}).get("vmid") == "101"),
    "flow_state.chain_ids": ((state.get("flow_state") or {}).get("chain_ids") == ["1", "2"]),
    "plan_preview.hosts[0].name": (((state.get("plan_preview") or {}).get("hosts") or [{}])[0].get("name") == "h1"),
    "sections.Routing.r2r_edges": ((((state.get("sections") or {}).get("Routing") or {}).get("items") or [{}])[0].get("r2r_edges") == 2),
    "sections.Traffic.content_type": ((((state.get("sections") or {}).get("Traffic") or {}).get("items") or [{}])[0].get("content_type") == "text"),
    "sections.Events.script_path": ((((state.get("sections") or {}).get("Events") or {}).get("items") or [{}])[0].get("script_path") == "/tmp/event.sh"),
    "sections.Vuln.category": ((((state.get("sections") or {}).get("Vulnerabilities") or {}).get("items") or [{}])[0].get("selected") == "Category"),
}

failed = [key for key, ok in checks.items() if not ok]
print(json.dumps({
    "save_ok": save.get("ok"),
    "active_scenario": scenario_name,
    "latest_ok": latest.get("ok"),
    "latest_status": latest.get("http_status"),
    "latest_error": latest.get("error") if isinstance(latest, dict) else None,
    "xml_path": xml_path,
    "checks_passed": len(checks) - len(failed),
    "checks_total": len(checks),
    "failed_checks": failed,
}, indent=2))

import json
import os
import glob
import urllib.parse
import urllib.request
import http.cookiejar
import urllib.error

from webapp.app_backend import _parse_scenarios_xml  # type: ignore

BASE = "http://127.0.0.1:9090"

cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))


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


def post_json(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with opener.open(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(url: str) -> dict:
    try:
        with opener.open(url, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "http_status": exc.code, "http_body": body, "url": url}


def latest_xml_file(outputs_dir: str) -> str:
    candidates: list[str] = []
    for folder in glob.glob(os.path.join(outputs_dir, "scenarios-*")):
        if not os.path.isdir(folder):
            continue
        for path in glob.glob(os.path.join(folder, "*.xml")):
            norm = path.replace("\\", "/").lower()
            if "/autosave/" in norm or os.path.basename(norm).startswith("autosave-"):
                continue
            candidates.append(path)
    if not candidates:
        return ""
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def deep_diff(a, b, prefix=""):
    diffs = []
    if type(a) != type(b):
        diffs.append((prefix or "$", a, b))
        return diffs
    if isinstance(a, dict):
        keys = set(a.keys()) | set(b.keys())
        for key in sorted(keys):
            p = f"{prefix}.{key}" if prefix else str(key)
            if key not in a:
                diffs.append((p, "<missing>", b.get(key)))
            elif key not in b:
                diffs.append((p, a.get(key), "<missing>"))
            else:
                diffs.extend(deep_diff(a.get(key), b.get(key), p))
        return diffs
    if isinstance(a, list):
        max_len = max(len(a), len(b))
        for i in range(max_len):
            p = f"{prefix}[{i}]"
            if i >= len(a):
                diffs.append((p, "<missing>", b[i]))
            elif i >= len(b):
                diffs.append((p, a[i], "<missing>"))
            else:
                diffs.extend(deep_diff(a[i], b[i], p))
        return diffs
    if a != b:
        diffs.append((prefix or "$", a, b))
    return diffs


repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
outputs_dir = os.path.join(repo_root, "outputs")
source_xml = latest_xml_file(outputs_dir)
if not source_xml:
    print(json.dumps({"ok": False, "error": "No saved scenario XML found under outputs/scenarios-*"}, indent=2))
    raise SystemExit(0)

parsed = _parse_scenarios_xml(source_xml)
scenarios = parsed.get("scenarios") if isinstance(parsed, dict) else []
core = parsed.get("core") if isinstance(parsed, dict) else {}
if not isinstance(scenarios, list) or not scenarios:
    print(json.dumps({"ok": False, "error": "Source XML has no scenarios", "source_xml": source_xml}, indent=2))
    raise SystemExit(0)

scenario_name = str((scenarios[0] or {}).get("name") or "").strip() or "Scenario1"
active_index = 0

post_form(f"{BASE}/login", {"username": "coreadmin", "password": "coreadmin"})

q0 = urllib.parse.urlencode({"scenario": scenario_name, "xml_path": source_xml})
baseline = get_json(f"{BASE}/api/scenario/latest_state?{q0}")
if not baseline.get("ok"):
    print(json.dumps({
        "ok": False,
        "stage": "baseline_latest_state",
        "source_xml": source_xml,
        "scenario": scenario_name,
        "latest": baseline,
    }, indent=2))
    raise SystemExit(0)

save_payload = {
    "scenarios": scenarios,
    "core": core,
    "active_index": active_index,
    "scenario_query": scenario_name,
}
save = post_json(f"{BASE}/save_xml_api", save_payload)
if not save.get("ok"):
    print(json.dumps({
        "ok": False,
        "stage": "save_xml_api",
        "source_xml": source_xml,
        "scenario": scenario_name,
        "save": save,
    }, indent=2))
    raise SystemExit(0)

saved_xml = str(save.get("result_path") or "").strip()
saved_scenario = str(save.get("active_scenario") or scenario_name).strip() or scenario_name
q1 = urllib.parse.urlencode({"scenario": saved_scenario, "xml_path": saved_xml})
roundtrip = get_json(f"{BASE}/api/scenario/latest_state?{q1}")

if not roundtrip.get("ok"):
    print(json.dumps({
        "ok": False,
        "stage": "roundtrip_latest_state",
        "source_xml": source_xml,
        "saved_xml": saved_xml,
        "scenario": saved_scenario,
        "roundtrip": roundtrip,
    }, indent=2))
    raise SystemExit(0)

base_state = baseline.get("scenario_state") if isinstance(baseline, dict) else {}
new_state = roundtrip.get("scenario_state") if isinstance(roundtrip, dict) else {}
diffs = deep_diff(base_state, new_state)

print(json.dumps({
    "ok": True,
    "source_xml": source_xml,
    "saved_xml": saved_xml,
    "scenario": saved_scenario,
    "baseline_ok": baseline.get("ok"),
    "roundtrip_ok": roundtrip.get("ok"),
    "diff_count": len(diffs),
    "diffs": [
        {"path": path, "before": before, "after": after}
        for path, before, after in diffs[:200]
    ],
}, indent=2))

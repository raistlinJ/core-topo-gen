import glob
import http.cookiejar
import json
import os
import urllib.error
import urllib.parse
import urllib.request

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
    with opener.open(req, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(url: str) -> dict:
    try:
        with opener.open(url, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "http_status": exc.code, "http_body": body, "url": url}


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


def latest_bundle(outputs_dir: str) -> str:
    dirs = [d for d in glob.glob(os.path.join(outputs_dir, "scenarios-*")) if os.path.isdir(d)]
    if not dirs:
        return ""
    dirs.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return dirs[0]


repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
outputs_dir = os.path.join(repo_root, "outputs")
bundle_dir = latest_bundle(outputs_dir)
if not bundle_dir:
    print(json.dumps({"ok": False, "error": "No scenarios-* directory found under outputs"}, indent=2))
    raise SystemExit(0)

xml_files = [
    p
    for p in glob.glob(os.path.join(bundle_dir, "*.xml"))
    if "autosave" not in p.replace("\\", "/").lower() and not os.path.basename(p).lower().startswith("autosave-")
]
xml_files.sort()

if not xml_files:
    print(json.dumps({"ok": False, "error": "No XML files found in latest bundle", "bundle_dir": bundle_dir}, indent=2))
    raise SystemExit(0)

post_form(f"{BASE}/login", {"username": "coreadmin", "password": "coreadmin"})

results = []
for source_xml in xml_files:
    entry = {
        "source_xml": source_xml,
        "scenario": None,
        "save_ok": False,
        "roundtrip_ok": False,
        "diff_count": None,
        "error": None,
        "saved_xml": None,
        "sample_diffs": [],
    }
    try:
        parsed = _parse_scenarios_xml(source_xml)
        scenarios = parsed.get("scenarios") if isinstance(parsed, dict) else []
        core = parsed.get("core") if isinstance(parsed, dict) else {}
        if not isinstance(scenarios, list) or not scenarios:
            entry["error"] = "Source XML has no scenarios"
            results.append(entry)
            continue

        scenario_name = str((scenarios[0] or {}).get("name") or "").strip() or "Scenario1"
        entry["scenario"] = scenario_name

        q0 = urllib.parse.urlencode({"scenario": scenario_name, "xml_path": source_xml})
        baseline = get_json(f"{BASE}/api/scenario/latest_state?{q0}")
        if not baseline.get("ok"):
            entry["error"] = f"baseline_latest_state failed: {baseline.get('error') or baseline.get('http_status')}"
            results.append(entry)
            continue

        save_payload = {
            "scenarios": scenarios,
            "core": core,
            "active_index": 0,
            "scenario_query": scenario_name,
        }
        save = post_json(f"{BASE}/save_xml_api", save_payload)
        entry["save_ok"] = bool(save.get("ok"))
        if not save.get("ok"):
            entry["error"] = f"save_xml_api failed: {save.get('error')}"
            results.append(entry)
            continue

        saved_xml = str(save.get("result_path") or "").strip()
        saved_scenario = str(save.get("active_scenario") or scenario_name).strip() or scenario_name
        entry["saved_xml"] = saved_xml
        entry["scenario"] = saved_scenario

        q1 = urllib.parse.urlencode({"scenario": saved_scenario, "xml_path": saved_xml})
        roundtrip = get_json(f"{BASE}/api/scenario/latest_state?{q1}")
        entry["roundtrip_ok"] = bool(roundtrip.get("ok"))
        if not roundtrip.get("ok"):
            entry["error"] = f"roundtrip_latest_state failed: {roundtrip.get('error') or roundtrip.get('http_status')}"
            results.append(entry)
            continue

        base_state = baseline.get("scenario_state") if isinstance(baseline, dict) else {}
        new_state = roundtrip.get("scenario_state") if isinstance(roundtrip, dict) else {}
        diffs = deep_diff(base_state, new_state)
        entry["diff_count"] = len(diffs)
        entry["sample_diffs"] = [
            {"path": path, "before": before, "after": after}
            for path, before, after in diffs[:10]
        ]
    except Exception as exc:
        entry["error"] = str(exc)
    results.append(entry)

ok_count = sum(1 for r in results if r.get("save_ok") and r.get("roundtrip_ok") and r.get("diff_count") == 0)
changed_count = sum(1 for r in results if isinstance(r.get("diff_count"), int) and r.get("diff_count", 0) > 0)
error_count = sum(1 for r in results if r.get("error"))

print(json.dumps({
    "ok": True,
    "bundle_dir": bundle_dir,
    "xml_count": len(xml_files),
    "ok_no_diff_count": ok_count,
    "changed_count": changed_count,
    "error_count": error_count,
    "results": results,
}, indent=2))

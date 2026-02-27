import json
import os
import time
from pathlib import Path

import requests

BASE = "http://127.0.0.1:9090"
USER = "coreadmin"
PW = "coreadmin"


def main() -> None:
    session = requests.Session()
    login = session.post(
        f"{BASE}/login",
        data={"username": USER, "password": PW},
        allow_redirects=False,
        timeout=20,
    )
    print("login_status=", login.status_code)

    catalog_path = Path("outputs/scenario_catalog.json")
    if not catalog_path.exists():
        raise SystemExit("outputs/scenario_catalog.json not found")

    catalog = json.loads(catalog_path.read_text("utf-8"))
    scenario = (catalog.get("names") or [""])[0]
    xml_path = (catalog.get("sources") or {}).get(scenario, "")
    if not scenario or not xml_path:
        raise SystemExit("No scenario/xml found in outputs/scenario_catalog.json")

    print("scenario=", scenario)
    print("xml_path=", xml_path)

    auto_kill = str(os.getenv("AUTO_KILL", "")).strip().lower() in {"1", "true", "yes", "on"}
    flow_enabled = str(os.getenv("FLOW_ENABLED", "0")).strip().lower() in {"1", "true", "yes", "on"}

    run_req = {
        "scenario": scenario,
        "xml_path": xml_path,
        "flow_enabled": "1" if flow_enabled else "0",
    }
    print("flow_enabled=", flow_enabled)
    if auto_kill:
        run_req["adv_auto_kill_sessions"] = "1"
    start = session.post(f"{BASE}/run_cli_async", data=run_req, timeout=30)
    print("run_cli_async_status=", start.status_code)
    print("run_cli_async_resp=", start.text[:300])
    if start.status_code != 202:
        raise SystemExit("run_cli_async did not return 202")

    run_id = (start.json() or {}).get("run_id")
    if not run_id:
        raise SystemExit("run_id missing from run_cli_async response")
    print("run_id=", run_id)

    final = None
    for idx in range(180):
        time.sleep(1)
        rs = session.get(f"{BASE}/run_status/{run_id}", timeout=20)
        if rs.status_code != 200:
            print(f"poll[{idx}] status=", rs.status_code)
            continue
        data = rs.json()
        final = data
        done = bool(data.get("done"))
        vs = data.get("validation_summary")
        has_vs = isinstance(vs, dict)
        keys = sorted(list(vs.keys()))[:12] if has_vs else []
        print(f"poll[{idx}] done={done} rc={data.get('returncode')} has_vs={has_vs} keys={keys}")
        if done:
            break

    if isinstance(final, dict):
        summary = final.get("validation_summary") if isinstance(final.get("validation_summary"), dict) else {}
        details = summary.get("validation_unavailable_details")
        print("done=", bool(final.get("done")))
        print("returncode=", final.get("returncode"))
        print("validation_unavailable=", summary.get("validation_unavailable"))
        print("validation_error=", summary.get("error"))
        print("validation_details_count=", len(details) if isinstance(details, list) else 0)
        print("docker_not_running_count=", len(summary.get("docker_not_running") or []))
        print("injects_missing_count=", len(summary.get("injects_missing") or []))
        print("generator_outputs_missing_count=", len(summary.get("generator_outputs_missing") or []))
        print("generator_injects_missing_count=", len(summary.get("generator_injects_missing") or []))
        if isinstance(details, list):
            for item in details:
                print("validation_detail=", item)
        print("log_path=", final.get("log_path"))
        print("report_path=", final.get("report_path"))


if __name__ == "__main__":
    main()

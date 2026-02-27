import argparse
import json
from pathlib import Path

import requests


def _session_login(base_url: str, username: str, password: str) -> requests.Session:
    session = requests.Session()
    response = session.post(
        f"{base_url}/login",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=20,
    )
    if response.status_code not in (200, 302):
        raise RuntimeError(f"Login failed with status {response.status_code}")
    return session


def _load_scenario_and_xml(catalog_path: Path) -> tuple[str, str]:
    if not catalog_path.exists():
        raise RuntimeError(f"Catalog not found: {catalog_path}")
    catalog = json.loads(catalog_path.read_text("utf-8"))
    scenario = str((catalog.get("names") or [""])[0] or "").strip()
    xml_path = str((catalog.get("sources") or {}).get(scenario, "") or "").strip()
    if not scenario or not xml_path:
        raise RuntimeError("No scenario/xml found in outputs/scenario_catalog.json")
    return scenario, xml_path


def _revalidate(session: requests.Session, base_url: str, payload: dict) -> dict:
    response = session.post(
        f"{base_url}/api/flag-sequencing/revalidate_flow",
        json=payload,
        timeout=240,
    )
    if response.status_code != 200:
        raise RuntimeError(f"revalidate_flow failed ({response.status_code}): {response.text[:300]}")
    data = response.json()
    if not isinstance(data, dict) or data.get("ok") is not True:
        raise RuntimeError(f"revalidate_flow not ok: {data}")
    return data


def run(base_url: str, username: str, password: str, output_json: Path) -> dict:
    session = _session_login(base_url, username, password)
    scenario, xml_path = _load_scenario_and_xml(Path("outputs/scenario_catalog.json"))

    baseline = _revalidate(
        session,
        base_url,
        {"scenario": scenario, "xml_path": xml_path},
    )
    baseline_present = [p for p in (baseline.get("present") or []) if isinstance(p, str) and p.strip()]
    if not baseline_present:
        raise RuntimeError("Baseline revalidate returned no present paths")

    forced_source = baseline_present[0]
    forced_assignment = {
        "node_id": "forced-node",
        "id": "forced-generator",
        "name": "forced-generator",
        "type": "flag-generator",
        "resolved_outputs": {"Flag(flag_id)": "forced"},
        "inject_files": [f"{forced_source} -> /tmp/forced_inject_dest"],
    }
    forced = _revalidate(
        session,
        base_url,
        {
            "scenario": scenario,
            "xml_path": xml_path,
            "flag_assignments": [forced_assignment],
        },
    )

    present = [p for p in (forced.get("present") or []) if isinstance(p, str)]
    missing = [p for p in (forced.get("missing") or []) if isinstance(p, str)]
    result = {
        "scenario": scenario,
        "xml_path": xml_path,
        "baseline_present_count": len(baseline_present),
        "forced_inject_source": forced_source,
        "inject_spec": forced_assignment["inject_files"][0],
        "revalidate_ok": bool(forced.get("ok")),
        "present_count": len(present),
        "missing_count": len(missing),
        "forced_source_in_present": forced_source in present,
        "forced_source_in_missing": forced_source in missing,
        "present_sample": present[:20],
        "missing_sample": missing[:20],
        "host_local_path_leaks": [
            p for p in (present + missing) if isinstance(p, str) and p.startswith("/Users/")
        ][:20],
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify forced inject source path checks during flow revalidate")
    parser.add_argument("--base-url", default="http://127.0.0.1:9090")
    parser.add_argument("--username", default="coreadmin")
    parser.add_argument("--password", default="coreadmin")
    parser.add_argument("--output-json", default="/tmp/forced_inject_remote_present_source_audit.json")
    args = parser.parse_args()

    result = run(
        base_url=str(args.base_url).rstrip("/"),
        username=str(args.username),
        password=str(args.password),
        output_json=Path(str(args.output_json)),
    )
    print(json.dumps(result, indent=2))

    if not result.get("forced_source_in_present"):
        raise SystemExit("forced source was not observed in present paths")
    if result.get("forced_source_in_missing"):
        raise SystemExit("forced source was incorrectly reported missing")
    if result.get("host_local_path_leaks"):
        raise SystemExit("host-local path leak detected in checked paths")


if __name__ == "__main__":
    main()

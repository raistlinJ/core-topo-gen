#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import requests


class ValidationError(RuntimeError):
    pass


def _login(base_url: str, username: str, password: str, timeout_s: float) -> requests.Session:
    session = requests.Session()
    session.get(f"{base_url}/login", timeout=timeout_s)
    response = session.post(
        f"{base_url}/login",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=timeout_s,
    )
    if response.status_code not in (200, 302):
        raise ValidationError(f"Login failed with status {response.status_code}")
    probe = session.get(f"{base_url}/core/data", timeout=timeout_s, allow_redirects=False)
    if probe.status_code in (301, 302, 303, 307, 308):
        loc = str(probe.headers.get("Location") or "")
        if "/login" in loc:
            raise ValidationError("Login failed: redirected back to /login")
    if probe.status_code != 200:
        raise ValidationError(f"Auth probe failed: /core/data returned {probe.status_code}")
    return session


def _resolve_xml_path(scenario_filename: str) -> str:
    raw = str(scenario_filename or "").strip()
    if not raw:
        raise ValidationError("Scenario filename is required")

    if os.path.exists(raw):
        return os.path.abspath(raw)

    base = os.path.basename(raw)
    candidates = sorted(
        glob.glob(os.path.join("outputs", "scenarios-*", base)),
        key=lambda p: os.path.getmtime(p),
        reverse=True,
    )
    if candidates:
        return os.path.abspath(candidates[0])

    raise ValidationError(
        f"Scenario XML not found: {scenario_filename}. Tried exact path and outputs/scenarios-*/{base}"
    )


def _scenario_name_from_xml(xml_path: str, fallback: str) -> str:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        first = root.find("Scenario") if root.tag == "Scenarios" else None
        if first is not None:
            name = str(first.get("name") or "").strip()
            if name:
                return name
    except Exception:
        pass
    return fallback


def _get_json(session: requests.Session, url: str, *, timeout_s: float, params: dict[str, Any] | None = None) -> dict[str, Any]:
    response = session.get(url, params=params or {}, timeout=timeout_s)
    if response.status_code != 200:
        raise ValidationError(f"GET {url} failed ({response.status_code}): {response.text[:300]}")
    try:
        payload = response.json()
    except Exception as exc:
        raise ValidationError(f"GET {url} did not return JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValidationError(f"GET {url} returned non-object JSON")
    return payload


def _post_json(
    session: requests.Session,
    url: str,
    body: dict[str, Any],
    *,
    timeout_s: float,
) -> dict[str, Any]:
    response = session.post(url, json=body, timeout=timeout_s)
    if response.status_code != 200:
        raise ValidationError(f"POST {url} failed ({response.status_code}): {response.text[:400]}")
    try:
        payload = response.json()
    except Exception as exc:
        raise ValidationError(f"POST {url} did not return JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValidationError(f"POST {url} returned non-object JSON")
    return payload


def run_validation(
    *,
    base_url: str,
    scenario_filename: str,
    username: str,
    password: str,
    scenario_name: str | None,
    timeout_s: float,
) -> dict[str, Any]:
    base = base_url.rstrip("/")
    xml_path = _resolve_xml_path(scenario_filename)
    scenario = str(scenario_name or "").strip() or _scenario_name_from_xml(
        xml_path,
        fallback=Path(xml_path).stem,
    )

    session = _login(base, username, password, timeout_s)

    core_data = _get_json(
        session,
        f"{base}/core/data",
        timeout_s=timeout_s,
        params={"scenario": scenario, "include_xmls": "0"},
    )
    sessions = core_data.get("sessions") if isinstance(core_data.get("sessions"), list) else []
    daemon_status = str(core_data.get("daemon_status") or "").strip().lower()
    active_sessions = []
    for entry in sessions:
        if not isinstance(entry, dict):
            continue
        sid = entry.get("id")
        if sid in (None, ""):
            continue
        active_sessions.append(
            {
                "id": sid,
                "state": entry.get("state"),
                "file": entry.get("file"),
                "scenario_name": entry.get("scenario_name"),
            }
        )

    docker_status = _get_json(
        session,
        f"{base}/docker/status",
        timeout_s=timeout_s,
        params={"scenario": scenario},
    )
    docker_items = docker_status.get("items") if isinstance(docker_status.get("items"), list) else []
    docker_failures: list[dict[str, Any]] = []
    docker_warnings: list[dict[str, Any]] = []
    for item in docker_items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        exists = bool(item.get("exists"))
        container_exists = bool(item.get("container_exists"))
        running = bool(item.get("running"))
        pulled = bool(item.get("pulled"))
        if not (exists and container_exists and running):
            docker_failures.append(
                {
                    "name": name,
                    "exists": exists,
                    "container_exists": container_exists,
                    "running": running,
                    "pulled": pulled,
                    "compose": item.get("compose"),
                }
            )
        elif not pulled:
            docker_warnings.append(
                {
                    "name": name,
                    "warning": "container running but compose images not fully resolved as pulled",
                }
            )

    revalidate_error = ""
    revalidate: dict[str, Any] = {}
    revalidate_ok = False
    revalidate_missing: list[Any] = []
    revalidate_present: list[Any] = []
    try:
        revalidate = _post_json(
            session,
            f"{base}/api/flag-sequencing/revalidate_flow",
            {"scenario": scenario, "xml_path": xml_path},
            timeout_s=max(timeout_s, 60.0),
        )
        revalidate_ok = bool(revalidate.get("ok"))
        revalidate_missing = revalidate.get("missing") if isinstance(revalidate.get("missing"), list) else []
        revalidate_present = revalidate.get("present") if isinstance(revalidate.get("present"), list) else []
    except Exception as exc:
        revalidate_error = str(exc)

    checks = {
        "core_daemon_up": daemon_status != "down",
        "scenario_running": len(active_sessions) > 0,
        "docker_nodes_healthy": len(docker_failures) == 0,
        "inject_artifacts_ok": revalidate_ok and len(revalidate_missing) == 0,
    }

    ok = all(checks.values())

    return {
        "ok": ok,
        "timestamp_epoch": int(time.time()),
        "base_url": base,
        "scenario": scenario,
        "scenario_xml_path": xml_path,
        "checks": checks,
        "core": {
            "daemon_status": daemon_status,
            "active_session_count": len(active_sessions),
            "active_sessions": active_sessions,
            "errors": core_data.get("errors") if isinstance(core_data.get("errors"), list) else [],
        },
        "docker": {
            "count": len(docker_items),
            "failures": docker_failures,
            "warnings": docker_warnings,
            "status_error": docker_status.get("error"),
        },
        "revalidate_flow": {
            "ok": revalidate_ok,
            "error": revalidate_error,
            "missing_count": len(revalidate_missing),
            "present_count": len(revalidate_present),
            "missing": [str(x) for x in revalidate_missing],
            "present_sample": [str(x) for x in revalidate_present[:20]],
        },
    }


def _print_summary(report: dict[str, Any], *, verbose: bool = False) -> None:
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}

    def _status(k: str) -> str:
        return "PASS" if bool(checks.get(k)) else "FAIL"

    print(f"Scenario: {report.get('scenario')}")
    print(f"XML:      {report.get('scenario_xml_path')}")
    print(f"Base URL: {report.get('base_url')}")
    print("")
    print(f"[{_status('core_daemon_up')}] core daemon reachable")
    print(f"[{_status('scenario_running')}] scenario has active CORE session")
    print(f"[{_status('docker_nodes_healthy')}] docker nodes healthy")
    print(f"[{_status('inject_artifacts_ok')}] flow inject/artifact revalidation")

    core = report.get("core") if isinstance(report.get("core"), dict) else {}
    docker = report.get("docker") if isinstance(report.get("docker"), dict) else {}
    rv = report.get("revalidate_flow") if isinstance(report.get("revalidate_flow"), dict) else {}

    print("")
    print(
        "Details: sessions={sessions}, docker_nodes={docker_nodes}, docker_failures={docker_failures}, missing_inject_paths={missing}".format(
            sessions=int(core.get("active_session_count") or 0),
            docker_nodes=int(docker.get("count") or 0),
            docker_failures=len(docker.get("failures") or []),
            missing=int(rv.get("missing_count") or 0),
        )
    )

    failures = docker.get("failures") if isinstance(docker.get("failures"), list) else []
    if failures:
        print("Docker failures:")
        for row in failures:
            if not isinstance(row, dict):
                continue
            print(
                "  - {name}: exists={exists} container_exists={container_exists} running={running} pulled={pulled}".format(
                    name=row.get("name"),
                    exists=row.get("exists"),
                    container_exists=row.get("container_exists"),
                    running=row.get("running"),
                    pulled=row.get("pulled"),
                )
            )
            if verbose:
                print(f"    compose={row.get('compose')}")

    missing = rv.get("missing") if isinstance(rv.get("missing"), list) else []
    if missing:
        print("Missing inject/artifact paths (all):" if verbose else "Missing inject/artifact paths (first 10):")
        to_show = missing if verbose else missing[:10]
        for p in to_show:
            print(f"  - {p}")

    if verbose:
        docker_warnings = docker.get("warnings") if isinstance(docker.get("warnings"), list) else []
        if docker_warnings:
            print("Docker warnings:")
            for w in docker_warnings:
                print(f"  - {w}")

        core_errors = core.get("errors") if isinstance(core.get("errors"), list) else []
        if core_errors:
            print("Core errors:")
            for err in core_errors:
                print(f"  - {err}")

        rv_error = str(rv.get("error") or "").strip()
        if rv_error:
            print("Revalidate endpoint error:")
            print(f"  - {rv_error}")

        present_sample = rv.get("present_sample") if isinstance(rv.get("present_sample"), list) else []
        if present_sample:
            print("Present path sample:")
            for p in present_sample:
                print(f"  - {p}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate that a scenario is running and docker/inject artifacts are healthy via Web UI APIs."
    )
    parser.add_argument(
        "scenario_filename",
        help="Scenario XML filename or path (example: Anatest.xml or outputs/scenarios-.../Anatest.xml)",
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:9090", help="Web UI base URL")
    parser.add_argument("--username", default="coreadmin", help="Web UI username")
    parser.add_argument("--password", default="coreadmin", help="Web UI password")
    parser.add_argument("--scenario", default="", help="Optional scenario label override")
    parser.add_argument("--timeout", type=float, default=25.0, help="HTTP timeout seconds")
    parser.add_argument(
        "--output-json",
        default="",
        help="Optional output JSON report path (default: /tmp/scenario_runtime_validation_<ts>.json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full validation details in terminal output",
    )

    args = parser.parse_args()

    try:
        report = run_validation(
            base_url=str(args.base_url),
            scenario_filename=str(args.scenario_filename),
            username=str(args.username),
            password=str(args.password),
            scenario_name=str(args.scenario).strip() or None,
            timeout_s=float(args.timeout),
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)

    out_path = str(args.output_json or "").strip()
    if not out_path:
        out_path = f"/tmp/scenario_runtime_validation_{int(time.time())}.json"
    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

    _print_summary(report, verbose=bool(args.verbose))
    print("")
    print(f"Report JSON: {out_file}")

    raise SystemExit(0 if bool(report.get("ok")) else 1)


if __name__ == "__main__":
    main()

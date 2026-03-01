from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests


DEFAULT_BASE_URL = "http://127.0.0.1:9090"


PRESET_STEPS: dict[str, list[dict[str, str]]] = {
    "sample": [
        {"id": "binary_embed_text", "kind": "flag-generator"},
        {"id": "nfs_sensitive_file", "kind": "flag-node-generator"},
        {"id": "textfile_username_password", "kind": "flag-generator"},
    ],
    "sample_reverse_nfs_ssh": [
        {"id": "binary_embed_text", "kind": "flag-generator"},
        {"id": "nfs_sensitive_file", "kind": "flag-node-generator"},
        {"id": "textfile_username_password", "kind": "flag-generator"},
    ],
}


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Live smoke check for flag generator + flag-node-generator CORE credential test flows.",
    )
    parser.add_argument("--base-url", default=os.getenv("CORETG_WEB_BASE", DEFAULT_BASE_URL))
    parser.add_argument("--username", default=os.getenv("CORETG_WEB_USER", "coreadmin"))
    parser.add_argument("--password", default=os.getenv("CORETG_WEB_PASS", "coreadmin"))
    parser.add_argument("--core-secret-id", default=os.getenv("CORETG_CORE_SECRET_ID", ""))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("CORETG_SMOKE_TIMEOUT", "20")))
    parser.add_argument("--poll-seconds", type=int, default=int(os.getenv("CORETG_SMOKE_POLL_SECONDS", "30")))
    parser.add_argument("--allow-pending", action="store_true", default=_truthy(os.getenv("CORETG_SMOKE_ALLOW_PENDING", "1")))
    parser.add_argument("--preset", default=os.getenv("CORETG_SMOKE_PRESET", "sample"))
    return parser.parse_args()


def _log(msg: str) -> None:
    print(msg, flush=True)


def _parse_missing_fields(error_text: str) -> list[str]:
    marker = "Missing required input(s):"
    if marker not in error_text:
        return []
    raw = error_text.split(marker, 1)[-1].strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _placeholder_for_field(field_name: str) -> str:
    key = field_name.strip().lower()
    if key == "seed":
        return "12345"
    if key == "node_name":
        return "node-1"
    if key == "flag_prefix":
        return "FLAG"
    if key.endswith("_port"):
        return "8080"
    return "test"


def _load_core_cfg_from_secret(
    session: requests.Session,
    *,
    base_url: str,
    timeout: float,
    secret_id: str,
) -> dict[str, Any] | None:
    candidate_ids: list[str] = []
    preferred = str(secret_id or "").strip()
    if preferred:
        candidate_ids.append(preferred)

    hint_path = Path("outputs") / "flag_generators_test_core_hint.json"
    try:
        if hint_path.is_file():
            hint_payload = json.loads(hint_path.read_text(encoding="utf-8"))
            if isinstance(hint_payload, dict):
                hinted_id = str(hint_payload.get("core_secret_id") or "").strip()
                if hinted_id and hinted_id not in candidate_ids:
                    candidate_ids.append(hinted_id)
    except Exception:
        pass

    secret_dir = Path("outputs/secrets/core")
    if secret_dir.is_dir():
        for p in sorted(secret_dir.glob("*.json")):
            sid = p.stem
            if sid and sid not in candidate_ids:
                candidate_ids.append(sid)

    _log(f"CORE_SECRET_COUNT={len(candidate_ids)}")
    for sid in candidate_ids:
        try:
            response = session.post(
                f"{base_url}/api/core/credentials/get",
                json={"core_secret_id": sid},
                timeout=timeout,
            )
            if response.status_code != 200:
                continue
            payload = response.json() if "json" in (response.headers.get("content-type", "").lower()) else {}
            creds = payload.get("credentials") if isinstance(payload, dict) else {}
            creds = creds if isinstance(creds, dict) else {}

            ssh_host = str(creds.get("ssh_host") or creds.get("host") or "").strip()
            ssh_user = str(creds.get("ssh_username") or "").strip()
            ssh_password = str(creds.get("ssh_password") or "").strip()
            if not (ssh_host and ssh_user and ssh_password):
                continue

            core_cfg: dict[str, Any] = {
                "ssh_host": ssh_host,
                "ssh_port": int(creds.get("ssh_port") or 22),
                "ssh_username": ssh_user,
                "ssh_password": ssh_password,
                "host": str(creds.get("host") or ssh_host),
                "port": int(creds.get("port") or 50051),
            }
            venv_bin = str(creds.get("venv_bin") or "").strip()
            if venv_bin:
                core_cfg["venv_bin"] = venv_bin
            _log(f"USING_CORE_SECRET={sid}")
            return core_cfg
        except Exception as exc:
            _log(f"SECRET_READ_ERR={sid} {exc}")

    return None


def _available_generator_ids(session: requests.Session, *, base_url: str, endpoint: str, timeout: float) -> list[str]:
    response = session.get(f"{base_url}{endpoint}", timeout=timeout)
    _log(f"{endpoint}_STATUS={response.status_code}")
    if response.status_code != 200:
        return []
    payload = response.json() if "json" in (response.headers.get("content-type", "").lower()) else {}
    generators = payload.get("generators") if isinstance(payload, dict) else None
    if not isinstance(generators, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in generators:
        if not isinstance(item, dict):
            continue
        gid = str(item.get("id") or "").strip()
        if gid and gid not in seen:
            seen.add(gid)
            out.append(gid)
    return out


def _preset_preferred_ids(preset: str, *, kind: str) -> list[str]:
    p = str(preset or "").strip().lower()
    steps = PRESET_STEPS.get(p) or []
    out: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        if str(step.get("kind") or "").strip() != kind:
            continue
        gid = str(step.get("id") or "").strip()
        if gid:
            out.append(gid)
    return out


def _ordered_candidates(available_ids: list[str], preferred_ids: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    avail_set = set(available_ids)
    for gid in preferred_ids:
        if gid in avail_set and gid not in seen:
            seen.add(gid)
            out.append(gid)
    for gid in available_ids:
        if gid not in seen:
            seen.add(gid)
            out.append(gid)
    return out


def _run_single(
    session: requests.Session,
    *,
    base_url: str,
    path_prefix: str,
    generator_id: str,
    core_cfg: dict[str, Any],
    timeout: float,
    poll_seconds: int,
    allow_pending: bool,
) -> bool:
    def _post_run(form_data: dict[str, str]) -> tuple[int, dict[str, Any]]:
        response = session.post(f"{base_url}{path_prefix}/run", data=form_data, timeout=max(timeout, 60.0))
        status = int(response.status_code)
        payload = response.json() if "json" in (response.headers.get("content-type", "").lower()) else {}
        return status, payload if isinstance(payload, dict) else {}

    form_data = {
        "generator_id": generator_id,
        "core": json.dumps(core_cfg, ensure_ascii=False),
    }
    status, run_payload = _post_run(form_data)
    _log(f"{path_prefix}_RUN_STATUS={status}")
    _log(f"{path_prefix}_RUN_JSON={json.dumps(run_payload)[:1200]}")

    if not run_payload.get("ok"):
        missing_fields = _parse_missing_fields(str(run_payload.get("error") or ""))
        if missing_fields:
            for field in missing_fields:
                form_data[field] = _placeholder_for_field(field)
            status, run_payload = _post_run(form_data)
            _log(f"{path_prefix}_RETRY_STATUS={status}")
            _log(f"{path_prefix}_RETRY_JSON={json.dumps(run_payload)[:1200]}")

    if not run_payload.get("ok"):
        return False

    run_id = str(run_payload.get("run_id") or "").strip()
    if not run_id:
        _log(f"{path_prefix}_ERROR=missing_run_id")
        return False

    done = False
    outputs_seen = False
    return_code: Any = None

    for _ in range(max(1, poll_seconds)):
        time.sleep(1)
        response = session.get(f"{base_url}{path_prefix}/outputs/{run_id}", timeout=timeout)
        if response.status_code != 200:
            continue
        payload = response.json() if "json" in (response.headers.get("content-type", "").lower()) else {}
        if isinstance(payload, dict):
            outputs_seen = True
            done = bool(payload.get("done"))
            return_code = payload.get("returncode")
            if done:
                break

    _log(f"{path_prefix}_DONE={done} RETURNCODE={return_code}")
    cleanup_ok = False
    try:
        response = session.post(f"{base_url}{path_prefix}/cleanup/{run_id}", timeout=max(timeout, 40.0))
        cleanup_ok = response.status_code == 200
        _log(f"{path_prefix}_CLEANUP_STATUS={response.status_code}")
    except Exception as exc:
        _log(f"{path_prefix}_CLEANUP_ERR={exc}")

    if done:
        return cleanup_ok
    if allow_pending:
        return outputs_seen and cleanup_ok
    return False


def main() -> int:
    args = _parse_args()
    base_url = str(args.base_url).rstrip("/")

    session = requests.Session()
    login = session.post(
        f"{base_url}/login",
        data={"username": args.username, "password": args.password},
        allow_redirects=False,
        timeout=args.timeout,
    )
    _log(f"LOGIN_STATUS={login.status_code}")
    if login.status_code not in (200, 302):
        _log("LOGIN_FAILED")
        return 10

    core_cfg = _load_core_cfg_from_secret(
        session,
        base_url=base_url,
        timeout=args.timeout,
        secret_id=args.core_secret_id,
    )
    if not core_cfg:
        _log("NO_USABLE_CORE_SECRET")
        return 11

    flag_ids = _available_generator_ids(session, base_url=base_url, endpoint="/flag_generators_data", timeout=args.timeout)
    node_ids = _available_generator_ids(session, base_url=base_url, endpoint="/flag_node_generators_data", timeout=args.timeout)

    preset_flag_ids = _preset_preferred_ids(args.preset, kind="flag-generator")
    preset_node_ids = _preset_preferred_ids(args.preset, kind="flag-node-generator")

    flag_candidates = _ordered_candidates(flag_ids, preset_flag_ids)
    node_candidates = _ordered_candidates(node_ids, preset_node_ids)

    _log(f"SMOKE_PRESET={args.preset}")
    _log(f"PRESET_FLAG_IDS={preset_flag_ids}")
    _log(f"PRESET_NODE_IDS={preset_node_ids}")
    _log(f"FLAG_GENERATOR_CANDIDATES={flag_candidates}")
    _log(f"FLAG_NODE_GENERATOR_CANDIDATES={node_candidates}")

    if not flag_candidates or not node_candidates:
        _log("MISSING_GENERATOR_IDS")
        return 12

    ok_flag = False
    selected_flag_id = ""
    for candidate in flag_candidates:
        selected_flag_id = candidate
        _log(f"FLAG_GENERATOR_ID={candidate}")
        ok_flag = _run_single(
            session,
            base_url=base_url,
            path_prefix="/flag_generators_test",
            generator_id=candidate,
            core_cfg=core_cfg,
            timeout=args.timeout,
            poll_seconds=args.poll_seconds,
            allow_pending=args.allow_pending,
        )
        if ok_flag:
            break

    ok_node = False
    selected_node_id = ""
    for candidate in node_candidates:
        selected_node_id = candidate
        _log(f"FLAG_NODE_GENERATOR_ID={candidate}")
        ok_node = _run_single(
            session,
            base_url=base_url,
            path_prefix="/flag_node_generators_test",
            generator_id=candidate,
            core_cfg=core_cfg,
            timeout=args.timeout,
            poll_seconds=args.poll_seconds,
            allow_pending=args.allow_pending,
        )
        if ok_node:
            break

    _log(f"FLAG_GENERATOR_SELECTED={selected_flag_id}")
    _log(f"FLAG_NODE_GENERATOR_SELECTED={selected_node_id}")

    _log(f"FLAG_TEST_OK={ok_flag}")
    _log(f"FLAG_NODE_TEST_OK={ok_node}")
    return 0 if (ok_flag and ok_node) else 13


if __name__ == "__main__":
    raise SystemExit(main())

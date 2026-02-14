#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, '..'))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from webapp import app_backend as backend


MOUNT_DIRS = ("exports", "outputs", "inputs")


def _normalize_mount_like_path(raw: Any, repo_root: str) -> str:
    try:
        s = str(raw or "").strip()
    except Exception:
        return ""
    if not s:
        return ""

    s_norm = s.replace("\\", "/")

    for mount in MOUNT_DIRS:
        mount_abs = f"/{mount}"
        if s_norm == mount_abs or s_norm.startswith(mount_abs + "/"):
            return s_norm

    rr = repo_root.replace("\\", "/").rstrip("/")
    if rr and s_norm.startswith(rr + "/"):
        rel = s_norm[len(rr) + 1 :]
        for mount in MOUNT_DIRS:
            if rel == mount or rel.startswith(mount + "/"):
                return "/" + rel

    return s_norm


def _normalize_inject_spec(raw_spec: Any, repo_root: str) -> str:
    text = str(raw_spec or "").strip()
    if not text:
        return ""
    for sep in ("->", "=>"):
        if sep in text:
            left, right = text.split(sep, 1)
            left_n = _normalize_mount_like_path(left.strip(), repo_root)
            right_s = right.strip()
            return f"{left_n} {sep} {right_s}" if right_s else left_n
    return _normalize_mount_like_path(text, repo_root)


def _normalize_assignment(assignment: dict[str, Any], repo_root: str) -> tuple[dict[str, Any], bool, list[str]]:
    out = dict(assignment)
    changed = False
    notes: list[str] = []

    inject_files = out.get("inject_files") if isinstance(out.get("inject_files"), list) else None
    if isinstance(inject_files, list):
        new_specs: list[Any] = []
        for spec in inject_files:
            if isinstance(spec, str):
                n = _normalize_inject_spec(spec, repo_root)
                if n != spec:
                    changed = True
                    notes.append(f"inject_files: {spec} -> {n}")
                new_specs.append(n)
            else:
                new_specs.append(spec)
        out["inject_files"] = new_specs

    detail = out.get("inject_files_detail") if isinstance(out.get("inject_files_detail"), list) else None
    if isinstance(detail, list):
        fixed_detail: list[Any] = []
        for item in detail:
            if not isinstance(item, dict):
                fixed_detail.append(item)
                continue
            d2 = dict(item)
            for key in ("field", "path", "resolved"):
                val = d2.get(key)
                if isinstance(val, str):
                    n = _normalize_mount_like_path(val, repo_root)
                    if n != val:
                        changed = True
                        notes.append(f"inject_files_detail.{key}: {val} -> {n}")
                        d2[key] = n
            try:
                old_path = str(item.get("path") or "")
                new_path = str(d2.get("path") or "")
                if old_path and new_path and old_path != new_path:
                    for id_key in ("id", "var_id"):
                        idv = d2.get(id_key)
                        if isinstance(idv, str) and old_path in idv:
                            d2[id_key] = idv.replace(old_path, new_path)
                            changed = True
            except Exception:
                pass
            fixed_detail.append(d2)
        out["inject_files_detail"] = fixed_detail

    live = out.get("live_paths") if isinstance(out.get("live_paths"), dict) else None
    if isinstance(live, dict):
        live2 = dict(live)
        srcs = live2.get("inject_sources") if isinstance(live2.get("inject_sources"), list) else None
        if isinstance(srcs, list):
            new_srcs: list[Any] = []
            for src in srcs:
                if not isinstance(src, dict):
                    new_srcs.append(src)
                    continue
                s2 = dict(src)
                p = s2.get("path")
                if isinstance(p, str):
                    n = _normalize_mount_like_path(p, repo_root)
                    if n != p:
                        changed = True
                        notes.append(f"live_paths.inject_sources.path: {p} -> {n}")
                        s2["path"] = n
                new_srcs.append(s2)
            live2["inject_sources"] = new_srcs
        out["live_paths"] = live2

    return out, changed, notes


def _normalize_plan_preview_payload(value: Any, repo_root: str) -> tuple[Any, bool]:
    changed = False

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if k == "inject_files" and isinstance(v, list):
                fixed_list: list[Any] = []
                for item in v:
                    if isinstance(item, str):
                        n = _normalize_inject_spec(item, repo_root)
                        if n != item:
                            changed = True
                        fixed_list.append(n)
                    else:
                        vv, cc = _normalize_plan_preview_payload(item, repo_root)
                        changed = changed or cc
                        fixed_list.append(vv)
                out[k] = fixed_list
                continue

            if k in {"field", "path", "resolved"} and isinstance(v, str):
                n = _normalize_mount_like_path(v, repo_root)
                if n != v:
                    changed = True
                out[k] = n
                continue

            vv, cc = _normalize_plan_preview_payload(v, repo_root)
            changed = changed or cc
            out[k] = vv
        return out, changed

    if isinstance(value, list):
        out_list: list[Any] = []
        for item in value:
            vv, cc = _normalize_plan_preview_payload(item, repo_root)
            changed = changed or cc
            out_list.append(vv)
        return out_list, changed

    return value, False


def migrate_file(xml_path: str, repo_root: str, *, dry_run: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "xml_path": xml_path,
        "changed": False,
        "skipped": False,
        "scenarios_changed": 0,
        "assignments_changed": 0,
        "plan_scenarios_changed": 0,
        "plan_assignments_changed": 0,
        "notes": [],
    }

    try:
        parsed = backend._parse_scenarios_xml(xml_path)
    except Exception:
        result["skipped"] = True
        return result
    scenarios = parsed.get("scenarios") if isinstance(parsed, dict) else None
    if not isinstance(scenarios, list):
        return result

    for scen in scenarios:
        if not isinstance(scen, dict):
            continue
        scenario_name = str(scen.get("name") or "").strip()
        flow_state = scen.get("flow_state") if isinstance(scen.get("flow_state"), dict) else None
        if isinstance(flow_state, dict):
            assignments = flow_state.get("flag_assignments") if isinstance(flow_state.get("flag_assignments"), list) else None
            if not isinstance(assignments, list):
                assignments = []

            flow2 = dict(flow_state)
            out_assignments: list[Any] = []
            scen_changed = False

            for idx, a in enumerate(assignments):
                if not isinstance(a, dict):
                    out_assignments.append(a)
                    continue
                fixed, changed, notes = _normalize_assignment(a, repo_root)
                out_assignments.append(fixed)
                if changed:
                    scen_changed = True
                    result["assignments_changed"] += 1
                    for note in notes:
                        result["notes"].append(f"{scenario_name} [#{idx}] {note}")

            if scen_changed:
                flow2["flag_assignments"] = out_assignments
                result["changed"] = True
                result["scenarios_changed"] += 1
                if not dry_run:
                    ok, msg = backend._update_flow_state_in_xml(xml_path, scenario_name, flow2)
                    if not ok:
                        raise RuntimeError(f"failed updating {xml_path} ({scenario_name}): {msg}")

        plan_preview = scen.get("plan_preview") if isinstance(scen.get("plan_preview"), dict) else None
        if isinstance(plan_preview, dict):
            plan2, plan_changed = _normalize_plan_preview_payload(plan_preview, repo_root)
            if plan_changed:
                result["changed"] = True
                result["plan_scenarios_changed"] += 1
                # Best-effort accounting: count flag assignments if present.
                try:
                    pmeta = plan2.get("metadata") if isinstance(plan2, dict) else None
                    pflow = pmeta.get("flow") if isinstance(pmeta, dict) else None
                    passigns = pflow.get("flag_assignments") if isinstance(pflow, dict) else None
                    if isinstance(passigns, list):
                        result["plan_assignments_changed"] += len([x for x in passigns if isinstance(x, dict)])
                except Exception:
                    pass
                if not dry_run:
                    ok, msg = backend._update_plan_preview_in_xml(xml_path, scenario_name, plan2 if isinstance(plan2, dict) else plan_preview)
                    if not ok:
                        raise RuntimeError(f"failed updating PlanPreview in {xml_path} ({scenario_name}): {msg}")

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate stale host-local Flow inject paths to VM mount paths.")
    parser.add_argument(
        "--glob",
        dest="glob_pattern",
        default="outputs/scenarios-*/**/*.xml",
        help="Glob pattern for scenario XML files (default: outputs/scenarios-*/**/*.xml)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing files")
    parser.add_argument("--show-notes", action="store_true", help="Print per-change notes")
    args = parser.parse_args()

    repo_root = os.path.abspath(backend._get_repo_root())
    xml_paths = sorted(set(glob.glob(args.glob_pattern, recursive=True)))

    summary = {
        "files_scanned": len(xml_paths),
        "files_skipped": 0,
        "files_changed": 0,
        "scenarios_changed": 0,
        "assignments_changed": 0,
        "plan_scenarios_changed": 0,
        "plan_assignments_changed": 0,
        "changed_files": [],
    }

    all_notes: list[str] = []

    for path in xml_paths:
        try:
            out = migrate_file(path, repo_root, dry_run=bool(args.dry_run))
        except Exception as exc:
            print(json.dumps({"ok": False, "xml_path": path, "error": str(exc)}))
            return 2

        if out.get("skipped"):
            summary["files_skipped"] += 1
            continue

        if out.get("changed"):
            summary["files_changed"] += 1
            summary["scenarios_changed"] += int(out.get("scenarios_changed") or 0)
            summary["assignments_changed"] += int(out.get("assignments_changed") or 0)
            summary["plan_scenarios_changed"] += int(out.get("plan_scenarios_changed") or 0)
            summary["plan_assignments_changed"] += int(out.get("plan_assignments_changed") or 0)
            summary["changed_files"].append(path)
            all_notes.extend(out.get("notes") or [])

    print(json.dumps({"ok": True, "dry_run": bool(args.dry_run), **summary}, indent=2))
    if args.show_notes and all_notes:
        print("--- notes ---")
        for note in all_notes[:400]:
            print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

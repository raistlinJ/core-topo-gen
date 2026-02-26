from __future__ import annotations

import os
from typing import Any, Callable, Optional

from flask import abort, jsonify, redirect, render_template, request


def register(
    app,
    *,
    participant_ui_state_getter: Callable[[], dict[str, Any]],
    normalize_scenario_label: Callable[[Any], str],
    normalize_participant_proxmox_url: Callable[[Any], str],
    load_run_history: Callable[[], list[dict[str, Any]]],
    latest_run_history_for_scenario: Callable[[str, Optional[list[dict[str, Any]]]], Optional[dict[str, Any]]],
    hitl_details_from_path: Callable[[str], Any],
    scenario_catalog_for_user: Callable[..., Any],
    current_user_getter: Callable[[], dict[str, Any] | None],
    nearest_gateway_address_for_scenario: Callable[..., str],
    load_participant_ui_stats: Callable[[], dict[str, Any]],
    save_participant_ui_stats: Callable[[dict[str, Any]], Any],
    local_timestamp_display: Callable[[], str],
    load_summary_counts: Callable[[Optional[str]], dict[str, Any]],
    load_summary_metadata: Callable[[Optional[str]], dict[str, Any]],
    subnet_cidrs_from_session_xml: Callable[[Optional[str]], list[str]],
    vulnerability_ipv4s_from_session_xml: Callable[[Optional[str]], list[str]],
    counts_from_session_xml: Callable[[Optional[str]], dict[str, Any]],
    recent_session_id_for_scenario: Callable[..., tuple[Optional[int], float]],
    live_core_session_status_for_scenario: Callable[..., Optional[dict[str, Any]]],
    flow_state_from_latest_xml: Callable[[str], dict[str, Any] | None],
    latest_session_xml_for_scenario_norm: Callable[[str], Optional[str]],
    build_topology_graph_from_session_xml: Callable[[str], tuple[list[dict[str, Any]], list[dict[str, Any]], Any]],
) -> None:
    """Register Participant UI endpoints.

    Extracted from `webapp.app_backend`.

    Important: callers should pass late-bound lambdas for helpers that tests monkeypatch
    in `webapp.app_backend` (e.g., `_participant_ui_state`, `_load_run_history`).
    """

    @app.route("/participant-ui")
    def participant_ui_page():
        state = participant_ui_state_getter()
        url_value = state.get("selected_url", "")
        scenario_label = state.get("selected_label", "")
        nearest_gateway = state.get("selected_nearest_gateway", "")
        override = normalize_participant_proxmox_url(request.args.get("url")) if request.args.get("url") else ""
        participant_url = override or url_value
        return render_template(
            "participant_ui.html",
            participant_url=participant_url,
            participant_scenario_label=scenario_label,
            participant_nearest_gateway=nearest_gateway,
            participant_scenarios=state.get("listing", []),
            participant_scenarios_heading=state.get("listing_heading"),
            participant_scenarios_hint=state.get("listing_hint"),
            participant_scenarios_empty=state.get("listing_empty_message"),
            participant_restricted=state.get("restrict_to_assigned", False),
            participant_active_norm=state.get("selected_norm", ""),
            participant_has_assignments=state.get("has_assignments", False),
        )

    @app.route("/participant-ui/gateway")
    def participant_ui_gateway_api():
        state = participant_ui_state_getter()
        scenario_norm = normalize_scenario_label(request.args.get("scenario") or "")
        if not scenario_norm:
            scenario_norm = state.get("selected_norm", "")

        try:
            if state.get("restrict_to_assigned"):
                allowed_norms = {
                    row.get("norm")
                    for row in (state.get("listing") or [])
                    if isinstance(row, dict) and row.get("norm")
                }
                if scenario_norm and scenario_norm not in allowed_norms:
                    return jsonify({"ok": False, "error": "Scenario not assigned."}), 403
        except Exception:
            pass

        gateway = ""

        try:
            history = load_run_history()
            last_run = latest_run_history_for_scenario(scenario_norm, history)
        except Exception:
            last_run = None

        session_xml_path = None
        if isinstance(last_run, dict):
            session_xml_path = last_run.get("session_xml_path") or last_run.get("post_xml_path")

        if session_xml_path:
            try:
                hitl = hitl_details_from_path(str(session_xml_path))
                first = hitl[0] if isinstance(hitl, list) and hitl else None
                ips = first.get("ips") if isinstance(first, dict) else None
                if isinstance(ips, list) and ips:
                    gateway = str(ips[0]).split("/", 1)[0]
            except Exception:
                gateway = ""

        if not gateway:
            if scenario_norm and scenario_norm == state.get("selected_norm", ""):
                gateway = state.get("selected_nearest_gateway", "")
            else:
                try:
                    _names, scenario_paths, _scenario_url_hints = scenario_catalog_for_user(
                        None,
                        user=current_user_getter(),
                    )
                except Exception:
                    scenario_paths = {}
                gateway = nearest_gateway_address_for_scenario(scenario_norm, scenario_paths=scenario_paths)

        return jsonify({"ok": True, "scenario_norm": scenario_norm, "nearest_gateway": gateway or ""})

    @app.route("/participant-ui/details")
    def participant_ui_details_api():
        state = participant_ui_state_getter()
        scenario_norm = normalize_scenario_label(request.args.get("scenario") or "")
        if not scenario_norm:
            scenario_norm = normalize_scenario_label(state.get("selected_norm", ""))

        listing = state.get("listing", [])
        listing_entry: Optional[dict[str, Any]] = None
        if isinstance(listing, list) and scenario_norm:
            for entry in listing:
                if isinstance(entry, dict) and (entry.get("norm") or "") == scenario_norm:
                    listing_entry = entry
                    break

        display = ""
        has_url = False
        assigned = False
        placeholder = False
        if isinstance(listing_entry, dict):
            display = str(listing_entry.get("display") or "")
            has_url = bool(listing_entry.get("has_url"))
            assigned = bool(listing_entry.get("assigned"))
            placeholder = bool(listing_entry.get("placeholder"))

        stats = load_participant_ui_stats()
        scenarios_stats = stats.get("scenarios") if isinstance(stats.get("scenarios"), dict) else {}
        scenario_stats = scenarios_stats.get(scenario_norm, {}) if scenario_norm else {}
        if not isinstance(scenario_stats, dict):
            scenario_stats = {}

        history = load_run_history()
        last_run = latest_run_history_for_scenario(scenario_norm, history)
        last_execute_ts = (last_run or {}).get("timestamp") if isinstance(last_run, dict) else ""
        returncode = (last_run or {}).get("returncode") if isinstance(last_run, dict) else None
        try:
            returncode_int = int(returncode) if returncode is not None else None
        except Exception:
            returncode_int = None
        last_execute_ok = (returncode_int == 0) if returncode_int is not None else None

        summary_path = (last_run or {}).get("summary_path") if isinstance(last_run, dict) else None
        summary_counts = load_summary_counts(summary_path)
        summary_meta = load_summary_metadata(summary_path)

        nodes_total = summary_counts.get("total_nodes")
        routers_total = summary_counts.get("routers")
        switches_total = summary_counts.get("switches")
        try:
            nodes_total = int(nodes_total) if nodes_total is not None else None
        except Exception:
            nodes_total = None
        try:
            routers_total = int(routers_total) if routers_total is not None else None
        except Exception:
            routers_total = None
        try:
            switches_total = int(switches_total) if switches_total is not None else None
        except Exception:
            switches_total = None

        session_xml_path = None
        if isinstance(last_run, dict):
            session_xml_path = last_run.get("session_xml_path") or last_run.get("post_xml_path")
        session_xml_exists = bool(session_xml_path and os.path.exists(str(session_xml_path)))
        subnetworks = subnet_cidrs_from_session_xml(session_xml_path) if session_xml_exists else []
        vulnerability_ips = vulnerability_ipv4s_from_session_xml(session_xml_path) if session_xml_exists else []

        vuln_total: Optional[int] = None
        xml_exists = False
        try:
            xml_exists = bool(session_xml_path and os.path.exists(str(session_xml_path)))
        except Exception:
            xml_exists = False
        if xml_exists:
            vuln_total = len(vulnerability_ips)
        else:
            planned = summary_meta.get("vuln_total_planned_additive") if isinstance(summary_meta, dict) else None
            try:
                vuln_total = int(planned) if planned is not None else None
            except Exception:
                vuln_total = None

        gateway = ""
        if session_xml_path:
            try:
                hitl = hitl_details_from_path(str(session_xml_path))
                first = hitl[0] if isinstance(hitl, list) and hitl else None
                ips = first.get("ips") if isinstance(first, dict) else None
                if isinstance(ips, list) and ips:
                    gateway = str(ips[0]).split("/", 1)[0]
            except Exception:
                gateway = ""

        if not gateway:
            if scenario_norm and scenario_norm == normalize_scenario_label(state.get("selected_norm", "")):
                gateway = str(state.get("selected_nearest_gateway") or "")
            else:
                try:
                    _names, scenario_paths, _scenario_url_hints = scenario_catalog_for_user(
                        None,
                        user=current_user_getter(),
                    )
                except Exception:
                    scenario_paths = {}
                gateway = (
                    nearest_gateway_address_for_scenario(scenario_norm, scenario_paths=scenario_paths)
                    if scenario_norm
                    else ""
                )

        xml_counts = counts_from_session_xml(session_xml_path)
        if isinstance(xml_counts.get("nodes"), int):
            nodes_total = xml_counts.get("nodes")
        if isinstance(xml_counts.get("routers"), int):
            routers_total = xml_counts.get("routers")
        if isinstance(xml_counts.get("switches"), int):
            switches_total = xml_counts.get("switches")

        session_running: Optional[bool] = None
        session_state = ""
        session_id: Optional[int] = None
        try:
            scenario_names_live, scenario_paths_live, _scenario_url_hints_live = scenario_catalog_for_user(
                history,
                user=current_user_getter(),
            )
        except Exception:
            scenario_names_live, scenario_paths_live = [], {}

        live = live_core_session_status_for_scenario(
            scenario_norm,
            history=history,
            scenario_names=scenario_names_live,
            scenario_paths=scenario_paths_live,
        )

        if isinstance(live, dict):
            running_val = live.get("running")
            session_running = running_val if isinstance(running_val, bool) else None
            session_state = str(live.get("state") or "")
            sid_val = live.get("session_id")
            try:
                session_id = int(sid_val) if sid_val is not None else None
            except Exception:
                session_id = None
        else:
            session_running = None

        if session_id is None:
            try:
                session_id, _last_seen = recent_session_id_for_scenario(
                    scenario_norm,
                    scenario_paths=scenario_paths_live,
                )
            except Exception:
                session_id = None

        return jsonify(
            {
                "ok": True,
                "scenario_norm": scenario_norm,
                "scenario": {
                    "display": display,
                    "assigned": assigned,
                    "placeholder": placeholder,
                    "participant_link_configured": bool(has_url),
                },
                "gateway": gateway or "",
                "open_stats": {
                    "open_count": int(scenario_stats.get("open_count") or 0),
                    "last_open_ts": str(scenario_stats.get("last_open_ts") or ""),
                },
                "execute": {
                    "last_execute_ts": str(last_execute_ts or ""),
                    "returncode": returncode_int,
                    "ok": last_execute_ok,
                },
                "session": {
                    "session_id": session_id,
                    "running": session_running,
                    "state": session_state,
                },
                "counts": {
                    "nodes": nodes_total,
                    "routers": routers_total,
                    "switches": switches_total,
                    "vulnerabilities": vuln_total,
                },
                "subnetworks": subnetworks,
                "vulnerability_ips": vulnerability_ips,
            }
        )

    @app.route("/participant-ui/topology")
    def participant_ui_topology_api():
        """Return a graph-friendly topology summary for the Participant UI."""
        state = participant_ui_state_getter()
        scenario_norm = normalize_scenario_label(request.args.get("scenario") or "")
        if not scenario_norm:
            scenario_norm = normalize_scenario_label(state.get("selected_norm", ""))

        try:
            if state.get("restrict_to_assigned"):
                allowed_norms = {
                    row.get("norm")
                    for row in (state.get("listing") or [])
                    if isinstance(row, dict) and row.get("norm")
                }
                if scenario_norm and scenario_norm not in allowed_norms:
                    return jsonify({"ok": False, "error": "Scenario not assigned."}), 403
        except Exception:
            pass

        flow_meta: dict[str, Any] | None = None
        try:
            if scenario_norm:
                flow_meta = flow_state_from_latest_xml(scenario_norm)
        except Exception:
            flow_meta = None

        xml_path = None
        try:
            if scenario_norm:
                xml_path = latest_session_xml_for_scenario_norm(scenario_norm)
        except Exception:
            xml_path = None

        if not xml_path or not os.path.exists(str(xml_path)):
            out: dict[str, Any] = {
                "ok": True,
                "scenario_norm": scenario_norm,
                "status": "No session XML found",
                "nodes": [],
                "links": [],
                "subnets": [],
                "vulnerability_ips": [],
            }
            if isinstance(flow_meta, dict) and flow_meta:
                out["flow"] = flow_meta
            return jsonify(out)

        nodes, links, _adj = build_topology_graph_from_session_xml(str(xml_path))
        subnets = subnet_cidrs_from_session_xml(str(xml_path))
        vuln_ips = vulnerability_ipv4s_from_session_xml(str(xml_path))

        out = {
            "ok": True,
            "scenario_norm": scenario_norm,
            "status": "",
            "nodes": nodes,
            "links": links,
            "subnets": subnets,
            "vulnerability_ips": vuln_ips,
        }
        if isinstance(flow_meta, dict) and flow_meta:
            out["flow"] = flow_meta
        return jsonify(out)

    @app.route("/participant-ui/stats")
    def participant_ui_stats_api():
        scenario_norm = normalize_scenario_label(request.args.get("scenario") or "")
        if not scenario_norm:
            try:
                scenario_norm = normalize_scenario_label(participant_ui_state_getter().get("selected_norm", ""))
            except Exception:
                scenario_norm = ""

        stats = load_participant_ui_stats()
        scenarios = stats.get("scenarios") if isinstance(stats.get("scenarios"), dict) else {}
        scenario_stats = scenarios.get(scenario_norm, {}) if scenario_norm else {}
        if not isinstance(scenario_stats, dict):
            scenario_stats = {}
        totals = stats.get("totals") if isinstance(stats.get("totals"), dict) else {}
        return jsonify(
            {
                "ok": True,
                "scenario_norm": scenario_norm,
                "scenario": {
                    "open_count": int(scenario_stats.get("open_count") or 0),
                    "last_open_ts": scenario_stats.get("last_open_ts") or "",
                },
                "totals": {
                    "open_count": int(totals.get("open_count") or 0),
                    "last_open_ts": totals.get("last_open_ts") or "",
                },
            }
        )

    @app.route("/participant-ui/record-open", methods=["POST"])
    def participant_ui_record_open_api():
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            payload = {}

        scenario_norm = normalize_scenario_label(payload.get("scenario_norm") or "")
        href_raw = (payload.get("href") or "").strip()
        href = normalize_participant_proxmox_url(href_raw)
        if not href and href_raw.startswith("/participant-ui/"):
            href = href_raw
        if not href:
            return jsonify({"ok": False, "error": "missing href"}), 400

        now = local_timestamp_display()
        stats = load_participant_ui_stats()
        totals = stats.get("totals") if isinstance(stats.get("totals"), dict) else {}
        totals["open_count"] = int(totals.get("open_count") or 0) + 1
        totals["last_open_ts"] = now
        stats["totals"] = totals

        if scenario_norm:
            scenarios = stats.get("scenarios") if isinstance(stats.get("scenarios"), dict) else {}
            entry = scenarios.get(scenario_norm)
            if not isinstance(entry, dict):
                entry = {}
            entry["open_count"] = int(entry.get("open_count") or 0) + 1
            entry["last_open_ts"] = now
            scenarios[scenario_norm] = entry
            stats["scenarios"] = scenarios

        save_participant_ui_stats(stats)

        return jsonify(
            {
                "ok": True,
                "scenario_norm": scenario_norm,
                "last_open_ts": now,
                "totals": stats.get("totals", {}),
                "scenario": (stats.get("scenarios", {}) or {}).get(scenario_norm, {}) if scenario_norm else {},
            }
        )

    @app.route("/participant-ui/open")
    def participant_ui_open_redirect():
        scenario_norm = normalize_scenario_label(request.args.get("scenario") or "")
        state = participant_ui_state_getter()
        resolved = ""
        try:
            listing = state.get("listing", [])
            if isinstance(listing, list) and scenario_norm:
                for entry in listing:
                    if not isinstance(entry, dict):
                        continue
                    if (entry.get("norm") or "") == scenario_norm and entry.get("url"):
                        resolved = str(entry.get("url") or "")
                        break
        except Exception:
            resolved = ""

        if not resolved:
            try:
                resolved = str(state.get("selected_url") or "")
            except Exception:
                resolved = ""

        resolved = normalize_participant_proxmox_url(resolved)
        if not resolved:
            abort(404)

        return redirect(resolved)

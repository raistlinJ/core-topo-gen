from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, request


def register(
    app,
    *,
    planner_persist_flow_plan: Callable[..., dict[str, Any]],
    normalize_scenario_label: Callable[[Any], str],
    latest_xml_path_for_scenario: Callable[[str], str],
) -> None:
    """Register planner endpoints.

    Extracted from `webapp.app_backend`.
    """

    @app.route("/api/planner/ensure_plan", methods=["POST"])
    def api_planner_ensure_plan():
        j = request.get_json(silent=True) or {}
        xml_path = str(j.get("xml_path") or "").strip()
        scenario = str(j.get("scenario") or "").strip() or None
        seed = j.get("seed")
        try:
            if seed is not None:
                seed = int(seed)
        except Exception:
            seed = None

        if not xml_path:
            return jsonify({"ok": False, "error": "xml_path required"}), 400

        try:
            result = planner_persist_flow_plan(
                xml_path=xml_path,
                scenario=scenario,
                seed=seed,
                persist_plan_file=False,
            )
            return jsonify(
                {
                    "ok": True,
                    "xml_path": result.get("xml_path"),
                    "scenario": result.get("scenario"),
                    "seed": result.get("seed"),
                    "preview_plan_path": result.get("preview_plan_path"),
                }
            )
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.route("/api/planner/latest_plan", methods=["GET"])
    def api_planner_latest_plan():
        scenario = str(request.args.get("scenario") or "").strip()
        scenario_norm = normalize_scenario_label(scenario)
        if not scenario_norm:
            return jsonify({"ok": False, "error": "scenario required"}), 400

        xml_path = latest_xml_path_for_scenario(scenario_norm)
        if xml_path:
            return jsonify({"ok": True, "preview_plan_path": xml_path, "xml_path": xml_path})

        return jsonify({"ok": False, "error": "No XML found for scenario."}), 404

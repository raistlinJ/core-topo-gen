from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, request


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    normalize_role_value: Callable[[Any], str],
    clear_hitl_config_in_scenario_catalog: Callable[..., Any],
    logger=None,
) -> None:
    """Register small HITL clear endpoints.

    Extracted from `webapp.app_backend` as a low-risk first HITL refactor step.
    """

    log = logger or getattr(app, "logger", None)

    def _require_admin():
        current = current_user_getter()
        if not current or normalize_role_value(current.get("role")) != "admin":
            return jsonify({"success": False, "error": "Admin privileges required"}), 403
        return None

    @app.route("/api/hitl/core_vm/clear", methods=["POST"])
    def api_hitl_core_vm_clear():
        denied = _require_admin()
        if denied is not None:
            return denied

        payload = request.get_json(silent=True) or {}
        scenario_name = str(payload.get("scenario_name") or payload.get("scenario") or "").strip()
        scenario_index = payload.get("scenario_index")
        if not scenario_name:
            return jsonify({"success": False, "error": "scenario_name is required"}), 400

        try:
            clear_hitl_config_in_scenario_catalog(scenario_name, clear_core_vm=True)
        except Exception:
            try:
                if log is not None:
                    log.exception("[hitl] failed clearing CORE VM selection for %s", scenario_name)
            except Exception:
                pass
            return jsonify({"success": False, "error": "Failed to clear CORE VM selection"}), 500

        return jsonify({"success": True, "scenario_name": scenario_name, "scenario_index": scenario_index})

    @app.route("/api/hitl/config/clear", methods=["POST"])
    def api_hitl_config_clear():
        denied = _require_admin()
        if denied is not None:
            return denied

        payload = request.get_json(silent=True) or {}
        scenario_name = str(payload.get("scenario_name") or payload.get("scenario") or "").strip()
        scenario_index = payload.get("scenario_index")
        if not scenario_name:
            return jsonify({"success": False, "error": "scenario_name is required"}), 400

        try:
            clear_hitl_config_in_scenario_catalog(scenario_name, clear_config=True)
        except Exception:
            try:
                if log is not None:
                    log.exception("[hitl] failed clearing HITL config for %s", scenario_name)
            except Exception:
                pass
            return jsonify({"success": False, "error": "Failed to clear HITL config"}), 500

        return jsonify({"success": True, "scenario_name": scenario_name, "scenario_index": scenario_index})

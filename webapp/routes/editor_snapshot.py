from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, request


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    build_editor_snapshot_payload: Callable[[dict[str, Any]], dict[str, Any] | None],
    write_editor_state_snapshot: Callable[..., Any],
    logger=None,
) -> None:
    """Register editor snapshot endpoint.

    Extracted from `webapp.app_backend`.
    """

    log = logger or getattr(app, "logger", None)

    @app.route("/api/editor_snapshot", methods=["POST"])
    def api_editor_snapshot():
        user = current_user_getter()
        if not user or not user.get("username"):
            return jsonify({"success": False, "error": "Authentication required"}), 401

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Invalid snapshot payload"}), 400

        snapshot = build_editor_snapshot_payload(payload)
        if not snapshot:
            return jsonify({"success": False, "error": "Snapshot rejected"}), 400

        try:
            write_editor_state_snapshot(snapshot, user=user)
        except Exception as exc:
            try:
                if log is not None:
                    log.exception("[editor_snapshot] persist failed: %s", exc)
            except Exception:
                pass
            return jsonify({"success": False, "error": "Unable to persist snapshot"}), 500

        return jsonify({"success": True})

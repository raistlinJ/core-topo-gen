from __future__ import annotations

import os
from typing import Any, Callable

from flask import jsonify, request


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    normalize_role_value: Callable[[Any], str],
    webui_log_path_getter: Callable[[], str],
) -> None:
    """Register Web UI log endpoints.

    Extracted from `webapp.app_backend`.
    """

    def _require_admin():
        current = current_user_getter()
        if not current or normalize_role_value(current.get("role")) != "admin":
            return jsonify({"ok": False, "error": "Admin privileges required"}), 403
        return None

    @app.route("/api/webui/log_tail")
    def api_webui_log_tail():
        denied = _require_admin()
        if denied is not None:
            return denied

        try:
            offset = int(request.args.get("offset") or 0)
        except Exception:
            offset = 0
        try:
            max_bytes = int(request.args.get("max_bytes") or 50000)
        except Exception:
            max_bytes = 50000
        max_bytes = max(1024, min(max_bytes, 200000))

        path = webui_log_path_getter()
        if not os.path.exists(path):
            return jsonify({"ok": False, "error": "Web UI log not found", "path": path, "offset": offset}), 404

        try:
            size = os.path.getsize(path)
        except Exception:
            size = 0

        if offset < 0 or offset > size:
            offset = max(size - max_bytes, 0)

        data = b""
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                data = f.read(max_bytes)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"Failed reading log: {exc}", "path": path, "offset": offset}), 500

        new_offset = offset + len(data)
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""

        return jsonify({"ok": True, "offset": new_offset, "text": text})

    @app.route("/api/webui/log_clear", methods=["POST"])
    def api_webui_log_clear():
        denied = _require_admin()
        if denied is not None:
            return denied

        path = webui_log_path_getter()
        if not os.path.exists(path):
            return jsonify({"ok": True, "users_cleared": False})

        try:
            with open(path, "w") as f:
                f.truncate(0)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"Failed clearing log: {exc}"}), 500

        return jsonify({"ok": True})

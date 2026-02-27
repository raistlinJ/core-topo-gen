from __future__ import annotations

from typing import Any, Callable, Optional

from flask import jsonify, request


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    normalize_role_value: Callable[[Any], str],
    proxmox_api_getter: Callable[[], Any],
    urlparse_func: Callable[[str], Any],
    coerce_bool: Callable[[Any], bool],
    load_proxmox_credentials: Callable[[str], Optional[dict[str, Any]]],
    save_proxmox_credentials: Callable[[dict[str, Any]], dict[str, Any]],
    delete_proxmox_credentials: Callable[[str], bool],
    enumerate_proxmox_vms: Callable[[str], Any],
    merge_hitl_validation_into_scenario_catalog: Callable[..., Any],
    clear_hitl_validation_in_scenario_catalog: Callable[..., Any],
    local_timestamp_display: Callable[[], str],
    logger=None,
) -> None:
    """Register Proxmox endpoints.

    Extracted from `webapp.app_backend` to reduce file size while preserving
    existing behavior.

    Important: `proxmox_api_getter` is used for late-binding so tests can
    monkeypatch `webapp.app_backend.ProxmoxAPI`.
    """

    log = logger or getattr(app, "logger", None)

    def _require_admin():
        current = current_user_getter()
        if not current or normalize_role_value(current.get("role")) != "admin":
            return jsonify({"success": False, "error": "Admin privileges required"}), 403
        return None

    @app.route("/api/proxmox/validate", methods=["POST"])
    def api_proxmox_validate():
        denied = _require_admin()
        if denied is not None:
            return denied

        ProxmoxAPI = proxmox_api_getter()
        if ProxmoxAPI is None:
            return (
                jsonify({"success": False, "error": "Proxmox integration unavailable: install proxmoxer package"}),
                500,
            )

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not payload:
            try:
                payload = request.form.to_dict(flat=True) if request.form else {}
            except Exception:
                payload = {}

        url_raw = str(payload.get("url") or "").strip()
        if not url_raw:
            return jsonify({"success": False, "error": "URL is required"}), 400

        parsed = urlparse_func(url_raw)
        if getattr(parsed, "scheme", None) not in {"http", "https"}:
            return jsonify({"success": False, "error": "URL must start with http:// or https://"}), 400

        host = getattr(parsed, "hostname", None)
        if not host:
            return jsonify({"success": False, "error": "Unable to determine host from URL"}), 400

        try:
            port = int(payload.get("port") or (getattr(parsed, "port", None) or 8006))
        except Exception:
            port = getattr(parsed, "port", None) or 8006

        if port < 1 or port > 65535:
            return jsonify({"success": False, "error": "Port must be between 1 and 65535"}), 400

        username = str(payload.get("username") or "").strip()
        if not username:
            return jsonify({"success": False, "error": "Username is required"}), 400

        password = payload.get("password")
        if password is None:
            password = ""
        if not isinstance(password, str):
            password = str(password)

        verify_ssl_raw = payload.get("verify_ssl")
        reuse_secret_raw = payload.get("reuse_secret_id")
        reuse_secret_id = reuse_secret_raw.strip() if isinstance(reuse_secret_raw, str) else ""
        stored_record: Optional[dict[str, Any]] = None

        if (not password) and reuse_secret_id:
            stored_record = load_proxmox_credentials(reuse_secret_id)
            if not stored_record:
                return jsonify({"success": False, "error": "Stored credentials unavailable. Re-enter the password."}), 400

            stored_password = stored_record.get("password_plain") or ""
            if not stored_password:
                return (
                    jsonify({"success": False, "error": "Stored credentials are missing password material. Re-enter the password."}),
                    400,
                )

            stored_url = (stored_record.get("url") or "").strip()
            stored_username = (stored_record.get("username") or "").strip()
            if stored_url and stored_url != url_raw:
                return jsonify({"success": False, "error": "URL changed since the last validation. Re-enter the password."}), 400
            if stored_username and stored_username != username:
                return jsonify({"success": False, "error": "Username changed since the last validation. Re-enter the password."}), 400

            password = stored_password
            if (stored_record.get("verify_ssl") is not None) and (verify_ssl_raw is None):
                verify_ssl_raw = bool(stored_record.get("verify_ssl"))

        if not password:
            return jsonify({"success": False, "error": "Password is required"}), 400

        if verify_ssl_raw is None:
            verify_ssl = (getattr(parsed, "scheme", "") == "https")
        else:
            verify_ssl = coerce_bool(verify_ssl_raw)

        timeout_val = payload.get("timeout", 5.0)
        try:
            timeout = float(timeout_val)
        except Exception:
            timeout = 5.0
        timeout = max(1.0, min(timeout, 30.0))

        remember_credentials = coerce_bool(payload.get("remember_credentials", True))

        prox_kwargs = {
            "host": host,
            "user": username,
            "password": password,
            "port": port,
            "verify_ssl": verify_ssl,
            "timeout": timeout,
            "backend": "https" if getattr(parsed, "scheme", "") == "https" else "http",
        }

        try:
            if log is not None:
                log.debug(
                    "[proxmox] attempting auth for %s@%s:%s (verify_ssl=%s)",
                    username,
                    host,
                    port,
                    verify_ssl,
                )
        except Exception:
            pass

        try:
            prox = ProxmoxAPI(**prox_kwargs)  # type: ignore[misc]
            prox.version.get()
        except Exception as exc:
            try:
                if log is not None:
                    log.warning("[proxmox] authentication failed: %s", exc)
            except Exception:
                pass

            msg = str(exc)
            lowered = msg.lower()
            if any(
                tok in lowered
                for tok in (
                    "bad gateway",
                    "502",
                    "connection refused",
                    "name or service not known",
                    "temporary failure in name resolution",
                    "timed out",
                    "timeout",
                    "max retries exceeded",
                    "connection error",
                    "proxyerror",
                    "sslerror",
                    "certificate verify failed",
                )
            ):
                detail = (
                    "Unable to reach Proxmox API from this server (network/proxy/TLS issue). "
                    f"Detail: {msg}"
                )
                return jsonify({"success": False, "error": detail}), 502

            return jsonify({"success": False, "error": f"Authentication failed: {msg}"}), 401

        try:
            if log is not None:
                log.info("[proxmox] authentication succeeded for %s@%s:%s", username, host, port)
        except Exception:
            pass

        scenario_index = payload.get("scenario_index")
        scenario_name = str(payload.get("scenario_name") or "").strip()

        summary: dict[str, Any] = {
            "url": url_raw,
            "port": port,
            "username": username,
            "verify_ssl": verify_ssl,
        }

        secret_identifier: Optional[str] = None
        stored_at_val: Optional[str] = None

        secret_payload = {
            "scenario_name": scenario_name,
            "scenario_index": scenario_index,
            "url": url_raw,
            "username": username,
            "password": password,
            "port": port,
            "verify_ssl": verify_ssl,
        }

        if remember_credentials:
            try:
                stored_meta = save_proxmox_credentials(secret_payload)
            except RuntimeError as exc:
                return jsonify({"success": False, "error": str(exc)}), 500
            except Exception as exc:
                try:
                    if log is not None:
                        log.exception("[proxmox] failed to persist credentials: %s", exc)
                except Exception:
                    pass
                return jsonify({"success": False, "error": "Credentials validated but could not be stored"}), 500

            stored_at_val = stored_meta.get("stored_at")
            summary = {
                "url": stored_meta["url"],
                "port": stored_meta["port"],
                "username": stored_meta["username"],
                "verify_ssl": stored_meta["verify_ssl"],
                "stored_at": stored_at_val,
            }
            secret_identifier = stored_meta["identifier"]
        else:
            summary = {
                "url": url_raw,
                "port": port,
                "username": username,
                "verify_ssl": verify_ssl,
                "stored_at": None,
            }

        message = f"Validated Proxmox access for {username} at {host}:{port}"

        try:
            if scenario_name:
                merge_hitl_validation_into_scenario_catalog(
                    scenario_name,
                    proxmox={
                        "url": summary.get("url"),
                        "port": summary.get("port"),
                        "verify_ssl": summary.get("verify_ssl"),
                        "secret_id": secret_identifier if remember_credentials else None,
                        "validated": bool(secret_identifier) if remember_credentials else False,
                        "last_validated_at": local_timestamp_display(),
                        "stored_at": summary.get("stored_at"),
                        "last_message": message,
                    },
                )
        except Exception:
            pass

        return jsonify(
            {
                "success": True,
                "message": message,
                "summary": summary,
                "secret_id": secret_identifier if remember_credentials else None,
                "scenario_index": scenario_index,
                "scenario_name": scenario_name,
            }
        )

    @app.route("/api/proxmox/clear", methods=["POST"])
    def api_proxmox_clear():
        denied = _require_admin()
        if denied is not None:
            return denied

        payload = request.get_json(silent=True) or {}
        secret_id_raw = payload.get("secret_id")
        secret_id = secret_id_raw.strip() if isinstance(secret_id_raw, str) else ""
        scenario_index = payload.get("scenario_index")
        scenario_name = str(payload.get("scenario_name") or "").strip()

        removed = False
        try:
            if secret_id:
                removed = delete_proxmox_credentials(secret_id)
        except Exception:
            try:
                if log is not None:
                    log.exception(
                        "[proxmox] failed to clear credentials for %s (scenario %s)",
                        secret_id or "unknown",
                        scenario_name or scenario_index,
                    )
            except Exception:
                pass
            return jsonify({"success": False, "error": "Failed to clear stored Proxmox credentials"}), 500

        try:
            if log is not None:
                log.info(
                    "[proxmox] cleared credentials request for %s (scenario_index=%s, removed=%s)",
                    scenario_name or "unnamed",
                    scenario_index,
                    removed,
                )
        except Exception:
            pass

        try:
            if scenario_name:
                clear_hitl_validation_in_scenario_catalog(scenario_name, proxmox=True)
        except Exception:
            pass

        return jsonify(
            {
                "success": True,
                "secret_removed": removed,
                "scenario_index": scenario_index,
                "scenario_name": scenario_name,
            }
        )

    @app.route("/api/proxmox/credentials/get", methods=["POST"])
    def api_proxmox_credentials_get():
        denied = _require_admin()
        if denied is not None:
            return denied

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not payload:
            try:
                payload = request.form.to_dict(flat=True) if request.form else {}
            except Exception:
                payload = {}

        secret_id_raw = payload.get("secret_id")
        secret_id = secret_id_raw.strip() if isinstance(secret_id_raw, str) else ""
        if not secret_id:
            return jsonify({"success": False, "error": "secret_id is required"}), 400

        try:
            record = load_proxmox_credentials(secret_id)
        except RuntimeError as exc:
            return jsonify({"success": False, "error": str(exc)}), 500

        if not record:
            return jsonify({"success": False, "error": "Stored credentials not found"}), 404

        credentials = {
            "identifier": record.get("identifier") or secret_id,
            "scenario_name": record.get("scenario_name") or "",
            "scenario_index": record.get("scenario_index"),
            "url": record.get("url") or "",
            "port": int(record.get("port") or 8006),
            "username": record.get("username") or "",
            "password": record.get("password_plain") or "",
            "verify_ssl": bool(record.get("verify_ssl", True)),
            "stored_at": record.get("stored_at"),
        }

        return jsonify({"success": True, "credentials": credentials})

    @app.route("/api/proxmox/vms", methods=["POST"])
    def api_proxmox_vms():
        denied = _require_admin()
        if denied is not None:
            return denied

        payload = request.get_json(silent=True) or {}
        secret_id_raw = payload.get("secret_id")
        secret_id = secret_id_raw.strip() if isinstance(secret_id_raw, str) else ""
        if not secret_id:
            return jsonify({"success": False, "error": "secret_id is required"}), 400

        try:
            inventory = enumerate_proxmox_vms(secret_id)
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"success": False, "error": str(exc)}), 502
        except Exception as exc:  # pragma: no cover
            try:
                if log is not None:
                    log.exception("[proxmox] unexpected error fetching VM inventory: %s", exc)
            except Exception:
                pass
            return jsonify({"success": False, "error": "Failed to fetch Proxmox VM inventory"}), 500

        return jsonify({"success": True, "inventory": inventory})

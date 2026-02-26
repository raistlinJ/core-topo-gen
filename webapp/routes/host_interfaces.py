from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Type

from flask import jsonify, request


def register(
    app,
    *,
    coerce_bool: Callable[[Any], bool],
    find_proxmox_vm_config: Callable[..., Any],
    enumerate_core_vm_interfaces_from_secret: Callable[..., Any],
    ssh_tunnel_error_type: Type[BaseException],
    local_timestamp_display: Callable[[], str],
    enumerate_host_interfaces: Callable[[], Any],
    logger=None,
) -> None:
    """Register host interface enumeration endpoints.

    Extracted from `webapp.app_backend`.

    Notes:
    - POST: enumerates interfaces inside the CORE VM (via SSH) with a Proxmox-inventory fallback.
    - GET: enumerates interfaces on the Web UI host (via psutil when available).
    """

    log = logger or getattr(app, "logger", None)

    @app.route("/api/host_interfaces", methods=["GET", "POST"])
    def api_host_interfaces():
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
            secret_id_raw = payload.get("core_secret_id") or payload.get("secret_id")
            secret_id = secret_id_raw.strip() if isinstance(secret_id_raw, str) else ""
            include_down = coerce_bool(payload.get("include_down"))
            core_vm_payload = payload.get("core_vm") if isinstance(payload.get("core_vm"), dict) else {}
            prox_interfaces_raw = core_vm_payload.get("interfaces") if isinstance(core_vm_payload, dict) else None
            prox_interfaces = (
                [entry for entry in prox_interfaces_raw if isinstance(entry, dict)]
                if isinstance(prox_interfaces_raw, list)
                else None
            )
            vm_context = {
                "vm_key": core_vm_payload.get("vm_key"),
                "vm_name": core_vm_payload.get("vm_name"),
                "vm_node": core_vm_payload.get("vm_node"),
                "vmid": core_vm_payload.get("vmid"),
            }

            if not secret_id:
                fresh_prox_interfaces = None
                if vm_context.get("vmid"):
                    fresh_prox_interfaces = find_proxmox_vm_config(
                        vm_context.get("vm_node"),
                        vm_context.get("vmid"),
                    )

                if fresh_prox_interfaces:
                    prox_interfaces = fresh_prox_interfaces
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "CORE credentials are required to enumerate interfaces from the CORE VM",
                            }
                        ),
                        400,
                    )

            def _fallback_from_proxmox() -> Optional[Dict[str, Any]]:
                if not prox_interfaces:
                    return None

                synthesized: List[Dict[str, Any]] = []
                for idx, vmif in enumerate(prox_interfaces):
                    if not isinstance(vmif, dict):
                        continue

                    name = str(vmif.get("name") or vmif.get("id") or vmif.get("label") or f"interface-{idx}")
                    if vmif.get("id"):
                        name = vmif.get("id")

                    mac = vmif.get("macaddr") or vmif.get("mac") or vmif.get("hwaddr") or ""
                    entry: Dict[str, Any] = {
                        "name": name,
                        "display": name,
                        "mac": mac,
                        "ipv4": [],
                        "ipv6": [],
                        "mtu": None,
                        "speed": None,
                        "is_up": None,
                        "flags": [],
                        "proxmox": {
                            "id": vmif.get("id") or vmif.get("name") or vmif.get("label") or name,
                            "macaddr": mac,
                            "bridge": vmif.get("bridge"),
                            "model": vmif.get("model"),
                            "raw": vmif,
                            "vm_key": vm_context.get("vm_key"),
                            "vm_name": vm_context.get("vm_name"),
                            "vm_node": vm_context.get("vm_node"),
                            "vmid": vm_context.get("vmid"),
                        },
                    }
                    if vmif.get("bridge"):
                        entry["bridge"] = vmif.get("bridge")
                    synthesized.append(entry)

                meta = {k: v for k, v in vm_context.items() if v not in (None, "")}
                return {
                    "success": True,
                    "source": "proxmox_inventory_fallback",
                    "interfaces": synthesized,
                    "metadata": meta,
                    "fetched_at": local_timestamp_display(),
                    "note": "Using Proxmox inventory as a fallback; CORE VM SSH enumeration unavailable.",
                }

            try:
                fresh_prox_interfaces = None
                if vm_context.get("vmid"):
                    try:
                        fresh_prox_interfaces = find_proxmox_vm_config(
                            vm_context.get("vm_node"),
                            vm_context.get("vmid"),
                        )
                    except Exception:
                        pass

                use_prox_interfaces = fresh_prox_interfaces if fresh_prox_interfaces else prox_interfaces

                if secret_id:
                    interfaces = enumerate_core_vm_interfaces_from_secret(
                        secret_id,
                        prox_interfaces=use_prox_interfaces,
                        include_down=include_down,
                        vm_context=vm_context,
                    )
                else:
                    if use_prox_interfaces:
                        interfaces = []
                    else:
                        raise ValueError("CORE credentials are required")

                if (not interfaces) and use_prox_interfaces:
                    prox_interfaces = use_prox_interfaces
                    fb = _fallback_from_proxmox()
                    if fb is not None:
                        return jsonify(fb)
            except ValueError:
                if fresh_prox_interfaces:
                    prox_interfaces = fresh_prox_interfaces
                fb = _fallback_from_proxmox()
                if fb is not None:
                    return jsonify(fb)
                return (
                    jsonify({"success": False, "error": "CORE credentials are required (and no Proxmox fallback available)"}),
                    400,
                )
            except ssh_tunnel_error_type as exc:
                fb = _fallback_from_proxmox()
                if fb is not None:
                    return jsonify(fb)
                return jsonify({"success": False, "error": str(exc)}), 502
            except RuntimeError as exc:
                fb = _fallback_from_proxmox()
                if fb is not None:
                    return jsonify(fb)
                return jsonify({"success": False, "error": str(exc)}), 500
            except Exception as exc:  # pragma: no cover
                try:
                    if log is not None:
                        log.exception("[hitl] unexpected failure retrieving CORE VM interfaces: %s", exc)
                except Exception:
                    pass
                return (
                    jsonify({"success": False, "error": "Unexpected error retrieving CORE VM interfaces"}),
                    500,
                )

            response_data = {
                "success": True,
                "source": "core_vm",
                "interfaces": interfaces,
                "metadata": {k: v for k, v in vm_context.items() if v not in (None, "")},
                "fetched_at": local_timestamp_display(),
            }
            return jsonify(response_data)

        try:
            interfaces = enumerate_host_interfaces()
            return jsonify({"success": True, "interfaces": interfaces})
        except Exception as exc:  # pragma: no cover
            try:
                if log is not None:
                    log.exception("[hitl] failed to enumerate host interfaces via GET: %s", exc)
            except Exception:
                pass
            return jsonify({"success": False, "error": "Failed to enumerate host interfaces"}), 500

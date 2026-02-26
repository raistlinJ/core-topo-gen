from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

from flask import jsonify, request


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    normalize_role_value: Callable[[Any], str],
    normalize_internal_bridge_name: Callable[[Any], str],
    normalize_hitl_attachment: Callable[[Any], str],
    parse_proxmox_vm_key: Callable[[str], Tuple[str, int]],
    connect_proxmox_from_secret: Callable[[str], Tuple[Any, dict[str, Any]]],
    ensure_proxmox_bridge: Callable[..., dict[str, Any]],
    rewrite_bridge_in_net_config: Callable[[str, str], Tuple[str, bool, str | None]],
    merge_hitl_config_into_scenario_catalog: Callable[[str, dict[str, Any]], Any],
    logger=None,
) -> None:
    """Register HITL bridge endpoints.

    Extracted from `webapp.app_backend` while preserving behavior.

    Important: pass `connect_proxmox_from_secret` / `ensure_proxmox_bridge` as
    late-bound callables so unit tests can monkeypatch the original symbols.
    """

    log = logger or getattr(app, "logger", None)

    def _require_admin():
        current = current_user_getter()
        if not current or normalize_role_value(current.get("role")) != "admin":
            return jsonify({"success": False, "error": "Admin privileges required"}), 403
        return None

    @app.route("/api/hitl/apply_bridge", methods=["POST"])
    def api_hitl_apply_bridge():
        denied = _require_admin()
        if denied is not None:
            return denied

        payload = request.get_json(silent=True) or {}
        bridge_raw = payload.get("bridge_name") or payload.get("internal_bridge") or payload.get("bridge")
        if bridge_raw in (None, ""):
            return jsonify({"success": False, "error": "Bridge name is required"}), 400
        try:
            bridge_name = normalize_internal_bridge_name(bridge_raw)
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

        scenario_name = str(payload.get("scenario_name") or payload.get("scenario") or "").strip()
        scenario_index_raw = payload.get("scenario_index")
        try:
            scenario_index = int(scenario_index_raw)
        except Exception:
            scenario_index = None

        hitl_payload = payload.get("hitl") or payload.get("scenario_hitl") or payload.get("hitl_config")
        if not isinstance(hitl_payload, dict):
            return (
                jsonify({"success": False, "error": "HITL configuration is required to apply bridge changes"}),
                400,
            )

        prox_state = hitl_payload.get("proxmox") or {}
        secret_id_raw = prox_state.get("secret_id") or prox_state.get("secretId") or prox_state.get("identifier")
        secret_id = secret_id_raw.strip() if isinstance(secret_id_raw, str) else ""
        if not secret_id:
            return (
                jsonify({"success": False, "error": "Validate and store Proxmox credentials before applying bridge changes"}),
                400,
            )

        core_state = hitl_payload.get("core") or {}
        vm_key_raw = core_state.get("vm_key") or core_state.get("vmKey")
        vm_key = str(vm_key_raw or "").strip()
        if not vm_key:
            return jsonify({"success": False, "error": "Select a CORE VM before applying bridge changes"}), 400
        try:
            core_node, core_vmid = parse_proxmox_vm_key(vm_key)
        except ValueError as exc:
            return jsonify({"success": False, "error": f"CORE VM selection invalid: {exc}"}), 400
        core_vm_name = str(core_state.get("vm_name") or core_state.get("vmName") or "").strip()

        interfaces_payload = hitl_payload.get("interfaces")
        if not isinstance(interfaces_payload, list) or not interfaces_payload:
            return (
                jsonify({"success": False, "error": "Add at least one HITL interface before applying bridge changes"}),
                400,
            )

        validation_errors: List[str] = []
        assignments: List[Dict[str, Any]] = []
        for idx, iface in enumerate(interfaces_payload):
            if not isinstance(iface, dict):
                continue
            iface_name = str(iface.get("name") or f"Interface {idx + 1}").strip() or f"Interface {idx + 1}"
            prox_target = iface.get("proxmox_target")
            if not isinstance(prox_target, dict):
                validation_errors.append(f"{iface_name}: Map the interface to a CORE VM adapter in Step 3.")
                continue
            external = iface.get("external_vm")
            attachment = normalize_hitl_attachment(iface.get("attachment"))
            if attachment != "proxmox_vm":
                if isinstance(external, dict):
                    attachment = "proxmox_vm"
                else:
                    continue
            core_iface_id = str(prox_target.get("interface_id") or "").strip()
            if not core_iface_id:
                validation_errors.append(f"{iface_name}: Select the CORE VM interface to use for HITL connectivity.")
                continue
            target_node = str(prox_target.get("node") or "").strip() or core_node
            try:
                target_vmid = int(prox_target.get("vmid") or core_vmid)
            except Exception:
                validation_errors.append(f"{iface_name}: CORE VM identifier is invalid.")
                continue
            if target_node != core_node or target_vmid != core_vmid:
                validation_errors.append(
                    f"{iface_name}: CORE interface must belong to the selected CORE VM on node {core_node}."
                )
                continue
            if not isinstance(external, dict):
                validation_errors.append(f"{iface_name}: Select an external Proxmox VM in Step 4.")
                continue
            external_vm_key = str(external.get("vm_key") or external.get("vmKey") or "").strip()
            if not external_vm_key:
                validation_errors.append(f"{iface_name}: Select an external Proxmox VM in Step 4.")
                continue
            try:
                external_node, external_vmid = parse_proxmox_vm_key(external_vm_key)
            except ValueError as exc:
                validation_errors.append(f"{iface_name}: External VM invalid: {exc}")
                continue
            if external_node != core_node:
                validation_errors.append(f"{iface_name}: External VM must be hosted on node {core_node}.")
                continue
            external_iface_id = str(external.get("interface_id") or "").strip()
            if not external_iface_id:
                validation_errors.append(
                    f"{iface_name}: Select the external VM interface to connect through the bridge."
                )
                continue
            assignments.append(
                {
                    "name": iface_name,
                    "core": {
                        "node": core_node,
                        "vmid": core_vmid,
                        "vm_name": core_vm_name,
                        "interface_id": core_iface_id,
                    },
                    "external": {
                        "node": external_node,
                        "vmid": external_vmid,
                        "vm_name": str(external.get("vm_name") or "").strip(),
                        "interface_id": external_iface_id,
                    },
                }
            )

        if validation_errors:
            message = " ; ".join(validation_errors[:3])
            if len(validation_errors) > 3:
                message += f" (and {len(validation_errors) - 3} more issue(s))"
            return jsonify({"success": False, "error": message, "details": validation_errors}), 400
        if not assignments:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": (
                            "No eligible HITL interface mappings found. Map at least one interface to a CORE VM and "
                            "external VM before applying."
                        ),
                    }
                ),
                400,
            )

        try:
            client, _record = connect_proxmox_from_secret(secret_id)
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"success": False, "error": str(exc)}), 502
        except Exception as exc:  # pragma: no cover
            try:
                if log is not None:
                    log.exception("[hitl] unexpected failure connecting to Proxmox: %s", exc)
            except Exception:
                pass
            return jsonify({"success": False, "error": "Unexpected error connecting to Proxmox"}), 500

        owner_raw = payload.get("bridge_owner") or core_state.get("internal_bridge_owner") or payload.get("username")
        bridge_owner = str(owner_raw or "").strip()
        comment_bits = ["core-topo-gen HITL bridge"]
        if scenario_name:
            comment_bits.append(f"scenario={scenario_name}")
        if bridge_owner:
            comment_bits.append(f"owner={bridge_owner}")
        bridge_comment = " ".join(comment_bits)

        try:
            bridge_meta = ensure_proxmox_bridge(client, core_node, bridge_name, comment=bridge_comment)
        except RuntimeError as exc:
            return jsonify({"success": False, "error": str(exc)}), 502

        vm_config_cache: Dict[tuple[str, int], Dict[str, Any]] = {}

        def _get_vm_config(node: str, vmid: int) -> Dict[str, Any]:
            key = (node, vmid)
            if key not in vm_config_cache:
                try:
                    vm_config_cache[key] = client.nodes(node).qemu(vmid).config.get()
                except Exception as exc:
                    raise RuntimeError(
                        f"Failed to fetch configuration for VM {vmid} on node {node}: {exc}"
                    ) from exc
            return vm_config_cache[key]

        vm_updates: Dict[tuple[str, int], Dict[str, str]] = {}
        change_details: List[Dict[str, Any]] = []
        try:
            for assignment in assignments:
                for role in ("core", "external"):
                    vm_info = assignment[role]
                    node = vm_info["node"]
                    vmid = vm_info["vmid"]
                    interface_id = vm_info["interface_id"]
                    vm_name = vm_info.get("vm_name") or ""
                    config = _get_vm_config(node, vmid)
                    net_config = config.get(interface_id)
                    if not isinstance(net_config, str) or not net_config.strip():
                        raise ValueError(
                            f"{role.title()} VM {vm_name or vmid} is missing Proxmox interface {interface_id}."
                        )
                    new_config, changed, previous_bridge = rewrite_bridge_in_net_config(net_config, bridge_name)
                    change_details.append(
                        {
                            "role": role,
                            "scenario_interface": assignment["name"],
                            "node": node,
                            "vmid": vmid,
                            "vm_name": vm_name,
                            "interface_id": interface_id,
                            "previous_bridge": previous_bridge,
                            "new_bridge": bridge_name,
                            "changed": changed,
                        }
                    )
                    if changed:
                        vm_updates.setdefault((node, vmid), {})[interface_id] = new_config
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"success": False, "error": str(exc)}), 502

        updated_vms: List[Dict[str, Any]] = []
        for (node, vmid), updates in vm_updates.items():
            if not updates:
                continue
            try:
                client.nodes(node).qemu(vmid).config.post(**updates)
            except Exception as exc:  # pragma: no cover
                try:
                    if log is not None:
                        log.exception("[hitl] failed updating Proxmox VM config: %s", exc)
                except Exception:
                    pass
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Failed to update Proxmox VM {vmid} on node {node}: {exc}",
                        }
                    ),
                    502,
                )
            updated_vms.append({"node": node, "vmid": vmid, "interfaces": list(updates.keys())})

        changed_interfaces = sum(1 for change in change_details if change.get("changed"))
        unchanged_interfaces = len(change_details) - changed_interfaces
        assignment_count = len(assignments)

        parts = [f"Bridge {bridge_name} applied to {assignment_count} HITL link{'s' if assignment_count != 1 else ''}."]
        if changed_interfaces:
            parts.append(f"{changed_interfaces} Proxmox interface{'s' if changed_interfaces != 1 else ''} updated.")
        if unchanged_interfaces:
            parts.append(f"{unchanged_interfaces} already on the requested bridge.")
        message = " ".join(parts)

        warnings: List[str] = []
        if bridge_meta.get("created") and not bridge_meta.get("reload_ok"):
            warnings.append(
                "Bridge created but Proxmox did not confirm network reload; apply pending changes manually if required."
            )

        response: Dict[str, Any] = {
            "success": True,
            "message": message,
            "bridge_name": bridge_name,
            "bridge_created": bool(bridge_meta.get("created")),
            "bridge_already_exists": bool(bridge_meta.get("already_exists")),
            "bridge_reload_ok": bool(bridge_meta.get("reload_ok")),
            "bridge_reload_error": bridge_meta.get("reload_error"),
            "scenario_index": scenario_index,
            "scenario_name": scenario_name,
            "assignments": assignment_count,
            "changed_interfaces": changed_interfaces,
            "unchanged_interfaces": unchanged_interfaces,
            "changes": change_details,
            "updated_vms": updated_vms,
            "proxmox_node": core_node,
        }
        if warnings:
            response["warnings"] = warnings
        if bridge_owner:
            response["bridge_owner"] = bridge_owner

        try:
            if scenario_name:
                hitl_to_store = dict(hitl_payload)
                core_store = hitl_to_store.get("core") if isinstance(hitl_to_store.get("core"), dict) else {}
                core_store = dict(core_store)
                core_store["internal_bridge"] = bridge_name
                if bridge_owner:
                    core_store["internal_bridge_owner"] = bridge_owner
                hitl_to_store["core"] = core_store
                merge_hitl_config_into_scenario_catalog(scenario_name, hitl_to_store)
        except Exception:
            pass

        try:
            if log is not None:
                log.info(
                    "[hitl] applied internal bridge %s on node %s (%d assignment(s), %d interface change(s))",
                    bridge_name,
                    core_node,
                    assignment_count,
                    changed_interfaces,
                )
        except Exception:
            pass

        return jsonify(response)

    @app.route("/api/hitl/validate_bridge", methods=["POST"])
    def api_hitl_validate_bridge():
        """Validate HITL bridge configuration without applying any changes."""

        denied = _require_admin()
        if denied is not None:
            return denied

        payload = request.get_json(silent=True) or {}
        bridge_raw = payload.get("bridge_name") or payload.get("internal_bridge") or payload.get("bridge")
        if bridge_raw in (None, ""):
            return jsonify({"success": False, "error": "Bridge name is required"}), 400
        try:
            bridge_name = normalize_internal_bridge_name(bridge_raw)
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

        scenario_name = str(payload.get("scenario_name") or payload.get("scenario") or "").strip()
        scenario_index_raw = payload.get("scenario_index")
        try:
            scenario_index = int(scenario_index_raw)
        except Exception:
            scenario_index = None

        hitl_payload = payload.get("hitl") or payload.get("scenario_hitl") or payload.get("hitl_config")
        if not isinstance(hitl_payload, dict):
            return (
                jsonify({"success": False, "error": "HITL configuration is required to validate bridge settings"}),
                400,
            )

        prox_state = hitl_payload.get("proxmox") or {}
        secret_id_raw = prox_state.get("secret_id") or prox_state.get("secretId") or prox_state.get("identifier")
        secret_id = secret_id_raw.strip() if isinstance(secret_id_raw, str) else ""
        if not secret_id:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Validate and store Proxmox credentials before verifying HITL bridge settings",
                    }
                ),
                400,
            )

        core_state = hitl_payload.get("core") or {}
        vm_key_raw = core_state.get("vm_key") or core_state.get("vmKey")
        vm_key = str(vm_key_raw or "").strip()
        if not vm_key:
            return (
                jsonify({"success": False, "error": "Select a CORE VM before verifying HITL bridge settings"}),
                400,
            )
        try:
            core_node, core_vmid = parse_proxmox_vm_key(vm_key)
        except ValueError as exc:
            return jsonify({"success": False, "error": f"CORE VM selection invalid: {exc}"}), 400
        core_vm_name = str(core_state.get("vm_name") or core_state.get("vmName") or "").strip()

        interfaces_payload = hitl_payload.get("interfaces")
        if not isinstance(interfaces_payload, list) or not interfaces_payload:
            return (
                jsonify(
                    {"success": False, "error": "Add at least one HITL interface before verifying bridge settings"}
                ),
                400,
            )

        validation_errors: List[str] = []
        assignments: List[Dict[str, Any]] = []
        for idx, iface in enumerate(interfaces_payload):
            if not isinstance(iface, dict):
                continue
            iface_name = str(iface.get("name") or f"Interface {idx + 1}").strip() or f"Interface {idx + 1}"
            prox_target = iface.get("proxmox_target")
            if not isinstance(prox_target, dict):
                validation_errors.append(f"{iface_name}: Map the interface to a CORE VM adapter in Step 3.")
                continue
            external = iface.get("external_vm")
            attachment = normalize_hitl_attachment(iface.get("attachment"))
            if attachment != "proxmox_vm":
                if isinstance(external, dict):
                    attachment = "proxmox_vm"
                else:
                    continue
            core_iface_id = str(prox_target.get("interface_id") or "").strip()
            if not core_iface_id:
                validation_errors.append(f"{iface_name}: Select the CORE VM interface to use for HITL connectivity.")
                continue
            target_node = str(prox_target.get("node") or "").strip() or core_node
            try:
                target_vmid = int(prox_target.get("vmid") or core_vmid)
            except Exception:
                validation_errors.append(f"{iface_name}: CORE VM identifier is invalid.")
                continue
            if target_node != core_node or target_vmid != core_vmid:
                validation_errors.append(
                    f"{iface_name}: CORE interface must belong to the selected CORE VM on node {core_node}."
                )
                continue
            if not isinstance(external, dict):
                validation_errors.append(f"{iface_name}: Select an external Proxmox VM in Step 4.")
                continue
            external_vm_key = str(external.get("vm_key") or external.get("vmKey") or "").strip()
            if not external_vm_key:
                validation_errors.append(f"{iface_name}: Select an external Proxmox VM in Step 4.")
                continue
            try:
                external_node, external_vmid = parse_proxmox_vm_key(external_vm_key)
            except ValueError as exc:
                validation_errors.append(f"{iface_name}: External VM invalid: {exc}")
                continue
            if external_node != core_node:
                validation_errors.append(f"{iface_name}: External VM must be hosted on node {core_node}.")
                continue
            external_iface_id = str(external.get("interface_id") or "").strip()
            if not external_iface_id:
                validation_errors.append(
                    f"{iface_name}: Select the external VM interface to connect through the bridge."
                )
                continue
            assignments.append(
                {
                    "name": iface_name,
                    "core": {
                        "node": core_node,
                        "vmid": core_vmid,
                        "vm_name": core_vm_name,
                        "interface_id": core_iface_id,
                    },
                    "external": {
                        "node": external_node,
                        "vmid": external_vmid,
                        "vm_name": str(external.get("vm_name") or "").strip(),
                        "interface_id": external_iface_id,
                    },
                }
            )

        if validation_errors:
            message = " ; ".join(validation_errors[:3])
            if len(validation_errors) > 3:
                message += f" (and {len(validation_errors) - 3} more issue(s))"
            return jsonify({"success": False, "error": message, "details": validation_errors}), 400
        if not assignments:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": (
                            "No eligible HITL interface mappings found. Map at least one interface to a CORE VM and "
                            "external VM before verifying."
                        ),
                    }
                ),
                400,
            )

        try:
            client, _record = connect_proxmox_from_secret(secret_id)
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"success": False, "error": str(exc)}), 502
        except Exception as exc:  # pragma: no cover
            try:
                if log is not None:
                    log.exception("[hitl] unexpected failure connecting to Proxmox: %s", exc)
            except Exception:
                pass
            return jsonify({"success": False, "error": "Unexpected error connecting to Proxmox"}), 500

        try:
            bridge_meta = ensure_proxmox_bridge(client, core_node, bridge_name)
        except RuntimeError as exc:
            msg = str(exc)
            status = 400 if "not found on node" in msg.lower() else 502
            return jsonify({"success": False, "error": msg}), status

        vm_config_cache: Dict[tuple[str, int], Dict[str, Any]] = {}

        def _get_vm_config(node: str, vmid: int) -> Dict[str, Any]:
            key = (node, vmid)
            if key not in vm_config_cache:
                try:
                    vm_config_cache[key] = client.nodes(node).qemu(vmid).config.get()
                except Exception as exc:
                    raise RuntimeError(
                        f"Failed to fetch configuration for VM {vmid} on node {node}: {exc}"
                    ) from exc
            return vm_config_cache[key]

        change_details: List[Dict[str, Any]] = []
        try:
            for assignment in assignments:
                for role in ("core", "external"):
                    vm_info = assignment[role]
                    node = vm_info["node"]
                    vmid = vm_info["vmid"]
                    interface_id = vm_info["interface_id"]
                    vm_name = vm_info.get("vm_name") or ""
                    config = _get_vm_config(node, vmid)
                    net_config = config.get(interface_id)
                    if not isinstance(net_config, str) or not net_config.strip():
                        raise ValueError(
                            f"{role.title()} VM {vm_name or vmid} is missing Proxmox interface {interface_id}."
                        )
                    _new_config, changed, previous_bridge = rewrite_bridge_in_net_config(net_config, bridge_name)
                    change_details.append(
                        {
                            "role": role,
                            "scenario_interface": assignment["name"],
                            "node": node,
                            "vmid": vmid,
                            "vm_name": vm_name,
                            "interface_id": interface_id,
                            "previous_bridge": previous_bridge,
                            "new_bridge": bridge_name,
                            "changed": changed,
                        }
                    )
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"success": False, "error": str(exc)}), 502

        changed_interfaces = sum(1 for change in change_details if change.get("changed"))
        unchanged_interfaces = len(change_details) - changed_interfaces
        assignment_count = len(assignments)

        parts = [
            f"Bridge {bridge_name} validation succeeded for {assignment_count} HITL link{'s' if assignment_count != 1 else ''}."
        ]
        if changed_interfaces:
            parts.append(
                f"{changed_interfaces} Proxmox interface{'s' if changed_interfaces != 1 else ''} would be updated."
            )
        if unchanged_interfaces:
            parts.append(f"{unchanged_interfaces} already on the requested bridge.")
        message = " ".join(parts)

        response: Dict[str, Any] = {
            "success": True,
            "message": message,
            "bridge_name": bridge_name,
            "bridge_meta": bridge_meta,
            "scenario_index": scenario_index,
            "scenario_name": scenario_name,
            "assignments": assignment_count,
            "changed_interfaces": changed_interfaces,
            "unchanged_interfaces": unchanged_interfaces,
            "changes": change_details,
            "proxmox_node": core_node,
        }

        try:
            if scenario_name:
                hitl_to_store = dict(hitl_payload)
                core_store = hitl_to_store.get("core") if isinstance(hitl_to_store.get("core"), dict) else {}
                core_store = dict(core_store)
                core_store["internal_bridge"] = bridge_name
                hitl_to_store["core"] = core_store
                merge_hitl_config_into_scenario_catalog(scenario_name, hitl_to_store)
        except Exception:
            pass

        return jsonify(response)

from __future__ import annotations

from typing import Any, Callable, Optional

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    current_user_getter: Callable[[], Any],
    normalize_role_value: Callable[[Any], str],
    merge_core_configs: Callable[..., dict[str, Any]],
    load_core_credentials: Callable[[str], Any],
    ensure_paramiko_available: Callable[[], None],
    paramiko_getter: Callable[[], Any],
    collect_remote_core_daemon_pids: Callable[[Any], list[int]],
    stop_remote_core_daemon_conflict: Callable[..., Any],
    install_custom_services_to_core_vm: Callable[..., Any],
    start_remote_core_daemon: Callable[..., Any],
    run_core_connection_advanced_checks: Callable[..., dict[str, Any]],
    ensure_core_daemon_listening: Callable[..., Any],
    core_connection: Callable[..., Any],
    save_core_credentials: Callable[[dict[str, Any]], dict[str, Any]],
    merge_hitl_validation_into_scenario_catalog: Callable[..., Any],
    normalize_core_config: Callable[..., dict[str, Any]],
    local_timestamp_display: Callable[[], str],
    ssh_tunnel_error_type: type[BaseException],
    webui_running_in_docker: Callable[[], bool],
    json_module: Any,
    os_module: Any,
    sys_module: Any,
    socket_module: Any,
) -> None:
    if not begin_route_registration(app, 'core_connection_validation_routes'):
        return

    def _test_core_view():
        current = current_user_getter()
        if not current or normalize_role_value(current.get('role')) != 'admin':
            return jsonify({'ok': False, 'error': 'Admin privileges required'}), 403
        try:
            data: dict[str, Any] = {}
            if request.is_json:
                data = request.get_json(silent=True) or {}
            else:
                data = {
                    'host': request.form.get('host'),
                    'port': request.form.get('port'),
                    'ssh_enabled': request.form.get('ssh_enabled'),
                    'ssh_host': request.form.get('ssh_host'),
                    'ssh_port': request.form.get('ssh_port'),
                    'ssh_username': request.form.get('ssh_username'),
                    'ssh_password': request.form.get('ssh_password'),
                    'core': request.form.get('core_json'),
                }
                try:
                    if isinstance(data.get('core'), str) and data['core']:
                        data['core'] = json_module.loads(data['core'])
                except Exception:
                    data['core'] = None
            direct_override = {
                key: data.get(key)
                for key in ('host', 'port', 'ssh_enabled', 'ssh_host', 'ssh_port', 'ssh_username', 'ssh_password')
                if data.get(key) not in (None, '')
            }
            scenario_core_raw = data.get('hitl_core')
            if not scenario_core_raw and request.form.get('hitl_core_json'):
                try:
                    scenario_core_raw = json_module.loads(request.form.get('hitl_core_json') or '')
                except Exception:
                    scenario_core_raw = None
            scenario_core_dict = scenario_core_raw if isinstance(scenario_core_raw, dict) else {}
            scenario_vm_key = str(scenario_core_dict.get('vm_key') or '').strip()
            scenario_vm_node = str(scenario_core_dict.get('vm_node') or '').strip()
            scenario_vm_name = str(scenario_core_dict.get('vm_name') or '').strip()
            scenario_vm_id_raw = scenario_core_dict.get('vmid') or scenario_core_dict.get('vm_id')
            scenario_vm_id = str(scenario_vm_id_raw).strip() if isinstance(scenario_vm_id_raw, (str, int)) else ''
            if not scenario_vm_node and scenario_vm_key and '::' in scenario_vm_key:
                scenario_vm_node = scenario_vm_key.split('::', 1)[0].strip()
            cfg = merge_core_configs(
                data.get('core') if isinstance(data.get('core'), dict) else None,
                direct_override if direct_override else None,
                include_password=True,
            )
            if not scenario_vm_key:
                return jsonify({'ok': False, 'error': 'Select a CORE VM before validating the connection.'}), 400
            cfg['vm_key'] = scenario_vm_key
            if scenario_vm_node:
                cfg['vm_node'] = scenario_vm_node
            if scenario_vm_name:
                cfg.setdefault('vm_name', scenario_vm_name)
            if scenario_vm_id:
                cfg.setdefault('vmid', scenario_vm_id)
            core_secret_id = str(cfg.get('core_secret_id') or '').strip()
            stored_secret = None
            if core_secret_id:
                stored_secret = load_core_credentials(core_secret_id)
                if not stored_secret:
                    supplied_password = str(cfg.get('ssh_password') or '')
                    if supplied_password.strip():
                        app.logger.warning(
                            '[core] stale core_secret_id=%s unavailable; proceeding with entered SSH password for vm_key=%s',
                            core_secret_id,
                            scenario_vm_key,
                        )
                        cfg['core_secret_id'] = None
                        core_secret_id = ''
                    else:
                        return jsonify({'ok': False, 'error': 'Stored CORE credentials are unavailable. Re-enter the SSH password for the selected CORE VM.'}), 400
                if stored_secret:
                    stored_vm_key = str(stored_secret.get('vm_key') or '').strip()
                    if stored_vm_key and stored_vm_key != scenario_vm_key:
                        stored_vm_name = str(stored_secret.get('vm_name') or stored_secret.get('vm_key') or 'previous VM')
                        mismatch_message = (
                            f'Stored CORE credentials target {stored_vm_name}, '
                            f'but Step 2 is configured for {scenario_vm_name or scenario_vm_key}. '
                            'Clear the Step 2 credentials and validate with the selected CORE VM.'
                        )
                        return jsonify({'ok': False, 'error': mismatch_message, 'vm_mismatch': True}), 409
                    stored_vm_node = str(stored_secret.get('vm_node') or '').strip()
                    if stored_vm_node and scenario_vm_node and stored_vm_node != scenario_vm_node:
                        mismatch_message = (
                            f'Stored CORE credentials reference node {stored_vm_node}, '
                            f'but the selected CORE VM resides on node {scenario_vm_node}. '
                            'Clear the Step 2 credentials and validate with the selected CORE VM.'
                        )
                        return jsonify({'ok': False, 'error': mismatch_message, 'vm_mismatch': True}), 409
            auto_start_daemon = bool(cfg.get('auto_start_daemon'))
            install_custom_services = bool(cfg.get('install_custom_services'))
            stop_duplicate_daemons = bool(cfg.get('stop_duplicate_daemons'))
            adv_fix_docker_daemon = bool(cfg.get('adv_fix_docker_daemon'))
            adv_run_core_cleanup = bool(cfg.get('adv_run_core_cleanup'))
            adv_check_core_version = False
            adv_restart_core_daemon = bool(cfg.get('adv_restart_core_daemon'))
            adv_start_core_daemon = bool(cfg.get('adv_start_core_daemon'))
            adv_auto_kill_sessions = bool(cfg.get('adv_auto_kill_sessions'))
            if webui_running_in_docker() and adv_fix_docker_daemon:
                return jsonify({
                    'ok': False,
                    'error': 'Fix Docker daemon for CORE is disabled while the Web UI runs in Docker because restarting Docker may interrupt this validation request.',
                    'code': 'adv_fix_docker_daemon_disabled_in_docker',
                }), 400
            is_pytest = bool(os_module.environ.get('PYTEST_CURRENT_TEST') or ('pytest' in sys_module.modules))
            daemon_pids: list[int] = []
            install_meta: Optional[dict[str, Any]] = None
            advanced_checks: dict[str, dict[str, Any]] = {}
            advanced_warnings: list[str] = []
            paramiko_module = paramiko_getter()
            if is_pytest and not (auto_start_daemon or install_custom_services or stop_duplicate_daemons):
                app.logger.info('[core] skipping core-daemon SSH inspection (pytest)')
            elif paramiko_module is None:
                if auto_start_daemon:
                    app.logger.warning('[core] Paramiko unavailable; cannot auto-start or inspect core-daemon remotely.')
                if install_custom_services:
                    app.logger.warning('[core] Paramiko unavailable; cannot install custom services remotely.')
            else:
                ensure_paramiko_available()
                ssh_client = paramiko_module.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko_module.AutoAddPolicy())
                try:
                    ssh_client.connect(
                        hostname=str(cfg.get('ssh_host') or cfg.get('host') or 'localhost'),
                        port=int(cfg.get('ssh_port') or 22),
                        username=str(cfg.get('ssh_username') or ''),
                        password=cfg.get('ssh_password'),
                        look_for_keys=False,
                        allow_agent=False,
                        timeout=10.0,
                        banner_timeout=10.0,
                        auth_timeout=10.0,
                    )
                    daemon_pids = collect_remote_core_daemon_pids(ssh_client)
                    if len(daemon_pids) > 1:
                        if stop_duplicate_daemons:
                            try:
                                stop_remote_core_daemon_conflict(
                                    ssh_client,
                                    sudo_password=cfg.get('ssh_password'),
                                    pids=daemon_pids,
                                    logger=app.logger,
                                )
                                try:
                                    import time as _time
                                    _time.sleep(1.0)
                                except Exception:
                                    pass
                                daemon_pids = collect_remote_core_daemon_pids(ssh_client)
                            except Exception as exc:
                                msg = (
                                    'Multiple core-daemon processes are running on the CORE VM, and the automatic stop failed. '
                                    f'PIDs: {", ".join(str(pid) for pid in daemon_pids)}. Error: {exc}'
                                )
                                return jsonify({
                                    'ok': False,
                                    'error': msg,
                                    'daemon_conflict': True,
                                    'daemon_pids': daemon_pids,
                                    'can_stop_daemons': bool(cfg.get('ssh_password')),
                                    'code': 'core_daemon_conflict',
                                }), 409
                        if len(daemon_pids) > 1:
                            msg = (
                                'Multiple core-daemon processes are running on the CORE VM. '
                                f'PIDs: {", ".join(str(pid) for pid in daemon_pids)}. '
                                'Stop duplicate daemons before continuing.'
                            )
                            return jsonify({
                                'ok': False,
                                'error': msg,
                                'daemon_conflict': True,
                                'daemon_pids': daemon_pids,
                                'can_stop_daemons': bool(cfg.get('ssh_password')),
                                'code': 'core_daemon_conflict',
                            }), 409
                    if install_custom_services:
                        app.logger.info('[core] Installing custom services on CORE VM...')
                        install_meta = install_custom_services_to_core_vm(
                            ssh_client,
                            sudo_password=cfg.get('ssh_password'),
                            logger=app.logger,
                            core_cfg=cfg,
                        )
                        app.logger.info(
                            '[core] Custom services installed: modules=%s targets=%s core_conf_path=%s core_conf_readable=%s core_conf_dirs=%s core_conf_lines=%s',
                            ','.join(install_meta.get('modules') or []),
                            ','.join([str(x) for x in (install_meta.get('services_dirs') or [install_meta.get('services_dir')]) if x]),
                            install_meta.get('core_conf_path'),
                            install_meta.get('core_conf_readable'),
                            ','.join([str(x) for x in (install_meta.get('core_conf_custom_services_dirs') or []) if x]) or 'none',
                            ' | '.join([str(x) for x in (install_meta.get('core_conf_custom_services_lines') or []) if x]) or 'none',
                        )
                        try:
                            import time as _time
                            _time.sleep(1.0)
                        except Exception:
                            pass
                        daemon_pids = collect_remote_core_daemon_pids(ssh_client)
                        if len(daemon_pids) > 1:
                            if stop_duplicate_daemons:
                                try:
                                    stop_remote_core_daemon_conflict(
                                        ssh_client,
                                        sudo_password=cfg.get('ssh_password'),
                                        pids=daemon_pids,
                                        logger=app.logger,
                                    )
                                    try:
                                        import time as _time
                                        _time.sleep(1.0)
                                    except Exception:
                                        pass
                                    daemon_pids = collect_remote_core_daemon_pids(ssh_client)
                                except Exception as exc:
                                    msg = (
                                        'Multiple core-daemon processes are running on the CORE VM after installing services, '
                                        'and the automatic stop failed. '
                                        f'PIDs: {", ".join(str(pid) for pid in daemon_pids)}. Error: {exc}'
                                    )
                                    return jsonify({
                                        'ok': False,
                                        'error': msg,
                                        'daemon_conflict': True,
                                        'daemon_pids': daemon_pids,
                                        'can_stop_daemons': bool(cfg.get('ssh_password')),
                                        'code': 'core_daemon_conflict',
                                    }), 409
                            if len(daemon_pids) > 1:
                                msg = (
                                    'Multiple core-daemon processes are running on the CORE VM after installing services. '
                                    f'PIDs: {", ".join(str(pid) for pid in daemon_pids)}. '
                                    'Stop duplicate daemons before continuing.'
                                )
                                return jsonify({
                                    'ok': False,
                                    'error': msg,
                                    'daemon_conflict': True,
                                    'daemon_pids': daemon_pids,
                                    'can_stop_daemons': bool(cfg.get('ssh_password')),
                                    'code': 'core_daemon_conflict',
                                }), 409
                    if auto_start_daemon:
                        if daemon_pids:
                            app.logger.info('[core] Skipping auto-start; core-daemon already running (PID %s).', daemon_pids[0])
                        else:
                            start_remote_core_daemon(ssh_client, cfg.get('ssh_password'), app.logger)
                            try:
                                import time as _time
                                _time.sleep(1.0)
                            except Exception:
                                pass
                            daemon_pids = collect_remote_core_daemon_pids(ssh_client)
                            if len(daemon_pids) != 1:
                                msg = 'core-daemon auto-start attempted but a single running process was not detected.'
                                app.logger.warning('[core] %s (pids=%s)', msg, daemon_pids)
                                return jsonify({'ok': False, 'error': msg, 'daemon_conflict': True}), 502
                    else:
                        if not daemon_pids:
                            app.logger.warning('[core] No core-daemon process detected during validation.')
                except Exception as conn_exc:
                    app.logger.warning('[core] core-daemon SSH inspection failed: %s', conn_exc)
                finally:
                    try:
                        ssh_client.close()
                    except Exception:
                        pass
            if (adv_fix_docker_daemon or adv_run_core_cleanup or adv_check_core_version or adv_restart_core_daemon or adv_start_core_daemon or adv_auto_kill_sessions):
                if is_pytest:
                    app.logger.info('[core] advanced checks enabled but skipping remote execution (pytest)')
                    advanced_checks = run_core_connection_advanced_checks(
                        cfg,
                        adv_fix_docker_daemon=False,
                        adv_run_core_cleanup=False,
                        adv_check_core_version=False,
                        adv_restart_core_daemon=False,
                        adv_start_core_daemon=False,
                        adv_auto_kill_sessions=False,
                    )
                else:
                    advanced_checks = run_core_connection_advanced_checks(
                        cfg,
                        adv_fix_docker_daemon=adv_fix_docker_daemon,
                        adv_run_core_cleanup=adv_run_core_cleanup,
                        adv_check_core_version=adv_check_core_version,
                        adv_restart_core_daemon=adv_restart_core_daemon,
                        adv_start_core_daemon=adv_start_core_daemon,
                        adv_auto_kill_sessions=adv_auto_kill_sessions,
                    )
                    failures = [
                        (key, result)
                        for key, result in (advanced_checks or {}).items()
                        if isinstance(result, dict) and result.get('enabled') and (result.get('ok') is False)
                    ]
                    if failures:
                        parts = []
                        for key, result in failures:
                            msg = str(result.get('message') or '').strip()
                            parts.append(f'{key}: {msg or "failed"}')
                        advanced_warnings.append('Advanced checks failed: ' + '; '.join(parts))
            if is_pytest:
                app.logger.info('[core] skipping daemon listening check (pytest)')
            elif paramiko_module is None:
                app.logger.warning('[core] skipping daemon listening check (paramiko unavailable)')
            else:
                try:
                    ensure_core_daemon_listening(cfg, timeout=5.0)
                except Exception as exc:
                    app.logger.warning('[core] daemon listening check failed: %s', exc)
                    return jsonify({'ok': False, 'error': f'core-daemon is not reachable on {cfg.get("host")}:{cfg.get("port")}: {exc}'}), 502
            remote_desc = f"{cfg.get('host')}:{cfg.get('port')}"
            forwarded_host = ''
            forwarded_port = 0
            with core_connection(cfg) as (conn_host, conn_port):
                forwarded_host = conn_host
                forwarded_port = int(conn_port)
                sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
                sock.settimeout(2.0)
                try:
                    sock.connect((forwarded_host, forwarded_port))
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
            scenario_index_raw = data.get('scenario_index')
            try:
                scenario_index_val = int(scenario_index_raw) if scenario_index_raw not in (None, '') else None
            except Exception:
                scenario_index_val = None
            scenario_name_val = str(data.get('scenario_name') or data.get('scenario') or '').strip()
            secret_payload = {
                'scenario_name': scenario_name_val,
                'scenario_index': scenario_index_val,
                'grpc_host': cfg.get('host'),
                'grpc_port': cfg.get('port'),
                'ssh_host': cfg.get('ssh_host'),
                'ssh_port': cfg.get('ssh_port'),
                'ssh_username': cfg.get('ssh_username'),
                'ssh_password': cfg.get('ssh_password'),
                'ssh_enabled': cfg.get('ssh_enabled'),
                'venv_bin': cfg.get('venv_bin'),
            }
            if isinstance(scenario_core_raw, dict):
                secret_payload.update({
                    'vm_key': scenario_core_raw.get('vm_key'),
                    'vm_name': scenario_core_raw.get('vm_name'),
                    'vm_node': scenario_core_raw.get('vm_node'),
                    'vmid': scenario_core_raw.get('vmid'),
                    'proxmox_secret_id': scenario_core_raw.get('proxmox_secret_id') or scenario_core_raw.get('secret_id'),
                    'proxmox_target': scenario_core_raw.get('proxmox_target') if isinstance(scenario_core_raw.get('proxmox_target'), dict) else None,
                })
            try:
                stored_meta = save_core_credentials(secret_payload)
            except RuntimeError as exc:
                return jsonify({'ok': False, 'error': str(exc)}), 500
            except Exception as exc:
                app.logger.exception('[core] failed to persist credentials: %s', exc)
                return jsonify({'ok': False, 'error': 'CORE connection succeeded but credentials could not be stored'}), 500
            summary_vm_label = stored_meta.get('vm_name') or stored_meta.get('vm_key')
            if summary_vm_label:
                summary_message = (
                    f"Validated CORE access for {stored_meta['ssh_username']} @ "
                    f"{stored_meta['ssh_host']}:{stored_meta['ssh_port']} (VM {summary_vm_label})"
                )
            else:
                summary_message = f"Validated CORE access for {stored_meta['ssh_username']} @ {stored_meta['ssh_host']}:{stored_meta['ssh_port']}"
            try:
                if scenario_name_val:
                    merge_hitl_validation_into_scenario_catalog(
                        scenario_name_val,
                        core={
                            'core_secret_id': stored_meta.get('identifier'),
                            'validated': bool(stored_meta.get('identifier')),
                            'last_validated_at': local_timestamp_display(),
                            'grpc_host': stored_meta.get('grpc_host') or stored_meta.get('host'),
                            'grpc_port': stored_meta.get('grpc_port') or stored_meta.get('port'),
                            'ssh_host': stored_meta.get('ssh_host'),
                            'ssh_port': stored_meta.get('ssh_port'),
                            'vm_key': stored_meta.get('vm_key'),
                            'vm_name': stored_meta.get('vm_name'),
                            'vm_node': stored_meta.get('vm_node'),
                            'stored_at': stored_meta.get('stored_at'),
                        },
                    )
            except Exception:
                pass
            return jsonify({
                'ok': True,
                'forward_host': forwarded_host,
                'forward_port': forwarded_port,
                'remote': remote_desc,
                'ssh_enabled': bool(cfg.get('ssh_enabled')),
                'host': cfg.get('host'),
                'port': int(cfg.get('port', 0)) if cfg.get('port') is not None else None,
                'daemon_pids': daemon_pids,
                'install_custom_services': install_meta,
                'advanced_checks': advanced_checks,
                'warnings': advanced_warnings,
                'core': normalize_core_config(cfg, include_password=False),
                'core_secret_id': stored_meta['identifier'],
                'core_summary': stored_meta,
                'scenario_index': scenario_index_val,
                'scenario_name': scenario_name_val,
                'message': summary_message,
            })
        except ssh_tunnel_error_type as exc:
            return jsonify({'ok': False, 'error': str(exc), 'ssh_error': True}), 200
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 200

    app.add_url_rule('/test_core', endpoint='test_core', view_func=_test_core_view, methods=['POST'])
    mark_routes_registered(app, 'core_connection_validation_routes')
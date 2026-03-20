from __future__ import annotations

import time
from typing import Any, Callable

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    login_required: Callable[[Callable[..., Any]], Callable[..., Any]],
    normalize_scenario_label: Callable[[str], str],
    select_core_config_for_page: Callable[..., dict[str, Any]],
    open_ssh_client: Callable[[dict[str, Any]], Any],
) -> None:
    if not begin_route_registration(app, 'core_daemon_admin_routes'):
        return

    def _restart_core_daemon_view():
        scenario_norm = normalize_scenario_label(request.args.get('scenario', ''))
        core_cfg = select_core_config_for_page(scenario_norm, include_password=True)

        if not core_cfg.get('ssh_host'):
            return jsonify({'error': 'No CORE VM configured via SSH.'}), 400

        try:
            app.logger.info('[core.daemon] Attempting restart via SSH')
            client = open_ssh_client(core_cfg)

            def _sudo_exec(cmd: str, *, timeout: float = 40.0) -> tuple[int, str, str]:
                sudo_password = core_cfg.get('ssh_password')
                wrapped = f"sh -c 'timeout {int(max(5, timeout))}s {cmd.strip()}'"
                sudo_cmd = f"sudo -S -p '' {wrapped}" if sudo_password else f"sudo -n {wrapped}"
                stdin = stdout = stderr = None
                try:
                    stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=timeout + 5.0, get_pty=True)
                    if sudo_password:
                        try:
                            stdin.write(str(sudo_password) + '\n')
                            stdin.flush()
                        except Exception:
                            pass
                    out_bytes = stdout.read() if stdout else b''
                    err_bytes = stderr.read() if stderr else b''
                    try:
                        code = stdout.channel.recv_exit_status() if (stdout and hasattr(stdout, 'channel')) else 0
                    except Exception:
                        code = 0
                    out_text = out_bytes.decode('utf-8', 'ignore') if isinstance(out_bytes, (bytes, bytearray)) else str(out_bytes or '')
                    err_text = err_bytes.decode('utf-8', 'ignore') if isinstance(err_bytes, (bytes, bytearray)) else str(err_bytes or '')
                    return int(code), out_text, err_text
                finally:
                    try:
                        if stdin:
                            stdin.close()
                    except Exception:
                        pass

            exit_code, _out, err = _sudo_exec('systemctl restart core-daemon', timeout=40.0)
            if exit_code != 0:
                err = (err or '').strip()
                return jsonify({'error': f'Restart failed (exit {exit_code}): {err}'}), 500

            chk_code, _, _ = _sudo_exec('systemctl is-active core-daemon', timeout=10.0)
            if chk_code != 0:
                return jsonify({'error': 'Restart command succeeded but service is not active.'}), 500

            app.logger.info('[core.daemon] Restart successful')
            time.sleep(2.0)
            return jsonify({'status': 'ok', 'message': 'CORE daemon restarted successfully.'})
        except Exception as exc:
            app.logger.error('Failed to restart CORE daemon: %s', exc, exc_info=True)
            msg = str(exc)
            if 'Authentication failed' in msg:
                msg = 'SSH authentication failed. Check your credentials in Scenarios > Config.'
            return jsonify({'error': msg}), 500
        finally:
            try:
                if 'client' in locals() and client is not None:
                    client.close()
            except Exception:
                pass

    app.add_url_rule(
        '/core/restart_core_daemon',
        endpoint='restart_core_daemon',
        view_func=login_required(_restart_core_daemon_view),
        methods=['POST'],
    )
    mark_routes_registered(app, 'core_daemon_admin_routes')
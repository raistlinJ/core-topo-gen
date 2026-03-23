from __future__ import annotations

from typing import Any, Callable

from flask import jsonify

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    get_repo_push_progress: Callable[[str], dict[str, Any] | None],
    update_repo_push_progress: Callable[..., None],
    get_repo_push_cancel_ctx: Callable[[str], dict[str, Any] | None],
    open_ssh_client: Callable[[dict[str, Any]], Any],
    exec_ssh_command: Callable[..., tuple[int, str, str]],
    shlex_quote: Callable[[str], str],
) -> None:
    if not begin_route_registration(app, 'core_push_progress_routes'):
        return

    def _core_push_repo_status_view(progress_id: str):
        payload = get_repo_push_progress(progress_id)
        if not payload:
            return jsonify({'progress_id': progress_id, 'status': 'unknown'}), 404
        response = {
            'progress_id': progress_id,
            'status': payload.get('status') or 'pending',
            'stage': payload.get('stage'),
            'detail': payload.get('detail'),
            'percent': payload.get('percent'),
            'done_bytes': payload.get('done_bytes'),
            'total_bytes': payload.get('total_bytes'),
            'done_files': payload.get('done_files'),
            'total_files': payload.get('total_files'),
            'method': payload.get('method'),
            'cancel_requested': bool(payload.get('cancel_requested')),
            'updated_at': payload.get('updated_at'),
            'created_at': payload.get('created_at'),
        }
        return jsonify(response)

    def _core_push_repo_cancel_view(progress_id: str):
        payload = get_repo_push_progress(progress_id)
        if not payload:
            return jsonify({'progress_id': progress_id, 'status': 'unknown'}), 404
        status = (payload.get('status') or '').strip().lower()
        if status in ('complete', 'error', 'cancelled'):
            return jsonify({'ok': True, 'progress_id': progress_id, 'status': status, 'noop': True})
        update_repo_push_progress(
            progress_id,
            cancel_requested=True,
            status='cancelled',
            stage='cancelled',
            detail='Cancelled by user.',
        )

        kill_info: dict[str, Any] = {
            'attempted': False,
            'pidfile': None,
            'pidfile_found': False,
            'pid': None,
            'term_sent': False,
            'kill_sent': False,
            'pidfile_removed': False,
            'archive': None,
            'archive_existed_before': None,
            'archive_exists_after': None,
        }
        try:
            ctx = get_repo_push_cancel_ctx(progress_id)
            if isinstance(ctx, dict):
                core_cfg = ctx.get('core_cfg')
                pidfile = ctx.get('remote_pidfile')
                remote_archive = ctx.get('remote_archive')
                if isinstance(core_cfg, dict):
                    kill_info['attempted'] = True
                    if isinstance(pidfile, str) and pidfile.strip():
                        kill_info['pidfile'] = pidfile
                    if isinstance(remote_archive, str) and remote_archive.strip():
                        kill_info['archive'] = remote_archive

                    client = open_ssh_client(core_cfg)
                    try:
                        kill_script = (
                            'set -e; '
                            f"pidfile={shlex_quote(pidfile or '')}; "
                            f"archive={shlex_quote(remote_archive or '')}; "
                            "pidfile_found=0; pid=''; "
                            "if [ -n \"$pidfile\" ] && [ -f \"$pidfile\" ]; then pidfile_found=1; pid=$(cat \"$pidfile\" 2>/dev/null || true); fi; "
                            "term_sent=0; kill_sent=0; "
                            "if [ -n \"$pid\" ]; then "
                            "kill -TERM \"$pid\" 2>/dev/null && term_sent=1 || term_sent=0; "
                            "sleep 0.5; "
                            "kill -KILL \"$pid\" 2>/dev/null && kill_sent=1 || kill_sent=0; "
                            "fi; "
                            "pidfile_removed=0; "
                            "if [ -n \"$pidfile\" ]; then rm -f -- \"$pidfile\" 2>/dev/null && pidfile_removed=1 || pidfile_removed=0; fi; "
                            "archive_existed_before=''; archive_exists_after=''; "
                            "if [ -n \"$archive\" ]; then "
                            "if [ -f \"$archive\" ]; then archive_existed_before=1; else archive_existed_before=0; fi; "
                            "rm -f -- \"$archive\" 2>/dev/null || true; "
                            "if [ -f \"$archive\" ]; then archive_exists_after=1; else archive_exists_after=0; fi; "
                            "fi; "
                            "echo PIDFILE_FOUND=\"$pidfile_found\"; "
                            "echo PID=\"$pid\"; "
                            "echo TERM_SENT=\"$term_sent\"; "
                            "echo KILL_SENT=\"$kill_sent\"; "
                            "echo PIDFILE_REMOVED=\"$pidfile_removed\"; "
                            "echo ARCHIVE_EXISTED_BEFORE=\"$archive_existed_before\"; "
                            "echo ARCHIVE_EXISTS_AFTER=\"$archive_exists_after\""
                        )
                        _code, out, _err = exec_ssh_command(client, f"sh -lc {shlex_quote(kill_script)}", timeout=25.0)
                        for line in (out or '').splitlines():
                            if '=' not in line:
                                continue
                            key, value = line.split('=', 1)
                            key = key.strip().upper()
                            value = value.strip().strip('"')
                            if key == 'PIDFILE_FOUND':
                                kill_info['pidfile_found'] = value == '1'
                            elif key == 'PID':
                                kill_info['pid'] = value or None
                            elif key == 'TERM_SENT':
                                kill_info['term_sent'] = value == '1'
                            elif key == 'KILL_SENT':
                                kill_info['kill_sent'] = value == '1'
                            elif key == 'PIDFILE_REMOVED':
                                kill_info['pidfile_removed'] = value == '1'
                            elif key == 'ARCHIVE_EXISTED_BEFORE':
                                kill_info['archive_existed_before'] = None if value == '' else (value == '1')
                            elif key == 'ARCHIVE_EXISTS_AFTER':
                                kill_info['archive_exists_after'] = None if value == '' else (value == '1')
                    finally:
                        try:
                            client.close()
                        except Exception:
                            pass
        except Exception:
            pass

        return jsonify({'ok': True, 'progress_id': progress_id, 'status': 'cancelled', 'remote': kill_info})

    app.add_url_rule('/core/push_repo/status/<progress_id>', endpoint='core_push_repo_status', view_func=_core_push_repo_status_view, methods=['GET'])
    app.add_url_rule('/core/push_repo/cancel/<progress_id>', endpoint='core_push_repo_cancel', view_func=_core_push_repo_cancel_view, methods=['POST'])
    mark_routes_registered(app, 'core_push_progress_routes')
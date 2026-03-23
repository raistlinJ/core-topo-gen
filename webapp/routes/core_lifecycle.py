from __future__ import annotations

import os
from typing import Any, Callable, Optional

from flask import flash, request
from werkzeug.utils import secure_filename

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    redirect_core_page_with_scenario: Callable[..., Any],
    local_timestamp_safe: Callable[[], str],
    uuid_hex: Callable[[], str],
    validate_core_xml: Callable[[str], tuple[bool, Any]],
    core_config_for_request: Callable[..., dict[str, Any]],
    normalize_core_config: Callable[..., dict[str, Any]],
    upload_file_to_core_host: Callable[[dict[str, Any], str], str],
    remote_core_open_xml_script: Callable[..., str],
    run_remote_python_json: Callable[..., dict[str, Any]],
    remove_remote_file: Callable[[dict[str, Any], str], None],
    update_xml_session_mapping: Callable[..., None],
    write_remote_session_scenario_meta: Callable[..., None],
    execute_remote_core_session_action: Callable[..., None],
    remote_docker_status_script: Callable[[Any], str],
    remote_docker_cleanup_script: Callable[[list[str], Any], str],
    remote_docker_remove_wrapper_images_script: Callable[[Any], str],
    core_host_default: Any,
    core_port_default: Any,
) -> None:
    if not begin_route_registration(app, 'core_lifecycle_routes'):
        return

    def _core_upload_view():
        upload = request.files.get('xml_file')
        if not upload or upload.filename == '':
            flash('No file selected.')
            return redirect_core_page_with_scenario()
        filename = secure_filename(upload.filename)
        if not filename.lower().endswith('.xml'):
            flash('Only .xml allowed.')
            return redirect_core_page_with_scenario()
        dest_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'core')
        os.makedirs(dest_dir, exist_ok=True)
        unique = f"{local_timestamp_safe()}-{uuid_hex()[:6]}"
        path = os.path.join(dest_dir, f'{unique}-{filename}')
        upload.save(path)
        ok, errs = validate_core_xml(path)
        if not ok:
            try:
                os.remove(path)
            except Exception:
                pass
            flash(f'Invalid CORE XML: {errs}')
            return redirect_core_page_with_scenario()
        flash('XML uploaded and validated.')
        return redirect_core_page_with_scenario()

    def _core_start_view():
        xml_path = request.form.get('path')
        if not xml_path:
            flash('Missing XML path')
            return redirect_core_page_with_scenario()
        scenario_label = (request.form.get('scenario') or '').strip()
        ap = os.path.abspath(xml_path)
        if not os.path.exists(ap):
            flash('File not found')
            return redirect_core_page_with_scenario(scenario_hint=scenario_label)
        ok, errs = validate_core_xml(ap)
        if not ok:
            flash(f'Invalid CORE XML: {errs}')
            return redirect_core_page_with_scenario(scenario_hint=scenario_label)
        core_cfg = core_config_for_request(include_password=True)
        cfg = normalize_core_config(core_cfg, include_password=True)
        ssh_user = (cfg.get('ssh_username') or '').strip() or '<unknown>'
        ssh_host = cfg.get('ssh_host') or cfg.get('host') or 'localhost'
        address = f"{cfg.get('host') or core_host_default}:{cfg.get('port') or core_port_default}"
        remote_xml_path: Optional[str] = None
        try:
            remote_xml_path = upload_file_to_core_host(cfg, ap)
        except Exception as exc:
            flash(f'Failed to upload XML to CORE host: {exc}')
            return redirect_core_page_with_scenario(scenario_hint=scenario_label)
        try:
            script = remote_core_open_xml_script(address, remote_xml_path, auto_start=True)
            command_desc = (
                f'remote ssh {ssh_user}@{ssh_host} -> CoreGrpcClient.open_xml {address} ({os.path.basename(ap)})'
            )
            payload = run_remote_python_json(
                cfg,
                script,
                logger=app.logger,
                label='core.open_xml',
                command_desc=command_desc,
            )
        except Exception as exc:
            flash(f'Failed to start CORE session: {exc}')
            return redirect_core_page_with_scenario(scenario_hint=scenario_label)
        finally:
            if remote_xml_path:
                remove_remote_file(cfg, remote_xml_path)
        if payload.get('error'):
            msg = payload.get('error')
            app.logger.warning('[core.start] remote error: %s', msg)
            flash(f'CORE rejected the XML: {msg}')
            tb = payload.get('traceback')
            if tb:
                app.logger.debug('[core.start] traceback: %s', tb)
            return redirect_core_page_with_scenario(scenario_hint=scenario_label)
        sid = payload.get('session_id')
        if sid is None:
            flash('Remote CORE did not return a session id.')
            return redirect_core_page_with_scenario(scenario_hint=scenario_label)
        try:
            sid_int = int(sid)
        except Exception:
            sid_int = sid
        app.logger.info('[core.start] Started session %s via %s (scenario=%r)', sid_int, address, scenario_label)
        update_xml_session_mapping(
            ap,
            sid_int,
            scenario_name=scenario_label or None,
            core_host=cfg.get('host', core_host_default) if isinstance(cfg, dict) else None,
            core_port=cfg.get('port', core_port_default) if isinstance(cfg, dict) else None,
        )
        try:
            write_remote_session_scenario_meta(
                cfg,
                session_id=int(sid_int) if isinstance(sid_int, int) else int(str(sid_int)),
                scenario_name=scenario_label or None,
                scenario_xml_basename=os.path.basename(ap),
                logger=app.logger,
            )
        except Exception:
            pass
        flash(f'Started session {sid_int}.')
        return redirect_core_page_with_scenario(scenario_hint=scenario_label)

    def _core_stop_view():
        sid = request.form.get('session_id')
        if not sid:
            flash('Missing session id')
            return redirect_core_page_with_scenario()
        try:
            sid_int = int(sid)
        except Exception:
            flash('Invalid session id')
            return redirect_core_page_with_scenario()
        core_cfg = core_config_for_request(include_password=True)
        try:
            execute_remote_core_session_action(core_cfg, 'stop', sid_int, logger=app.logger)
            cleanup_containers = 0
            cleanup_images = 0
            cleanup_notes: list[str] = []
            try:
                status_payload = run_remote_python_json(
                    core_cfg,
                    remote_docker_status_script(core_cfg.get('ssh_password')),
                    logger=app.logger,
                    label='docker.status(for stop cleanup)',
                    timeout=60.0,
                )
                names: list[str] = []
                if isinstance(status_payload, dict) and isinstance(status_payload.get('items'), list):
                    for item in status_payload.get('items') or []:
                        if isinstance(item, dict) and item.get('name'):
                            names.append(str(item.get('name')))
                if names:
                    payload = run_remote_python_json(
                        core_cfg,
                        remote_docker_cleanup_script(names, core_cfg.get('ssh_password')),
                        logger=app.logger,
                        label='docker.cleanup(on stop)',
                        timeout=120.0,
                    )
                    if isinstance(payload, dict) and isinstance(payload.get('results'), list):
                        cleanup_containers = len(payload.get('results') or [])
                else:
                    cleanup_notes.append('no docker-compose node containers to cleanup')
            except Exception as exc:
                cleanup_notes.append(f'container cleanup skipped/failed: {exc}')

            try:
                payload = run_remote_python_json(
                    core_cfg,
                    remote_docker_remove_wrapper_images_script(core_cfg.get('ssh_password')),
                    logger=app.logger,
                    label='docker.wrapper_images.cleanup(on stop)',
                    timeout=180.0,
                )
                if isinstance(payload, dict) and isinstance(payload.get('removed'), list):
                    cleanup_images = len(payload.get('removed') or [])
            except Exception as exc:
                cleanup_notes.append(f'wrapper image cleanup skipped/failed: {exc}')

            msg = f'Stopped session {sid_int}.'
            extra = []
            if cleanup_containers:
                extra.append(f'docker containers cleaned={cleanup_containers}')
            if cleanup_images:
                extra.append(f'wrapper images removed={cleanup_images}')
            if cleanup_notes:
                extra.append('; '.join(cleanup_notes)[:240])
            if extra:
                msg = msg + ' ' + ' · '.join(extra)
            flash(msg)
        except Exception as exc:
            flash(f'Failed to stop session: {exc}')
        return redirect_core_page_with_scenario()

    app.add_url_rule('/core/upload', endpoint='core_upload', view_func=_core_upload_view, methods=['POST'])
    app.add_url_rule('/core/start', endpoint='core_start', view_func=_core_start_view, methods=['POST'])
    app.add_url_rule('/core/stop', endpoint='core_stop', view_func=_core_stop_view, methods=['POST'])
    mark_routes_registered(app, 'core_lifecycle_routes')
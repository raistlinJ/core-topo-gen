from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from typing import Any, Callable, Optional

from flask import jsonify, request, send_file
from werkzeug.utils import secure_filename


def register(
    app,
    *,
    runs: dict[str, dict[str, Any]],
    outputs_dir: Callable[[], str],
    flaggen_run_dir_for_id: Callable[[str], str],
    write_sse_marker: Callable[[Any, str, Any], None],
    open_ssh_client: Callable[[dict[str, Any]], Any],
    remote_remove_path: Callable[[Any, str], None],
    find_enabled_generator_by_id: Callable[[str], Optional[dict[str, Any]]],
    is_installed_generator_view: Callable[[dict[str, Any]], bool],
    is_installed_generator_disabled: Callable[..., bool],
    flag_generators_runs_dir: Callable[[], str],
    parse_flag_test_core_cfg_from_form: Callable[[Any], dict[str, Any] | None],
    ensure_core_vm_idle_for_test: Callable[[dict[str, Any]], None],
    start_remote_flag_test_process: Callable[..., dict[str, Any]],
    sync_remote_flag_test_outputs: Callable[[dict[str, Any]], None],
    purge_remote_flag_test_dir: Callable[[dict[str, Any]], None],
    resolve_python_executable: Callable[[], str],
    get_repo_root: Callable[[], str],
    local_timestamp_safe: Callable[[], str],
) -> None:
    """Register Flag Generators test routes.

    Extracted from `webapp.app_backend` to reduce file size while keeping behavior identical.
    """

    def _cleanup_view(run_id: str):
        """Delete all artifacts for a flag-generator test run.

        This is intentionally scoped to outputs/ to avoid deleting arbitrary paths.
        """
        t0 = time.time()
        app.logger.info("[flaggen_test] POST /flag_generators_test/cleanup run_id=%s", run_id)
        meta = runs.get(run_id)
        if meta and meta.get('kind') != 'flag_generator_test':
            app.logger.info("[flaggen_test] cleanup refusing: kind=%r", meta.get('kind'))
            return jsonify({'ok': False, 'error': 'not found'}), 404

        run_dir = meta.get('run_dir') if isinstance(meta, dict) else None
        if not isinstance(run_dir, str) or not run_dir:
            run_dir = flaggen_run_dir_for_id(run_id)
        if not isinstance(run_dir, str) or not run_dir:
            app.logger.warning("[flaggen_test] cleanup missing run dir run_id=%s", run_id)
            return jsonify({'ok': False, 'error': 'missing run dir'}), 500

        abs_run_dir = os.path.abspath(run_dir)
        outputs_root = os.path.abspath(outputs_dir())
        if not (abs_run_dir == outputs_root or abs_run_dir.startswith(outputs_root + os.sep)):
            app.logger.warning(
                "[flaggen_test] cleanup refusing run_id=%s abs_run_dir=%s outputs_root=%s",
                run_id,
                abs_run_dir,
                outputs_root,
            )
            return jsonify({'ok': False, 'error': 'refusing'}), 400

        app.logger.info(
            "[flaggen_test] cleanup resolved run_id=%s run_dir=%s exists=%s",
            run_id,
            abs_run_dir,
            os.path.isdir(abs_run_dir),
        )

        # Best-effort: stop any still-running runner process.
        try:
            if isinstance(meta, dict):
                meta['cleanup_requested'] = True
                if meta.get('remote'):
                    try:
                        channel = meta.get('ssh_channel')
                        if channel is not None and hasattr(channel, 'close'):
                            channel.close()
                    except Exception:
                        pass
                    try:
                        client_obj = meta.get('ssh_client')
                        if client_obj is not None:
                            client_obj.close()
                    except Exception:
                        pass
                    try:
                        core_cfg = meta.get('core_cfg') if isinstance(meta.get('core_cfg'), dict) else None
                        remote_run_dir = str(meta.get('remote_run_dir') or '').strip()
                        if core_cfg and remote_run_dir:
                            _client = open_ssh_client(core_cfg)
                            try:
                                remote_remove_path(_client, remote_run_dir)
                            finally:
                                _client.close()
                    except Exception:
                        pass
            proc = meta.get('proc') if isinstance(meta, dict) else None
            if proc and hasattr(proc, 'poll') and proc.poll() is None:
                try:
                    app.logger.info("[flaggen_test] cleanup terminating runner run_id=%s", run_id)
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        app.logger.info("[flaggen_test] cleanup killing runner run_id=%s", run_id)
                        proc.kill()
                    except Exception:
                        pass
        except Exception:
            pass

        # Emit cleanup markers to the log if possible.
        try:
            lp = meta.get('log_path') if isinstance(meta, dict) else os.path.join(abs_run_dir, 'run.log')
            if isinstance(lp, str) and lp:
                with open(lp, 'a', encoding='utf-8') as log_f:
                    write_sse_marker(log_f, 'phase', {'phase': 'cleanup_start', 'run_id': run_id})
        except Exception:
            pass

        removed = False
        try:
            if os.path.isdir(abs_run_dir):
                shutil.rmtree(abs_run_dir, ignore_errors=True)
            removed = True
        except Exception:
            removed = False

        app.logger.info(
            "[flaggen_test] cleanup removed=%s run_id=%s elapsed_ms=%d",
            removed,
            run_id,
            int((time.time() - t0) * 1000),
        )

        try:
            if isinstance(meta, dict):
                meta['done'] = True
        except Exception:
            pass

        try:
            if isinstance(meta, dict):
                lp = meta.get('log_path')
            else:
                lp = os.path.join(abs_run_dir, 'run.log')
            if isinstance(lp, str) and lp and os.path.exists(lp):
                with open(lp, 'a', encoding='utf-8') as log_f2:
                    write_sse_marker(log_f2, 'phase', {'phase': 'cleanup_done', 'run_id': run_id, 'removed': removed})
        except Exception:
            pass

        try:
            runs.pop(run_id, None)
        except Exception:
            pass

        app.logger.info(
            "[flaggen_test] cleanup complete run_id=%s elapsed_ms=%d",
            run_id,
            int((time.time() - t0) * 1000),
        )

        return jsonify({'ok': True, 'removed': removed}), 200

    def _run_view():
        """Start a generator test run."""
        t0 = time.time()
        generator_id = (request.form.get('generator_id') or '').strip()
        try:
            app.logger.info("[flaggen_test] POST /flag_generators_test/run generator_id=%s", generator_id)
        except Exception:
            pass

        gen = find_enabled_generator_by_id(generator_id)
        if not gen:
            try:
                app.logger.warning("[flaggen_test] generator not found: %s", generator_id)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': 'Generator not found (must be in an enabled source).'}), 404

        # Respect disabled state for installed generators.
        try:
            if (
                isinstance(gen, dict)
                and is_installed_generator_view(gen)
                and is_installed_generator_disabled(kind='flag-generator', generator_id=generator_id)
            ):
                return jsonify({'ok': False, 'error': f'Generator {generator_id} is disabled.'}), 400
        except Exception:
            pass

        run_id = local_timestamp_safe() + '-' + uuid.uuid4().hex[:10]
        run_dir = os.path.join(flag_generators_runs_dir(), run_id)
        inputs_dir = os.path.join(run_dir, 'inputs')
        os.makedirs(inputs_dir, exist_ok=True)
        log_path = os.path.join(run_dir, 'run.log')

        # Build config object from declared inputs.
        cfg: dict[str, Any] = {}
        saved_uploads: dict[str, dict[str, Any]] = {}
        inputs = gen.get('inputs') if isinstance(gen, dict) else None
        inputs_list = inputs if isinstance(inputs, list) else []

        for inp in inputs_list:
            if not isinstance(inp, dict):
                continue
            name = str(inp.get('name') or '').strip()
            if not name:
                continue
            raw_val = request.form.get(name)
            if raw_val is not None:
                cfg[name] = raw_val

        def _unique_dest_filename(dir_path: str, filename: str) -> str:
            base = secure_filename(filename) or 'upload'
            cand = base
            root, ext = os.path.splitext(base)
            i = 1
            while os.path.exists(os.path.join(dir_path, cand)):
                cand = f"{root}_{i}{ext}"
                i += 1
                if i > 5000:
                    break
            return cand

        for inp in inputs_list:
            if not isinstance(inp, dict):
                continue
            name = str(inp.get('name') or '').strip()
            if not name:
                continue
            f = request.files.get(name)
            if not (f and getattr(f, 'filename', '')):
                continue

            original_filename = str(getattr(f, 'filename', '') or '')
            safe_uploaded = secure_filename(original_filename) or 'upload'
            stored = f"{name}__{safe_uploaded}"

            desired = None
            try:
                if name == 'input_file':
                    desired = cfg.get('File(path)')
            except Exception:
                desired = None

            requested_filename = None
            used_requested = False
            if isinstance(desired, str) and desired.strip():
                requested_filename = desired.strip()
                stored = _unique_dest_filename(inputs_dir, requested_filename)
                used_requested = True
            else:
                stored = _unique_dest_filename(inputs_dir, stored)

            dest = os.path.join(inputs_dir, stored)
            try:
                f.save(dest)
                cfg[name] = f"/inputs/{stored}"
                saved_uploads[name] = {
                    'original_filename': original_filename,
                    'requested_filename': requested_filename,
                    'stored_filename': stored,
                    'stored_path': f"inputs/{stored}",
                    'container_path': f"/inputs/{stored}",
                    'used_requested_filename': used_requested,
                }
            except Exception:
                return jsonify({'ok': False, 'error': f"Failed saving file input: {name}"}), 400

        try:
            app.logger.info("[flaggen_test] inputs keys=%s", sorted(list(cfg.keys())))
        except Exception:
            pass

        missing: list[str] = []
        for inp in inputs_list:
            if not isinstance(inp, dict):
                continue
            try:
                if not inp.get('required'):
                    continue
                name = str(inp.get('name') or '').strip()
                if not name:
                    continue
                val = cfg.get(name)
                if val is None or (isinstance(val, str) and not val.strip()):
                    missing.append(name)
            except Exception:
                continue
        if missing:
            try:
                app.logger.warning("[flaggen_test] missing required inputs: %s", missing)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': f"Missing required input(s): {', '.join(missing)}"}), 400

        core_cfg: dict[str, Any] | None = None
        try:
            core_cfg = parse_flag_test_core_cfg_from_form(request.form)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'CORE VM SSH config required: {exc}'}), 400
        if core_cfg:
            try:
                ensure_core_vm_idle_for_test(core_cfg)
            except Exception as exc:
                return jsonify({'ok': False, 'error': str(exc)}), 409

        if core_cfg:
            try:
                with open(log_path, 'a', encoding='utf-8') as log_f:
                    log_f.write(f"[flaggen] starting {generator_id} (remote CORE VM)\n")
                    write_sse_marker(log_f, 'phase', {
                        'phase': 'starting',
                        'generator_id': generator_id,
                        'run_id': run_id,
                        'remote': True,
                    })
            except Exception:
                pass

            try:
                log_handle = open(log_path, 'a', encoding='utf-8')
                remote_meta = start_remote_flag_test_process(
                    run_id=run_id,
                    run_dir=run_dir,
                    log_handle=log_handle,
                    kind='flag-generator',
                    generator_id=generator_id,
                    cfg=cfg,
                    core_cfg=core_cfg,
                )
            except Exception as exc:
                try:
                    with open(log_path, 'a', encoding='utf-8') as log_f:
                        log_f.write(f"[flaggen] failed to start remote run: {exc}\n")
                        write_sse_marker(log_f, 'phase', {'phase': 'error', 'error': str(exc)})
                except Exception:
                    pass
                return jsonify({'ok': False, 'error': f"Failed launching remote generator: {exc}"}), 500

            runs[run_id] = {
                'proc': None,
                'log_path': log_path,
                'done': False,
                'returncode': None,
                'run_dir': run_dir,
                'kind': 'flag_generator_test',
                'generator_id': generator_id,
                'remote': True,
                'core_cfg': core_cfg,
                'remote_run_dir': remote_meta.get('remote_run_dir'),
                'remote_repo_dir': remote_meta.get('remote_repo_dir'),
                'ssh_client': remote_meta.get('ssh_client'),
                'ssh_channel': remote_meta.get('ssh_channel'),
                'ssh_log_thread': remote_meta.get('ssh_log_thread'),
                'ssh_log_handle': log_handle,
                'cleanup_requested': False,
            }

            def _finalize_remote_flaggen(run_id_local: str):
                meta = runs.get(run_id_local)
                if not isinstance(meta, dict):
                    return
                rc = -1
                try:
                    ch = meta.get('ssh_channel')
                    if ch is not None:
                        while True:
                            try:
                                if ch.exit_status_ready():
                                    rc = int(ch.recv_exit_status())
                                    break
                            except Exception:
                                break
                            time.sleep(0.5)
                finally:
                    meta['done'] = True
                    meta['returncode'] = rc
                    try:
                        with open(meta.get('log_path'), 'a', encoding='utf-8') as log_f:
                            write_sse_marker(log_f, 'phase', {'phase': 'done', 'returncode': rc})
                    except Exception:
                        pass
                    try:
                        if not meta.get('cleanup_requested'):
                            sync_remote_flag_test_outputs(meta)
                    except Exception:
                        pass
                    try:
                        purge_remote_flag_test_dir(meta)
                    except Exception:
                        pass
                    try:
                        thread_obj = meta.get('ssh_log_thread')
                        if thread_obj and hasattr(thread_obj, 'join'):
                            thread_obj.join(timeout=3)
                    except Exception:
                        pass
                    try:
                        client_obj = meta.get('ssh_client')
                        if client_obj:
                            client_obj.close()
                    except Exception:
                        pass
                    try:
                        handle = meta.get('ssh_log_handle')
                        if handle:
                            handle.flush()
                            handle.close()
                    except Exception:
                        pass

            threading.Thread(
                target=_finalize_remote_flaggen,
                args=(run_id,),
                name=f'flaggen-remote-{run_id[:8]}',
                daemon=True,
            ).start()

            try:
                app.logger.info(
                    "[flaggen_test] remote run_id=%s run_dir=%s elapsed_ms=%s",
                    run_id,
                    run_dir,
                    int((time.time() - t0) * 1000),
                )
            except Exception:
                pass
            return jsonify({'ok': True, 'run_id': run_id, 'saved_uploads': saved_uploads})

        repo_root = get_repo_root()
        runner_path = os.path.join(repo_root, 'scripts', 'run_flag_generator.py')
        cmd = [
            resolve_python_executable(),
            runner_path,
            '--kind',
            'flag-generator',
            '--generator-id',
            generator_id,
            '--out-dir',
            run_dir,
            '--config',
            json.dumps(cfg, ensure_ascii=False),
            '--repo-root',
            repo_root,
        ]

        try:
            with open(log_path, 'a', encoding='utf-8') as log_f:
                log_f.write(f"[flaggen] starting {generator_id}\n")
                write_sse_marker(log_f, 'phase', {
                    'phase': 'starting',
                    'generator_id': generator_id,
                    'run_id': run_id,
                })
        except Exception:
            pass

        try:
            log_handle = open(log_path, 'a', encoding='utf-8')
            env = dict(os.environ)
            env.setdefault('CORETG_DOCKER_USE_SUDO', '0')
            env.setdefault('CORETG_DOCKER_HOST_NETWORK', '1')
            proc = subprocess.Popen(
                cmd,
                cwd=repo_root,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=log_handle,
                text=True,
                env=env,
            )
        except Exception as exc:
            try:
                with open(log_path, 'a', encoding='utf-8') as log_f:
                    log_f.write(f"[flaggen] failed to start: {exc}\n")
                    write_sse_marker(log_f, 'phase', {'phase': 'error', 'error': str(exc)})
            except Exception:
                pass
            return jsonify({'ok': False, 'error': f"Failed launching generator: {exc}"}), 500

        try:
            app.logger.info(
                "[flaggen_test] spawned pid=%s run_id=%s run_dir=%s elapsed_ms=%s",
                getattr(proc, 'pid', None),
                run_id,
                run_dir,
                int((time.time() - t0) * 1000),
            )
        except Exception:
            pass

        runs[run_id] = {
            'proc': proc,
            'log_path': log_path,
            'done': False,
            'returncode': None,
            'run_dir': run_dir,
            'kind': 'flag_generator_test',
            'generator_id': generator_id,
        }

        def _finalize_flaggen(run_id_local: str, log_handle_local: Any):
            try:
                meta = runs.get(run_id_local)
                if not meta:
                    return
                p = meta.get('proc')
                if not p:
                    return
                rc = p.wait()
                meta['done'] = True
                meta['returncode'] = rc
                try:
                    with open(meta.get('log_path'), 'a', encoding='utf-8') as log_f:
                        write_sse_marker(log_f, 'phase', {'phase': 'done', 'returncode': rc})
                except Exception:
                    pass
            finally:
                try:
                    log_handle_local.close()
                except Exception:
                    pass

        threading.Thread(
            target=_finalize_flaggen,
            args=(run_id, log_handle),
            name=f'flaggen-{run_id[:8]}',
            daemon=True,
        ).start()

        try:
            app.logger.info(
                "[flaggen_test] responding ok run_id=%s elapsed_ms=%s",
                run_id,
                int((time.time() - t0) * 1000),
            )
        except Exception:
            pass
        return jsonify({'ok': True, 'run_id': run_id, 'saved_uploads': saved_uploads})

    def _outputs_view(run_id: str):
        meta = runs.get(run_id)
        if meta and meta.get('kind') != 'flag_generator_test':
            return jsonify({'ok': False, 'error': 'not found'}), 404

        run_dir = meta.get('run_dir') if isinstance(meta, dict) else None
        if not isinstance(run_dir, str) or not run_dir:
            run_dir = flaggen_run_dir_for_id(run_id)
        if not isinstance(run_dir, str) or not run_dir:
            return jsonify({'ok': False, 'error': 'missing run dir'}), 500

        abs_run_dir = os.path.abspath(run_dir)
        outputs_root = os.path.abspath(outputs_dir())
        if not (abs_run_dir == outputs_root or abs_run_dir.startswith(outputs_root + os.sep)):
            return jsonify({'ok': False, 'error': 'refusing'}), 400

        if not os.path.isdir(abs_run_dir):
            done = bool(meta.get('done')) if isinstance(meta, dict) else False
            returncode = meta.get('returncode') if isinstance(meta, dict) else None
            return jsonify({'ok': True, 'files': [], 'done': done, 'returncode': returncode}), 200

        input_files: list[dict[str, Any]] = []
        output_files: list[dict[str, Any]] = []
        misc_files: list[dict[str, Any]] = []

        for root, _dirs, filenames in os.walk(abs_run_dir):
            rel_root = os.path.relpath(root, abs_run_dir).replace('\\', '/')
            for fn in filenames:
                abs_path = os.path.join(root, fn)
                try:
                    st = os.stat(abs_path)
                    rel = os.path.relpath(abs_path, abs_run_dir).replace('\\', '/')
                    entry = {'path': rel, 'name': fn, 'size': st.st_size}
                except Exception:
                    continue

                if rel_root == 'inputs' or rel_root.startswith('inputs/'):
                    input_files.append(entry)
                elif rel == 'run.log':
                    misc_files.append(entry)
                else:
                    output_files.append(entry)

        input_files.sort(key=lambda x: x.get('path') or '')
        output_files.sort(key=lambda x: x.get('path') or '')
        misc_files.sort(key=lambda x: x.get('path') or '')

        done = bool(meta.get('done')) if isinstance(meta, dict) else True
        returncode = meta.get('returncode') if isinstance(meta, dict) else None
        return jsonify({
            'ok': True,
            'inputs': input_files,
            'outputs': output_files,
            'misc': misc_files,
            'done': done,
            'returncode': returncode,
        }), 200

    def _download_view(run_id: str):
        meta = runs.get(run_id)
        if meta and meta.get('kind') != 'flag_generator_test':
            return jsonify({'ok': False, 'error': 'not found'}), 404

        run_dir = meta.get('run_dir') if isinstance(meta, dict) else None
        if not isinstance(run_dir, str) or not run_dir:
            run_dir = flaggen_run_dir_for_id(run_id)
        if not isinstance(run_dir, str) or not run_dir:
            return jsonify({'ok': False, 'error': 'missing run dir'}), 500

        rel = (request.args.get('p') or '').strip().lstrip('/').replace('\\', '/')
        if not rel:
            return jsonify({'ok': False, 'error': 'invalid path'}), 400

        abs_run_dir = os.path.abspath(run_dir)
        outputs_root = os.path.abspath(outputs_dir())
        if not (abs_run_dir == outputs_root or abs_run_dir.startswith(outputs_root + os.sep)):
            return jsonify({'ok': False, 'error': 'refusing'}), 400

        abs_path = os.path.abspath(os.path.join(abs_run_dir, rel))
        if not (abs_path == abs_run_dir or abs_path.startswith(abs_run_dir + os.sep)):
            return jsonify({'ok': False, 'error': 'refusing'}), 400

        if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
            return jsonify({'ok': False, 'error': 'missing file'}), 404

        return send_file(abs_path, as_attachment=True, download_name=os.path.basename(abs_path))

    def _bundle_view(run_id: str):
        # Kept for backward compatibility with existing UI links.
        return jsonify({'ok': False, 'error': 'bundle.zip output disabled'}), 404

    app.add_url_rule(
        '/flag_generators_test/cleanup/<run_id>',
        endpoint='flag_generators_test_cleanup',
        view_func=_cleanup_view,
        methods=['POST'],
    )
    app.add_url_rule(
        '/flag_generators_test/run',
        endpoint='flag_generators_test_run',
        view_func=_run_view,
        methods=['POST'],
    )
    app.add_url_rule(
        '/flag_generators_test/outputs/<run_id>',
        endpoint='flag_generators_test_outputs',
        view_func=_outputs_view,
        methods=['GET'],
    )
    app.add_url_rule(
        '/flag_generators_test/download/<run_id>',
        endpoint='flag_generators_test_download',
        view_func=_download_view,
        methods=['GET'],
    )
    app.add_url_rule(
        '/flag_generators_test/bundle/<run_id>',
        endpoint='flag_generators_test_bundle',
        view_func=_bundle_view,
        methods=['GET'],
    )

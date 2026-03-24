from __future__ import annotations

import json
import shlex
from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def _prefer_explicit_or_ssh_core_host(raw_core: Any, core_cfg: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(core_cfg, dict):
        return core_cfg
    payload = raw_core if isinstance(raw_core, dict) else {}
    explicit_host = str(payload.get('grpc_host') or payload.get('host') or '').strip()
    explicit_secret_id = str(payload.get('core_secret_id') or payload.get('secret_id') or '').strip()
    if explicit_host or explicit_secret_id:
        return core_cfg
    ssh_host = str(payload.get('ssh_host') or core_cfg.get('ssh_host') or '').strip()
    if not ssh_host:
        return core_cfg
    adjusted = dict(core_cfg)
    adjusted['host'] = ssh_host
    adjusted['grpc_host'] = ssh_host
    return adjusted


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'vuln_catalog_test_start_routes'):
        return

    backend = backend_module

    @app.route('/vuln_catalog_items/test/start', methods=['POST'])
    def vuln_catalog_items_test_start():
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        force_replace = bool(payload.get('force_replace') or payload.get('replace'))
        execute_like_real = backend._coerce_bool(
            payload.get('execute_like_real') if isinstance(payload, dict) and 'execute_like_real' in payload else True
        )
        cleanup_generated_artifacts = True
        try:
            if 'cleanup_generated_artifacts' in payload:
                cleanup_generated_artifacts = backend._coerce_bool(payload.get('cleanup_generated_artifacts'))
        except Exception:
            cleanup_generated_artifacts = True
        item_id_raw = payload.get('item_id')
        try:
            item_id = int(item_id_raw)
        except Exception:
            return jsonify({'ok': False, 'error': 'Invalid item_id'}), 400

        state = backend._load_vuln_catalogs_state()
        entry = backend._get_active_vuln_catalog_entry(state)
        if not entry:
            return jsonify({'ok': False, 'error': 'No active catalog pack'}), 404
        catalog_id = str(entry.get('id') or '').strip()
        items = backend._normalize_vuln_catalog_items(entry)
        target = None
        for item in items:
            if int(item.get('id') or 0) == item_id:
                target = item
                break
        if not target:
            return jsonify({'ok': False, 'error': 'Unknown item id'}), 404

        try:
            compose_path = backend._vuln_catalog_item_abs_compose_path(catalog_id=catalog_id, item=target)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Invalid compose path: {exc}'}), 400
        if not backend.os.path.isfile(compose_path):
            return jsonify({'ok': False, 'error': 'docker-compose.yml not found'}), 404

        try:
            for meta in backend.RUNS.values():
                if isinstance(meta, dict) and meta.get('kind') == 'vuln_test' and not meta.get('done'):
                    return jsonify({'ok': False, 'error': 'Another vulnerability test is already running'}), 409
        except Exception:
            pass

        run_id = str(backend.uuid.uuid4())[:12]
        project_name = f"coretg-vuln-test-{item_id}-{int(backend.time.time())}"
        run_dir = backend.os.path.join(backend._outputs_dir(), 'vuln-tests', f'test-{run_id}')
        backend.os.makedirs(run_dir, exist_ok=True)
        log_path = backend.os.path.join(run_dir, 'run.log')

        try:
            raw_core = payload.get('core')
            core_cfg = backend._merge_core_configs(raw_core, include_password=True)
            core_cfg = _prefer_explicit_or_ssh_core_host(raw_core, core_cfg)
            if not core_cfg.get('host'):
                core_cfg['host'] = core_cfg.get('ssh_host') or '127.0.0.1'
            if not core_cfg.get('port'):
                core_cfg['port'] = backend.CORE_PORT
            core_cfg = backend._require_core_ssh_credentials(core_cfg)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'CORE VM SSH config required: {exc}'}), 400

        try:
            errors: list[str] = []
            host = str(core_cfg.get('host') or '127.0.0.1')
            port = int(core_cfg.get('port') or backend.CORE_PORT)
            sessions = backend._list_active_core_sessions(host, port, core_cfg, errors=errors, meta={})
            if errors:
                return jsonify({'ok': False, 'error': f'Unable to verify CORE sessions: {errors[0]}'}), 409
            if sessions:
                return jsonify({'ok': False, 'error': 'CORE VM has active session(s). Stop running scenario before testing.'}), 409
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Unable to verify CORE sessions: {exc}'}), 409

        if execute_like_real:
            item_name = str(target.get('name') or target.get('Name') or target.get('Title') or f'vuln-{item_id}')
            prepared_compose_path = compose_path
            try:
                from core_topo_gen.utils.vuln_process import prepare_compose_for_assignments

                node_name = f'vuln-test-{item_id}'
                rec = {
                    'Name': item_name,
                    'Path': compose_path,
                    'Type': 'docker-compose',
                    'ScenarioTag': f'vuln-test-{item_id}',
                }
                created = prepare_compose_for_assignments({node_name: rec}, out_base=run_dir)
                if created:
                    prepared_compose_path = created[0]
            except Exception:
                prepared_compose_path = compose_path

            job_spec, build_err = backend._vuln_test_build_ephemeral_execute_job(
                run_dir=run_dir,
                run_id=run_id,
                core_cfg=core_cfg,
                item_id=item_id,
                item_name=item_name,
                compose_path=prepared_compose_path,
            )
            if not isinstance(job_spec, dict):
                return jsonify({'ok': False, 'error': str(build_err or 'failed to prepare execute-like-real vulnerability test')}), 500

            try:
                with open(log_path, 'a', encoding='utf-8') as log_f:
                    log_f.write(f'[vuln-test] starting execute-like-real item_id={item_id}\n')
                    backend._write_sse_marker(
                        log_f,
                        'phase',
                        {
                            'phase': 'starting',
                            'run_id': run_id,
                            'item_id': item_id,
                            'execute_like_real': True,
                        },
                    )
            except Exception:
                pass

            backend.RUNS[run_id] = {
                'kind': 'vuln_test',
                'proc': None,
                'log_path': log_path,
                'run_dir': run_dir,
                'done': False,
                'returncode': None,
                'status': 'executing',
                'cleanup_started': False,
                'cleanup_done': False,
                'catalog_id': catalog_id,
                'item_id': item_id,
                'core_cfg': core_cfg,
                'cleanup_generated_artifacts': bool(cleanup_generated_artifacts),
                'execute_like_real': True,
                'compose_path_raw': compose_path,
                'compose_path_prepared': prepared_compose_path,
                'test_docker_node_id': str(job_spec.get('test_docker_node_id') or '').strip(),
                'test_docker_node_name': str(job_spec.get('test_docker_node_name') or '').strip(),
                'test_scenario_tag': str(job_spec.get('test_scenario_tag') or '').strip(),
            }

            try:
                backend.threading.Thread(
                    target=backend._run_cli_background_task,
                    args=(run_id, job_spec),
                    name=f'vuln-test-exec-{run_id[:8]}',
                    daemon=True,
                ).start()
            except Exception as exc:
                backend.RUNS.pop(run_id, None)
                return jsonify({'ok': False, 'error': f'failed to start execute-like-real vulnerability test: {exc}'}), 500

            return jsonify(
                {
                    'ok': True,
                    'run_id': run_id,
                    'cleanup_generated_artifacts': bool(cleanup_generated_artifacts),
                    'execute_like_real': True,
                }
            )

        remote_run_dir = f'/tmp/tests/test-{run_id}'
        prepared_compose_path = compose_path
        try:
            from core_topo_gen.utils.vuln_process import prepare_compose_for_assignments

            node_name = f'vuln-test-{item_id}'
            rec = {
                'Name': str(target.get('name') or target.get('Name') or target.get('Title') or f'vuln-{item_id}'),
                'Path': compose_path,
                'Type': 'docker-compose',
                'ScenarioTag': f'vuln-test-{item_id}',
            }
            created = prepare_compose_for_assignments({node_name: rec}, out_base=run_dir)
            if created:
                prepared_compose_path = created[0]
        except Exception:
            prepared_compose_path = compose_path

        def _rewrite_compose_paths_for_remote(compose_path: str, local_base: str, remote_base: str) -> None:
            try:
                import yaml

                with open(compose_path, 'r', encoding='utf-8') as file_handle:
                    compose_obj = yaml.safe_load(file_handle)
                if not isinstance(compose_obj, dict):
                    return
                services = compose_obj.get('services')
                if not isinstance(services, dict):
                    return
                for _svc_name, svc in services.items():
                    if not isinstance(svc, dict):
                        continue
                    build = svc.get('build')
                    if isinstance(build, dict):
                        ctx = build.get('context')
                        if isinstance(ctx, str) and ctx.startswith(local_base):
                            rel = backend.os.path.relpath(ctx, local_base)
                            build['context'] = backend._remote_path_join(remote_base, rel)
                    labels = svc.get('labels')
                    if isinstance(labels, dict):
                        for key, value in list(labels.items()):
                            try:
                                if not isinstance(value, str):
                                    continue
                                if value.startswith(local_base):
                                    rel = backend.os.path.relpath(value, local_base)
                                    labels[key] = backend._remote_path_join(remote_base, rel)
                            except Exception:
                                continue
                    volumes = svc.get('volumes')
                    if isinstance(volumes, list):
                        new_volumes = []
                        for vol in volumes:
                            if isinstance(vol, str) and ':' in vol:
                                parts = vol.split(':', 2)
                                src = parts[0]
                                if src.startswith(local_base):
                                    rel = backend.os.path.relpath(src, local_base)
                                    parts[0] = backend._remote_path_join(remote_base, rel)
                                    new_volumes.append(':'.join(parts))
                                else:
                                    new_volumes.append(vol)
                            else:
                                new_volumes.append(vol)
                        svc['volumes'] = new_volumes
                with open(compose_path, 'w', encoding='utf-8') as file_handle:
                    yaml.safe_dump(compose_obj, file_handle, sort_keys=False)
            except Exception:
                pass

        def _summarize_compose_for_log(path: str) -> list[str]:
            lines: list[str] = []
            try:
                import yaml

                with open(path, 'r', encoding='utf-8') as file_handle:
                    obj = yaml.safe_load(file_handle) or {}
                if not isinstance(obj, dict):
                    return lines
                services = obj.get('services') if isinstance(obj, dict) else None
                if not isinstance(services, dict) or not services:
                    return lines
                lines.append(f'[local] compose services={len(services)}')
                inject_helpers = [key for key in services.keys() if str(key).startswith('inject_copy')]
                if inject_helpers:
                    lines.append(f"[local] inject helper(s): {', '.join(inject_helpers)}")
                for svc_name, svc in services.items():
                    if not isinstance(svc, dict):
                        continue
                    img = str(svc.get('image') or '').strip()
                    build = svc.get('build')
                    ctx = ''
                    if isinstance(build, dict):
                        ctx = str(build.get('context') or '').strip()
                    vols = svc.get('volumes') if isinstance(svc, dict) else None
                    vcount = len(vols) if isinstance(vols, list) else 0
                    labels = svc.get('labels') if isinstance(svc, dict) else None
                    has_flow_label = False
                    if isinstance(labels, dict):
                        for key in labels.keys():
                            if str(key).startswith('coretg.flow_artifacts.'):
                                has_flow_label = True
                                break
                    elif isinstance(labels, list):
                        for item in labels:
                            if isinstance(item, str) and item.startswith('coretg.flow_artifacts.'):
                                has_flow_label = True
                                break
                    parts: list[str] = []
                    if img:
                        parts.append(f'image={img}')
                    if ctx:
                        parts.append(f'build={ctx}')
                    if vcount:
                        parts.append(f'volumes={vcount}')
                    if has_flow_label:
                        parts.append('flow_artifacts_label=1')
                    if parts:
                        lines.append(f"[local] service {svc_name}: " + ', '.join(parts))
            except Exception:
                return lines
            return lines

        if prepared_compose_path != compose_path:
            _rewrite_compose_paths_for_remote(prepared_compose_path, run_dir, remote_run_dir)

        preflight_ok, preflight_error, preflight_meta = backend._core_like_compose_template_preflight(prepared_compose_path)
        if not preflight_ok:
            return jsonify(
                {
                    'ok': False,
                    'error': preflight_error or 'Prepared docker-compose failed template preflight',
                    'compose_path': prepared_compose_path,
                    'preflight': preflight_meta,
                }
            ), 422

        def _compose_images_and_containers(path: str) -> tuple[list[str], list[str]]:
            images: list[str] = []
            containers: list[str] = []
            try:
                import yaml

                with open(path, 'r', encoding='utf-8') as file_handle:
                    obj = yaml.safe_load(file_handle) or {}
                services = obj.get('services') if isinstance(obj, dict) else None
                if not isinstance(services, dict):
                    return images, containers
                for _svc_name, svc in services.items():
                    if not isinstance(svc, dict):
                        continue
                    img = svc.get('image')
                    if isinstance(img, str) and img.strip():
                        images.append(img.strip())
                    cname = svc.get('container_name')
                    if isinstance(cname, str) and cname.strip():
                        containers.append(cname.strip())
            except Exception:
                pass
            images = list(dict.fromkeys(images))
            containers = list(dict.fromkeys(containers))
            return images, containers

        def _exec_ssh_sudo_capture(client: Any, command: str, password: str | None) -> tuple[int, str, str]:
            channel = client.get_transport().open_session() if client.get_transport() else None
            if channel is None:
                return 1, '', 'SSH channel unavailable'
            try:
                channel.get_pty()
            except Exception:
                pass
            channel.exec_command(command)
            try:
                if password:
                    channel.send(str(password) + '\n')
            except Exception:
                pass
            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []
            while True:
                try:
                    if channel.recv_ready():
                        stdout_chunks.append(channel.recv(backend.REMOTE_LOG_CHUNK_SIZE))
                    if channel.recv_stderr_ready():
                        stderr_chunks.append(channel.recv_stderr(backend.REMOTE_LOG_CHUNK_SIZE))
                    if channel.exit_status_ready():
                        if not channel.recv_ready() and not channel.recv_stderr_ready():
                            break
                except Exception:
                    break
                backend.time.sleep(0.15)
            try:
                rc = int(channel.recv_exit_status())
            except Exception:
                rc = 0
            try:
                out = b''.join(stdout_chunks).decode('utf-8', 'replace')
            except Exception:
                out = b''.join(stdout_chunks).decode('latin-1', 'replace')
            try:
                err = b''.join(stderr_chunks).decode('utf-8', 'replace')
            except Exception:
                err = b''.join(stderr_chunks).decode('latin-1', 'replace')
            return rc, out.strip(), err.strip()

        def _remote_compose_preflight(
            *,
            ssh_client: Any,
            core_cfg: dict[str, Any],
            compose_path: str,
            project_name: str,
            node_service: str,
            password: str,
            log_handle: Any,
        ) -> tuple[bool, str | None]:
            try:
                log_handle.write('[remote] preflight: begin\n')
            except Exception:
                pass
            try:
                py = backend._select_remote_python_interpreter(ssh_client, core_cfg or {})
            except Exception:
                py = 'python3'

            parse_script = (
                "import json\n"
                "try:\n"
                "  import yaml\n"
                "except Exception:\n"
                "  yaml=None\n"
                "p=%r\n"
                "obj={}\n"
                "if yaml is not None:\n"
                "  try:\n"
                "    obj=yaml.safe_load(open(p,'r',encoding='utf-8',errors='ignore')) or {}\n"
                "  except Exception:\n"
                "    obj={}\n"
                "services=(obj.get('services') if isinstance(obj,dict) else None)\n"
                "wrap=[]\n"
                "pull=[]\n"
                "if isinstance(services,dict):\n"
                "  for name,svc in services.items():\n"
                "    if not isinstance(svc,dict):\n"
                "      continue\n"
                "    img=str(svc.get('image') or '').strip()\n"
                "    labs=svc.get('labels') if isinstance(svc.get('labels'),dict) else {}\n"
                "    ctx=str(labs.get('coretg.wrapper_build_context') or '').strip()\n"
                "    df=str(labs.get('coretg.wrapper_build_dockerfile') or 'Dockerfile').strip()\n"
                "    net=str(labs.get('coretg.wrapper_build_network') or 'host').strip()\n"
                "    if img and img.startswith('coretg/') and img.endswith(':iproute2') and ctx:\n"
                "      wrap.append({'service':str(name),'image':img,'context':ctx,'dockerfile':df,'network':net})\n"
                "      continue\n"
                "    if svc.get('build'):\n"
                "      continue\n"
                "    try:\n"
                "      if str(svc.get('pull_policy') or '').strip().lower()=='never':\n"
                "        continue\n"
                "    except Exception:\n"
                "      pass\n"
                "    if img and not img.startswith('coretg/'):\n"
                "      pull.append(str(name))\n"
                "print(json.dumps({'wrap':wrap,'pull':pull},ensure_ascii=False))\n"
            ) % (compose_path,)

            inner = f"{shlex.quote(py)} -c {shlex.quote(parse_script)}"
            cmd = f"bash -lc {shlex.quote(inner)}"
            rc, out, err = _exec_ssh_sudo_capture(ssh_client, cmd, password)
            if rc != 0:
                try:
                    log_handle.write(f'[remote] preflight: failed to parse compose rc={rc} err={err or out}\n')
                except Exception:
                    pass
                return False, 'failed to parse compose on CORE VM'

            try:
                payload = json.loads((out or '').strip() or '{}')
            except Exception:
                payload = {}

            wrap_items = payload.get('wrap') if isinstance(payload, dict) else None
            pull_services = payload.get('pull') if isinstance(payload, dict) else None
            if not isinstance(wrap_items, list):
                wrap_items = []
            if not isinstance(pull_services, list):
                pull_services = []

            for wrap_item in wrap_items:
                if not isinstance(wrap_item, dict):
                    continue
                img = str(wrap_item.get('image') or '').strip()
                ctx = str(wrap_item.get('context') or '').strip()
                dockerfile = str(wrap_item.get('dockerfile') or 'Dockerfile').strip() or 'Dockerfile'
                network = str(wrap_item.get('network') or 'host').strip() or 'host'
                if not img or not ctx:
                    continue
                try:
                    log_handle.write(f'[remote] preflight: docker build image={img} context={ctx}\n')
                except Exception:
                    pass
                inner = (
                    f"sudo -S -p '' -k docker build --network {shlex.quote(network)} "
                    f"-t {shlex.quote(img)} -f {shlex.quote(backend.os.path.join(ctx, dockerfile))} {shlex.quote(ctx)}"
                )
                cmd = f"bash -lc {shlex.quote(inner)}"
                rc, out, err = _exec_ssh_sudo_capture(ssh_client, cmd, password)
                if rc != 0:
                    try:
                        log_handle.write(f'[remote] preflight: wrapper build failed rc={rc} output={(err or out)[-800:]}\n')
                    except Exception:
                        pass
                    return False, 'wrapper build failed on CORE VM'

            pull_services = [str(service).strip() for service in pull_services if str(service).strip()]
            pull_services = list(dict.fromkeys(pull_services))
            if pull_services:
                try:
                    log_handle.write(f'[remote] preflight: docker compose pull services={len(pull_services)}\n')
                except Exception:
                    pass
                inner = (
                    f"COMPOSE_PROJECT_NAME={shlex.quote(project_name)} sudo -S -p '' -k "
                    f"docker compose -f {shlex.quote(compose_path)} pull " + ' '.join([shlex.quote(service) for service in pull_services])
                )
                cmd = f"bash -lc {shlex.quote(inner)}"
                rc, out, err = _exec_ssh_sudo_capture(ssh_client, cmd, password)
                if rc != 0:
                    try:
                        log_handle.write(f'[remote] preflight: pull failed rc={rc} output={(err or out)[-800:]}\n')
                    except Exception:
                        pass
                    return False, 'image pull failed on CORE VM'

            try:
                log_handle.write('[remote] preflight: docker compose up --no-start --no-build\n')
            except Exception:
                pass
            inner = (
                f"COMPOSE_PROJECT_NAME={shlex.quote(project_name)} sudo -S -p '' -k "
                f"docker compose -f {shlex.quote(compose_path)} up --no-start --no-build --remove-orphans"
            )
            cmd = f"bash -lc {shlex.quote(inner)}"
            rc, out, err = _exec_ssh_sudo_capture(ssh_client, cmd, password)
            if rc != 0:
                try:
                    log_handle.write(f'[remote] preflight: up --no-start failed rc={rc} output={(err or out)[-800:]}\n')
                except Exception:
                    pass
                return False, 'docker compose up --no-start failed on CORE VM'

            try:
                log_handle.write(f'[remote] preflight: docker compose up -d --no-build {node_service}\n')
            except Exception:
                pass
            inner = (
                f"COMPOSE_PROJECT_NAME={shlex.quote(project_name)} sudo -S -p '' -k "
                f"docker compose -f {shlex.quote(compose_path)} up -d --no-build --remove-orphans {shlex.quote(node_service)}"
            )
            cmd = f"bash -lc {shlex.quote(inner)}"
            rc, out, err = _exec_ssh_sudo_capture(ssh_client, cmd, password)
            if rc != 0:
                try:
                    log_handle.write(f'[remote] preflight: up -d failed rc={rc} output={(err or out)[-800:]}\n')
                except Exception:
                    pass
                return False, 'docker compose up -d failed on CORE VM'

            wait_inner = (
                'set -euo pipefail; '
                f"p={shlex.quote(project_name)}; f={shlex.quote(compose_path)}; s={shlex.quote(node_service)}; "
                "for i in $(seq 1 14); do "
                "  cid=$(sudo -S -p '' -k docker compose -f \"$f\" -p \"$p\" ps -q \"$s\" 2>/dev/null | head -n 1 || true); "
                "  if [ -n \"$cid\" ]; then "
                "    pid=$(sudo -S -p '' -k docker inspect --format '{{.State.Pid}}' \"$cid\" 2>/dev/null || echo 0); "
                "    if [ \"$pid\" != \"0\" ] && [ -n \"$pid\" ]; then echo \"pid=$pid\"; exit 0; fi; "
                "  fi; "
                "  sleep 0.5; "
                "done; echo 'pid_wait_timeout'; exit 0"
            )
            cmd = f"bash -lc {shlex.quote(wait_inner)}"
            _exec_ssh_sudo_capture(ssh_client, cmd, password)
            try:
                log_handle.write('[remote] preflight: done\n')
            except Exception:
                pass
            return True, None

        ssh_client = None
        sftp = None

        try:
            log_f = open(log_path, 'a', encoding='utf-8', buffering=1)
        except Exception:
            return jsonify({'ok': False, 'error': 'Failed to open log file'}), 500

        try:
            log_f.write(f"compose: {backend.os.path.relpath(compose_path, backend._get_repo_root())}\n")
            if prepared_compose_path != compose_path:
                log_f.write(f"compose_prepared: {backend.os.path.relpath(prepared_compose_path, backend._get_repo_root())}\n")
            try:
                flow_mode = str(backend.os.getenv('CORETG_FLOW_ARTIFACTS_MODE') or '').strip() or 'copy'
                log_f.write(f'[local] inject_files_mode=copy flow_artifacts_mode={flow_mode}\n')
            except Exception:
                pass
            try:
                for line in _summarize_compose_for_log(prepared_compose_path):
                    log_f.write(line + '\n')
            except Exception:
                pass
            log_f.write('[remote] uploading to CORE VM…\n')
            try:
                env_path = backend.os.path.join(run_dir, '.env')
                if not backend.os.path.exists(env_path):
                    with open(env_path, 'w', encoding='utf-8') as env_file:
                        env_file.write('')
            except Exception:
                pass
            ssh_client = backend._open_ssh_client(core_cfg)
            sftp = ssh_client.open_sftp()
            backend._remote_mkdirs(ssh_client, remote_run_dir)

            try:
                images, containers = _compose_images_and_containers(prepared_compose_path)
                existing_images: list[str] = []
                existing_containers: list[str] = []
                try:
                    pw = str(core_cfg.get('ssh_password') or '')
                except Exception:
                    pw = ''
                for image in images:
                    inner = f"sudo -S -p '' -k docker images -q {shlex.quote(image)}"
                    cmd = f"bash -lc {shlex.quote(inner)}"
                    rc, out, _err = _exec_ssh_sudo_capture(ssh_client, cmd, pw)
                    if rc == 0 and out:
                        existing_images.append(image)
                for cname in containers:
                    filter_arg = f'name=^{cname}$'
                    inner = f"sudo -S -p '' -k docker ps -a --filter {shlex.quote(filter_arg)} --format {{.Names}}"
                    cmd = f"bash -lc {shlex.quote(inner)}"
                    rc, out, _err = _exec_ssh_sudo_capture(ssh_client, cmd, pw)
                    if rc == 0 and out:
                        existing_containers.append(cname)
                if (existing_images or existing_containers) and not force_replace:
                    try:
                        log_f.write('[remote] existing images/containers detected; awaiting user confirmation\n')
                        log_f.flush()
                    except Exception:
                        pass
                    try:
                        if sftp:
                            sftp.close()
                    except Exception:
                        pass
                    try:
                        if ssh_client:
                            ssh_client.close()
                    except Exception:
                        pass
                    try:
                        log_f.close()
                    except Exception:
                        pass
                    return jsonify(
                        {
                            'ok': True,
                            'replace_required': True,
                            'existing_images': existing_images,
                            'existing_containers': existing_containers,
                        }
                    )
                if force_replace and (existing_images or existing_containers):
                    try:
                        log_f.write('[remote] replacing existing images/containers\n')
                    except Exception:
                        pass
                    for cname in existing_containers:
                        inner = f"sudo -S -p '' -k docker rm -f {shlex.quote(cname)}"
                        cmd = f"bash -lc {shlex.quote(inner)}"
                        _exec_ssh_sudo_capture(ssh_client, cmd, pw)
                    for image in existing_images:
                        inner = f"sudo -S -p '' -k docker rmi -f {shlex.quote(image)}"
                        cmd = f"bash -lc {shlex.quote(inner)}"
                        _exec_ssh_sudo_capture(ssh_client, cmd, pw)
            except Exception:
                pass

            total_files = 0
            try:
                for walk_root, _dirs, walk_files in backend.os.walk(run_dir):
                    total_files += sum(1 for filename in walk_files if filename and backend.os.path.isfile(backend.os.path.join(walk_root, filename)))
            except Exception:
                total_files = 0
            try:
                if total_files:
                    log_f.write(f'[upload] 0/{total_files} (0%)\n')
            except Exception:
                pass
            uploaded = 0
            for root, dirs, files in backend.os.walk(run_dir):
                rel = backend.os.path.relpath(root, run_dir)
                rel = '' if rel == '.' else rel
                remote_root = remote_run_dir if not rel else backend._remote_path_join(remote_run_dir, rel)
                backend._remote_mkdirs(ssh_client, remote_root)
                for dirname in dirs:
                    backend._remote_mkdirs(ssh_client, backend._remote_path_join(remote_root, dirname))
                for filename in files:
                    local_path = backend.os.path.join(root, filename)
                    remote_path = backend._remote_path_join(remote_root, filename)
                    if backend.os.path.isfile(local_path):
                        sftp.put(local_path, remote_path)
                        try:
                            uploaded += 1
                            if total_files and (uploaded == total_files or uploaded % 10 == 0):
                                pct = int((uploaded / max(1, total_files)) * 100)
                                log_f.write(f'[upload] {uploaded}/{total_files} ({pct}%)\n')
                        except Exception:
                            pass
            try:
                if total_files:
                    log_f.write(f'[upload] done ({uploaded}/{total_files})\n')
            except Exception:
                pass

            rel_compose = backend.os.path.relpath(prepared_compose_path, run_dir)
            remote_compose_path = backend._remote_path_join(remote_run_dir, rel_compose)
            log_f.write(f'[remote] compose: {remote_compose_path}\n')

            remote_preflight_ok, remote_preflight_error, remote_preflight_meta = backend._core_vm_compose_template_preflight(
                ssh_client,
                remote_compose_path,
            )
            if remote_preflight_ok:
                try:
                    log_f.write(
                        f"[remote] compose preflight ok (engine={str((remote_preflight_meta or {}).get('template_engine') or 'unknown')})\n"
                    )
                except Exception:
                    pass
            else:
                try:
                    log_f.write(f'[remote] compose preflight failed: {remote_preflight_error}\n')
                except Exception:
                    pass
                return jsonify(
                    {
                        'ok': False,
                        'error': remote_preflight_error or 'CORE VM compose template preflight failed',
                        'compose_path': prepared_compose_path,
                        'remote_compose_path': remote_compose_path,
                        'preflight_remote': remote_preflight_meta,
                    }
                ), 422

            remote_render_ok, remote_runtime_compose_path, remote_render_error, remote_render_meta = backend._core_vm_render_compose_template(
                ssh_client,
                remote_compose_path,
            )
            if not remote_render_ok or not remote_runtime_compose_path:
                try:
                    log_f.write(f'[remote] compose render failed: {remote_render_error}\n')
                except Exception:
                    pass
                return jsonify(
                    {
                        'ok': False,
                        'error': remote_render_error or 'CORE VM compose render failed',
                        'compose_path': prepared_compose_path,
                        'remote_compose_path': remote_compose_path,
                        'preflight_remote': remote_preflight_meta,
                        'render_remote': remote_render_meta,
                    }
                ), 422
            try:
                log_f.write(
                    f"[remote] compose render ok (engine={str((remote_render_meta or {}).get('engine') or 'unknown')}) path={remote_runtime_compose_path}\n"
                )
            except Exception:
                pass

            remote_compose_runtime_path = remote_runtime_compose_path
            log_f.write(f'[remote] docker compose preflight+up (project={project_name})\n')

            try:
                pw = str(core_cfg.get('ssh_password') or '')
            except Exception:
                pw = ''
            try:
                node_service = f'vuln-test-{item_id}'
            except Exception:
                node_service = 'vuln-test'
            ok_pf, err_pf = _remote_compose_preflight(
                ssh_client=ssh_client,
                core_cfg=core_cfg,
                compose_path=remote_compose_runtime_path,
                project_name=project_name,
                node_service=node_service,
                password=pw,
                log_handle=log_f,
            )
            if not ok_pf:
                try:
                    log_f.write(f'[remote] preflight failed: {err_pf}\n')
                except Exception:
                    pass
                return jsonify({'ok': False, 'error': err_pf or 'remote preflight failed'}), 422

            inner_cmd = (
                f"cd {shlex.quote(remote_run_dir)} && "
                f"COMPOSE_PROJECT_NAME={shlex.quote(project_name)} sudo -S -p '' -k "
                f"docker compose -f {shlex.quote(remote_compose_runtime_path)} up --remove-orphans --no-build"
            )
            cmd = f"bash -lc {shlex.quote(inner_cmd)}"
            channel = ssh_client.get_transport().open_session() if ssh_client.get_transport() else None
            if channel is None:
                raise RuntimeError('SSH channel unavailable')
            try:
                channel.get_pty()
            except Exception:
                pass
            channel.exec_command(cmd)
            try:
                if pw:
                    channel.send(pw + '\n')
            except Exception:
                pass

            relay_thread = backend.threading.Thread(
                target=backend._relay_remote_channel_to_log,
                args=(channel, log_f),
                kwargs={'redact_tokens': [pw]},
                daemon=True,
            )
            relay_thread.start()
        except Exception as exc:
            try:
                log_f.write(str(exc) + '\n')
                log_f.flush()
                log_f.close()
            except Exception:
                pass
            try:
                if sftp:
                    sftp.close()
            except Exception:
                pass
            try:
                if ssh_client:
                    ssh_client.close()
            except Exception:
                pass
            return jsonify({'ok': False, 'error': str(exc)}), 500

        backend.RUNS[run_id] = {
            'kind': 'vuln_test',
            'proc': None,
            'log_path': log_path,
            'run_dir': run_dir,
            'done': False,
            'returncode': None,
            'cleanup_started': False,
            'cleanup_done': False,
            'compose_path': prepared_compose_path,
            'compose_path_raw': compose_path,
            'compose_dir': backend.os.path.dirname(prepared_compose_path),
            'project_name': project_name,
            'catalog_id': catalog_id,
            'item_id': item_id,
            'remote_run_dir': remote_run_dir,
            'remote_compose_path': remote_compose_runtime_path,
            'remote_compose_template_path': remote_compose_path,
            'core_cfg': core_cfg,
            'ssh_client': ssh_client,
            'ssh_channel': channel,
            'ssh_log_handle': log_f,
            'ssh_log_thread': relay_thread,
            'cleanup_generated_artifacts': bool(cleanup_generated_artifacts),
        }

        def _monitor_remote_vuln_test(current_run_id: str) -> None:
            try:
                meta = backend.RUNS.get(current_run_id)
                if not isinstance(meta, dict):
                    return
                channel_ref = meta.get('ssh_channel')
                if channel_ref is None:
                    return
                while True:
                    try:
                        if channel_ref.exit_status_ready():
                            try:
                                rc = int(channel_ref.recv_exit_status())
                            except Exception:
                                rc = 0
                            meta['returncode'] = rc
                            meta['done'] = True
                            break
                    except Exception:
                        break
                    backend.time.sleep(0.5)
            finally:
                try:
                    log_handle = backend.RUNS.get(current_run_id, {}).get('ssh_log_handle')
                    if log_handle:
                        log_handle.flush()
                        log_handle.close()
                except Exception:
                    pass
                try:
                    client = backend.RUNS.get(current_run_id, {}).get('ssh_client')
                    if client:
                        client.close()
                except Exception:
                    pass

        try:
            backend.threading.Thread(target=_monitor_remote_vuln_test, args=(run_id,), daemon=True).start()
        except Exception:
            pass
        return jsonify({'ok': True, 'run_id': run_id, 'cleanup_generated_artifacts': bool(cleanup_generated_artifacts)})

    mark_routes_registered(app, 'vuln_catalog_test_start_routes')
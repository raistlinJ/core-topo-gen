from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from flask import jsonify, request


def register(
    app,
    *,
    load_run_history: Callable[[], list[dict[str, Any]]],
    current_user_getter: Callable[[], dict[str, Any] | None],
    scenario_catalog_for_user: Callable[..., Any],
    normalize_scenario_label: Callable[[Any], str],
    select_core_config_for_page: Callable[..., dict[str, Any]],
    ensure_core_vm_metadata: Callable[[dict[str, Any]], dict[str, Any]],
    run_remote_python_json: Callable[..., Any],
    remote_docker_status_script_builder: Callable[[str | None], str],
    remote_docker_cleanup_script_builder: Callable[[list[str], str | None], str],
    logger=None,
) -> None:
    """Register Docker status/compose/cleanup routes.

    Extracted from `webapp.app_backend`.
    """

    log = logger or getattr(app, "logger", None)

    @app.route('/docker/status', methods=['GET'])
    def docker_status():
        history = load_run_history()
        current_user = current_user_getter()
        scenario_names, _scenario_paths, _scenario_url_hints = scenario_catalog_for_user(history, user=current_user)
        scenario_query = request.args.get('scenario', '').strip()
        scenario_norm = normalize_scenario_label(scenario_query)
        if scenario_names:
            if not scenario_norm or not any(normalize_scenario_label(n) == scenario_norm for n in scenario_names):
                scenario_norm = normalize_scenario_label(scenario_names[0])
        core_cfg = select_core_config_for_page(scenario_norm, history, include_password=True)
        core_cfg = ensure_core_vm_metadata(core_cfg)
        try:
            payload = run_remote_python_json(
                core_cfg,
                remote_docker_status_script_builder(core_cfg.get('ssh_password')),
                logger=log,
                label='docker.status',
                timeout=60.0,
            )
            if not isinstance(payload, dict):
                payload = {'items': [], 'timestamp': int(time.time()), 'error': 'invalid remote payload'}
            payload.setdefault('timestamp', int(time.time()))
            return jsonify(payload)
        except Exception as exc:
            return jsonify({'items': [], 'timestamp': int(time.time()), 'error': str(exc)}), 200

    @app.route('/docker/compose_text', methods=['GET'])
    def docker_compose_text():
        history = load_run_history()
        current_user = current_user_getter()
        scenario_names, _scenario_paths, _scenario_url_hints = scenario_catalog_for_user(history, user=current_user)
        scenario_query = request.args.get('scenario', '').strip()
        scenario_norm = normalize_scenario_label(scenario_query)
        if scenario_names:
            if not scenario_norm or not any(normalize_scenario_label(n) == scenario_norm for n in scenario_names):
                scenario_norm = normalize_scenario_label(scenario_names[0])
        node_name = str(request.args.get('name') or '').strip()
        if not node_name or not re.match(r'^[A-Za-z0-9._-]{1,64}$', node_name):
            return jsonify({'ok': False, 'error': 'Invalid node name.'}), 400
        try:
            lines = int(request.args.get('lines') or 120)
        except Exception:
            lines = 120
        lines = max(20, min(400, lines))

        core_cfg = select_core_config_for_page(scenario_norm, history, include_password=True)
        core_cfg = ensure_core_vm_metadata(core_cfg)

        script = (
            "import os, json, time\n"
            f"name = {json.dumps(node_name)}\n"
            f"max_lines = int({json.dumps(str(lines))})\n"
            "base = os.environ.get('CORE_REMOTE_BASE_DIR', '/tmp/core-topo-gen')\n"
            "def _read_file(path, max_lines=120):\n"
            "  try:\n"
            "    out=[]\n"
            "    with open(path, 'r', encoding='utf-8', errors='ignore') as f:\n"
            "      for i, ln in enumerate(f):\n"
            "        if i >= max_lines: break\n"
            "        out.append(ln.rstrip('\\\\n'))\n"
            "    return True, '\\\\n'.join(out)\n"
            "  except Exception as e:\n"
            "    return False, str(e)\n"
            "def _imageish_lines(text):\n"
            "  out=[]\n"
            "  try:\n"
            "    for ln in (text or '').split('\\\\n'):\n"
            "      low=ln.lower()\n"
            "      if 'image:' in low or 'build:' in low or 'container_name' in low or 'quay.io' in low or 'nfs' in low or 'ganesha' in low:\n"
            "        out.append(ln)\n"
            "  except Exception:\n"
            "    pass\n"
            "  return out[:120]\n"
            "candidates = [\n"
            "  os.path.join(base, 'vulns', 'compose_assignments.json'),\n"
            "  os.path.join(base, 'outputs', 'vulns', 'compose_assignments.json'),\n"
            "  os.path.join(base, 'compose_assignments.json'),\n"
            "  '/tmp/vulns/compose_assignments.json',\n"
            "]\n"
            "assign_path = ''\n"
            "for p in candidates:\n"
            "  try:\n"
            "    if os.path.exists(p):\n"
            "      assign_path = p\n"
            "      break\n"
            "  except Exception:\n"
            "    pass\n"
            "assign_dir = os.path.dirname(assign_path) if assign_path else '/tmp/vulns'\n"
            "yml = os.path.join(assign_dir, f'docker-compose-{name}.yml')\n"
            "exists = False\n"
            "try: exists = os.path.exists(yml)\n"
            "except Exception: exists = False\n"
            "head = ''\n"
            "image_lines = []\n"
            "flow_src = ''\n"
            "flow_run_dir = ''\n"
            "flow_compose = ''\n"
            "flow_compose_exists = False\n"
            "flow_compose_head = ''\n"
            "flow_compose_image_lines = []\n"
            "if exists:\n"
            "  ok, content = _read_file(yml, max_lines=max_lines)\n"
            "  if ok:\n"
            "    head = content\n"
            "    image_lines = _imageish_lines(content)\n"
            "    try:\n"
            "      for ln in content.split('\\\\n'):\n"
            "        low = ln.lower().strip()\n"
            "        if low.startswith('coretg.flow_artifacts.src:'):\n"
            "          flow_src = ln.split(':', 1)[1].strip()\n"
            "          break\n"
            "    except Exception:\n"
            "      flow_src = ''\n"
            "  else:\n"
            "    head = f'ERROR reading {yml}: {content}'\n"
            "if flow_src:\n"
            "  try:\n"
            "    flow_run_dir = os.path.dirname(flow_src.rstrip('/'))\n"
            "    cand = os.path.join(flow_run_dir, 'docker-compose.yml')\n"
            "    flow_compose = cand\n"
            "    flow_compose_exists = bool(os.path.exists(cand))\n"
            "    if flow_compose_exists:\n"
            "      ok2, content2 = _read_file(cand, max_lines=max_lines)\n"
            "      flow_compose_head = content2 if ok2 else ('ERROR reading ' + cand + ': ' + content2)\n"
            "      if ok2:\n"
            "        flow_compose_image_lines = _imageish_lines(content2)\n"
            "  except Exception:\n"
            "    pass\n"
            "print(json.dumps({\n"
            "  'ok': True,\n"
            "  'name': name,\n"
            "  'compose': yml,\n"
            "  'exists': bool(exists),\n"
            "  'head': head,\n"
            "  'image_lines': image_lines[:80],\n"
            "  'flow_artifacts_src': flow_src,\n"
            "  'flow_run_dir': flow_run_dir,\n"
            "  'flow_compose': flow_compose,\n"
            "  'flow_compose_exists': bool(flow_compose_exists),\n"
            "  'flow_compose_image_lines': flow_compose_image_lines[:80],\n"
            "  'flow_compose_head': flow_compose_head,\n"
            "  'timestamp': int(time.time()),\n"
            "}))\n"
        )
        try:
            payload = run_remote_python_json(
                core_cfg,
                script,
                logger=log,
                label='docker.compose_text',
                timeout=30.0,
            )
            if not isinstance(payload, dict):
                payload = {'ok': False, 'error': 'invalid remote payload'}
            return jsonify(payload)
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 200

    @app.route('/docker/cleanup', methods=['POST'])
    def docker_cleanup():
        names: list[str] = []
        try:
            if request.is_json:
                body = request.get_json(silent=True) or {}
                if isinstance(body.get('names'), list):
                    names = [str(x) for x in body.get('names')]
            else:
                raw = request.form.get('names')
                if raw:
                    try:
                        arr = json.loads(raw)
                        if isinstance(arr, list):
                            names = [str(x) for x in arr]
                        else:
                            names = [str(raw)]
                    except Exception:
                        names = [str(raw)]

            history = load_run_history()
            current_user = current_user_getter()
            scenario_names, _scenario_paths, _scenario_url_hints = scenario_catalog_for_user(history, user=current_user)
            scenario_query = request.args.get('scenario', '').strip()
            scenario_norm = normalize_scenario_label(scenario_query)
            if scenario_names:
                if not scenario_norm or not any(normalize_scenario_label(n) == scenario_norm for n in scenario_names):
                    scenario_norm = normalize_scenario_label(scenario_names[0])
            core_cfg = select_core_config_for_page(scenario_norm, history, include_password=True)
            core_cfg = ensure_core_vm_metadata(core_cfg)

            if not names:
                try:
                    status_payload = run_remote_python_json(
                        core_cfg,
                        remote_docker_status_script_builder(core_cfg.get('ssh_password')),
                        logger=log,
                        label='docker.status(for cleanup)',
                        timeout=60.0,
                    )
                    if isinstance(status_payload, dict) and isinstance(status_payload.get('items'), list):
                        names = [str(it.get('name')) for it in status_payload['items'] if isinstance(it, dict) and it.get('name')]
                except Exception:
                    names = []

            payload = run_remote_python_json(
                core_cfg,
                remote_docker_cleanup_script_builder(names, core_cfg.get('ssh_password')),
                logger=log,
                label='docker.cleanup',
                timeout=120.0,
            )
            if not isinstance(payload, dict):
                payload = {'ok': False, 'error': 'invalid remote payload'}
            return jsonify(payload)
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500

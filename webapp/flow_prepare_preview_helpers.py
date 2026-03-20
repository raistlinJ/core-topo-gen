from __future__ import annotations

import os
import posixpath
import random
import re
import shutil
import subprocess
import time
import glob
from typing import Any

import json

from werkzeug.utils import secure_filename


def flow_is_file_input_type(type_value: Any) -> bool:
    try:
        type_name = str(type_value or '').strip().lower()
    except Exception:
        return False
    if not type_name:
        return False
    if type_name in {'file', 'file_list'}:
        return True
    if type_name in {'file', 'filepath', 'file_path', 'path', 'pathname'}:
        return True
    if 'file' in type_name:
        return True
    if 'path' in type_name:
        return True
    return False


def flow_is_file_list_input_type(type_value: Any) -> bool:
    try:
        type_name = str(type_value or '').strip().lower()
    except Exception:
        return False
    if not type_name:
        return False
    if type_name == 'file_list':
        return True
    if 'list' in type_name and ('file' in type_name or 'path' in type_name):
        return True
    return False


def flow_is_allowed_upload_path(path_value: Any, *, backend: Any) -> bool:
    if not path_value:
        return False
    try:
        abs_path = os.path.abspath(str(path_value))
    except Exception:
        return False
    try:
        if not os.path.isfile(abs_path):
            return False
    except Exception:
        return False
    try:
        allowed_roots = [
            os.path.abspath(os.path.join(backend._outputs_dir(), 'flow_uploads')),
            os.path.abspath(backend._uploads_dir()),
        ]
        for root in allowed_roots:
            try:
                if os.path.commonpath([abs_path, root]) == root:
                    return True
            except Exception:
                continue
    except Exception:
        return False
    return False


def flow_unique_dest_filename(dir_path: str, filename: str, sequence: int = None, *, backend: Any) -> str:
    secure_filename_func = getattr(backend, 'secure_filename', secure_filename)
    base_name = secure_filename_func(filename) or 'upload'
    candidate = base_name
    if not os.path.exists(os.path.join(dir_path, candidate)):
        return candidate

    root, ext = os.path.splitext(base_name)
    sequence_prefix = f"{sequence:02d}_" if sequence is not None else ''
    for _ in range(100):
        rand = random.randint(1000, 9999)
        candidate = f"{sequence_prefix}{rand}_{root}{ext}"
        if not os.path.exists(os.path.join(dir_path, candidate)):
            return candidate

    index = 1
    while os.path.exists(os.path.join(dir_path, candidate)):
        candidate = f"{root}_{index}{ext}"
        index += 1
        if index > 5000:
            break
    return candidate


def flow_stage_file_inputs_for_generator(
    cfg_to_pass: dict[str, Any],
    gen_def: dict[str, Any],
    *,
    run_dir: str,
    run_index: int = None,
    backend: Any,
) -> None:
    if not isinstance(cfg_to_pass, dict) or not isinstance(gen_def, dict):
        return
    if not run_dir:
        return

    inputs = gen_def.get('inputs') if isinstance(gen_def, dict) else None
    inputs_list = inputs if isinstance(inputs, list) else []

    file_input_names: set[str] = set()
    file_list_input_names: set[str] = set()
    for inp in inputs_list:
        if not isinstance(inp, dict):
            continue
        name = str(inp.get('name') or '').strip()
        if not name:
            continue
        if flow_is_file_list_input_type(inp.get('type')):
            file_list_input_names.add(name)
            continue
        if flow_is_file_input_type(inp.get('type')):
            file_input_names.add(name)

    if not file_input_names and not file_list_input_names:
        return

    target_dir = os.path.join(run_dir, 'inputs')
    os.makedirs(target_dir, exist_ok=True)

    for key in list(cfg_to_pass.keys()):
        if key in file_input_names:
            value = cfg_to_pass.get(key)
            if not isinstance(value, str):
                continue
            raw = value.strip()
            if not raw or raw.startswith('/inputs/'):
                continue
            if not flow_is_allowed_upload_path(raw, backend=backend):
                continue
            try:
                src = os.path.abspath(raw)
            except Exception:
                continue
            try:
                base_name = os.path.basename(src) or f"{key}.upload"
            except Exception:
                base_name = f"{key}.upload"
            dest_name = flow_unique_dest_filename(target_dir, base_name, sequence=run_index, backend=backend)
            dest = os.path.join(target_dir, dest_name)
            try:
                shutil.copyfile(src, dest)
                cfg_to_pass[key] = f"/inputs/{dest_name}"
            except Exception:
                continue

        if key in file_list_input_names:
            value = cfg_to_pass.get(key)
            if not isinstance(value, list):
                continue
            staged: list[str] = []
            for item in value or []:
                if not isinstance(item, str):
                    continue
                raw = item.strip()
                if not raw:
                    continue
                if raw.startswith('/inputs/'):
                    staged.append(raw)
                    continue
                if not flow_is_allowed_upload_path(raw, backend=backend):
                    continue
                try:
                    src = os.path.abspath(raw)
                except Exception:
                    continue
                try:
                    base_name = os.path.basename(src) or f"{key}.upload"
                except Exception:
                    base_name = f"{key}.upload"
                dest_name = flow_unique_dest_filename(target_dir, base_name, sequence=run_index, backend=backend)
                dest = os.path.join(target_dir, dest_name)
                try:
                    shutil.copyfile(src, dest)
                    staged.append(f"/inputs/{dest_name}")
                except Exception:
                    continue
            if staged:
                cfg_to_pass[key] = staged


def all_input_names_of(gen: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    try:
        inputs = gen.get('inputs')
        if isinstance(inputs, list):
            for inp in inputs:
                if not isinstance(inp, dict):
                    continue
                name = str(inp.get('name') or '').strip()
                if name:
                    names.add(name)
    except Exception:
        pass
    return names


def required_input_names_of(gen: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    try:
        inputs = gen.get('inputs')
        if isinstance(inputs, list):
            for inp in inputs:
                if not isinstance(inp, dict):
                    continue
                name = str(inp.get('name') or '').strip()
                if not name:
                    continue
                if inp.get('required') is False:
                    continue
                names.add(name)
    except Exception:
        pass
    return names


def flow_default_generator_config(
    assignment: dict[str, Any],
    *,
    seed_val: Any,
    occurrence_idx: int = 0,
    flag_seed_epoch: Any,
    scenario_norm: str,
    backend: Any,
) -> dict[str, Any]:
    node_id = str(assignment.get('node_id') or '').strip()
    gen_id = str(assignment.get('id') or '').strip()
    base_seed = str(seed_val if seed_val not in (None, '') else '0')
    flag_seed = str(flag_seed_epoch if flag_seed_epoch not in (None, '') else '0')
    try:
        base_seed = f"{base_seed}:{flag_seed}"
    except Exception:
        pass
    return {
        'seed': backend._flow_generator_seed(
            base_seed=base_seed,
            scenario_norm=scenario_norm,
            node_id=node_id,
            gen_id=gen_id,
            occurrence_idx=int(occurrence_idx or 0),
        ),
        'flag_prefix': 'FLAG',
        'flag_seed': f"{flag_seed}",
        'secret': f"FLOWSECRET_{base_seed}_{scenario_norm}_{node_id}_{flag_seed}",
        'env_name': f"env_{scenario_norm}_{node_id}",
        'challenge': f"challenge_{scenario_norm}_{node_id}",
        'username_prefix': 'user',
        'key_len': 16,
    }


def redact_kv_for_ui(kv: Any) -> dict[str, Any]:
    if not isinstance(kv, dict) or not kv:
        return {}
    return dict(kv)


def flow_try_run_generator(
    generator_id: str,
    *,
    out_dir: str,
    config: dict[str, Any],
    kind: str = 'flag-generator',
    timeout_s: int = 120,
    inject_files_override: list[str] | None = None,
    backend: Any,
) -> tuple[bool, str, str | None, str | None, str | None]:
    subprocess_module = getattr(backend, 'subprocess', subprocess)
    app = backend.app
    try:
        repo_root = backend._get_repo_root()
        runner_path = os.path.join(repo_root, 'scripts', 'run_flag_generator.py')
        if not os.path.exists(runner_path):
            return False, 'runner script not found', None, None, None

        cmd = [
            backend._resolve_python_executable(),
            runner_path,
            '--kind',
            str(kind or 'flag-generator'),
            '--generator-id',
            generator_id,
            '--out-dir',
            out_dir,
            '--config',
            json.dumps(config, ensure_ascii=False),
            '--repo-root',
            repo_root,
        ]
        env = dict(os.environ)
        env.setdefault('CORETG_DOCKER_USE_SUDO', '1')
        env.setdefault('CORETG_DOCKER_HOST_NETWORK', '1')
        try:
            if isinstance(inject_files_override, list):
                env['CORETG_INJECT_FILES_JSON'] = json.dumps(list(inject_files_override))
        except Exception:
            pass

        proc = subprocess_module.run(
            cmd,
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_s or 120)),
            env=env,
        )
        manifest_path = os.path.join(out_dir, 'outputs.json')
        stdout_tail = (proc.stdout or '').strip()[-4000:]
        stderr_tail = (proc.stderr or '').strip()[-4000:]
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or '').strip()
            if err:
                err = err[-800:]
            return False, f'generator failed (rc={proc.returncode}): {err}', (manifest_path if os.path.exists(manifest_path) else None), stdout_tail, stderr_tail
        if os.path.exists(manifest_path):
            return True, 'ok', manifest_path, stdout_tail, stderr_tail
        try:
            app.logger.warning(
                '[flow.generator] outputs.json missing for generator=%s kind=%s out_dir=%s stdout_tail=%s stderr_tail=%s',
                generator_id,
                kind,
                out_dir,
                (proc.stdout or '').strip()[-400:],
                (proc.stderr or '').strip()[-400:],
            )
        except Exception:
            pass
        return True, 'ok (no outputs.json)', None, stdout_tail, stderr_tail
    except subprocess_module.TimeoutExpired:
        return False, 'generator timed out', None, None, None
    except Exception as exc:
        return False, f'generator exception: {exc}', None, None, None


def flow_try_run_generator_remote(
    generator_id: str,
    *,
    out_dir: str,
    config: dict[str, Any],
    kind: str = 'flag-generator',
    timeout_s: int = 120,
    inject_files_override: list[str] | None = None,
    core_cfg: dict[str, Any],
    repo_dir: str,
    backend: Any,
) -> tuple[bool, str, str | None, dict[str, Any] | None, str | None, str | None]:
    app = backend.app
    try:
        timeout_literal = str(int(timeout_s or 120))
    except Exception:
        timeout_literal = '120'
    try:
        cfg_json = json.dumps(config or {}, ensure_ascii=False)
    except Exception:
        cfg_json = '{}'
    sudo_pw = None
    try:
        sudo_pw = str(core_cfg.get('ssh_password') or '').strip() if isinstance(core_cfg, dict) else None
    except Exception:
        sudo_pw = None
    inject_json = None
    try:
        if isinstance(inject_files_override, list):
            inject_json = json.dumps(list(inject_files_override))
    except Exception:
        inject_json = None
    script = (
        "import json, os, subprocess, sys\n"
        f"REPO={json.dumps(str(repo_dir))}\n"
        f"OUT={json.dumps(str(out_dir))}\n"
        f"GEN={json.dumps(str(generator_id))}\n"
        f"KIND={json.dumps(str(kind or 'flag-generator'))}\n"
        f"CFG={json.dumps(cfg_json)}\n"
        f"INJECT={inject_json if inject_json is not None else 'None'}\n"
        "os.makedirs(OUT, exist_ok=True)\n"
        "runner=os.path.join(REPO,'scripts','run_flag_generator.py')\n"
        "env=os.environ.copy()\n"
        "env['CORETG_DOCKER_USE_SUDO']='1'\n"
        "env['CORETG_DOCKER_HOST_NETWORK']='1'\n"
        "preflight=''\n"
        "deps_dir='/tmp/coretg_pydeps'\n"
        "try:\n"
        "  import yaml  # noqa\n"
        "except Exception as _e_yaml:\n"
        "  try:\n"
        "    os.makedirs(deps_dir, exist_ok=True)\n"
        "    pip_cmd=[sys.executable,'-m','pip','install','-q','--disable-pip-version-check','--no-input','-t',deps_dir,'PyYAML==6.0.2']\n"
        "    r=subprocess.run(pip_cmd, cwd=REPO, check=False, capture_output=True, text=True)\n"
        "    if r.returncode!=0:\n"
        "      try:\n"
        "        subprocess.run([sys.executable,'-m','ensurepip','--upgrade'], cwd=REPO, check=False, capture_output=True, text=True)\n"
        "      except Exception:\n"
        "        pass\n"
        "      r=subprocess.run(pip_cmd, cwd=REPO, check=False, capture_output=True, text=True)\n"
        "    if deps_dir not in sys.path:\n"
        "      sys.path.insert(0, deps_dir)\n"
        "    import yaml  # noqa\n"
        "    preflight += '[preflight] installed PyYAML into ' + deps_dir + '\\n'\n"
        "    if (r.stderr or r.stdout):\n"
        "      preflight += '[preflight] pip: ' + (r.stderr or r.stdout).strip()[-800:] + '\\n'\n"
        "  except Exception as _e_pip:\n"
        "    preflight += '[preflight] PyYAML missing and install failed: ' + str(_e_pip) + '\\n'\n"
        f"SUDO_PW={json.dumps(str(sudo_pw or ''))}\n"
        "if SUDO_PW:\n"
        "  env['CORETG_DOCKER_SUDO_PASSWORD']=SUDO_PW\n"
        "if INJECT is not None:\n"
        "  try:\n"
        "    env['CORETG_INJECT_FILES_JSON']=json.dumps(json.loads(INJECT))\n"
        "  except Exception:\n"
        "    env['CORETG_INJECT_FILES_JSON']=INJECT\n"
        "cmd=[sys.executable, runner, '--kind', KIND, '--generator-id', GEN, '--out-dir', OUT, '--config', CFG, '--repo-root', REPO]\n"
        f"p=subprocess.run(cmd, cwd=REPO, env=env, check=False, capture_output=True, text=True, timeout=max(1, int({timeout_literal})))\n"
        "OUT_ARTIFACTS=OUT\n"
        "manifest=os.path.join(OUT,'outputs.json')\n"
        "outputs=None\n"
        "if os.path.exists(manifest):\n"
        "  try:\n"
        "    with open(manifest,'r',encoding='utf-8') as f:\n"
        "      m=json.load(f) or {}\n"
        "    outputs=m.get('outputs') if isinstance(m, dict) else None\n"
        "  except Exception:\n"
        "    outputs=None\n"
        "if outputs is None:\n"
        "  try:\n"
        "    flag_path=os.path.join(OUT_ARTIFACTS,'flag.txt')\n"
        "    if os.path.exists(flag_path):\n"
        "      flag_val=open(flag_path,'r',encoding='utf-8',errors='ignore').read().strip()\n"
        "      if flag_val:\n"
        "        outputs={'Flag(flag_id)': flag_val, 'flag': flag_val}\n"
        "  except Exception:\n"
        "    outputs=outputs\n"
        "ok=bool(p.returncode==0)\n"
        "err=None\n"
        "if ok and outputs:\n"
        "  for k,v in outputs.items():\n"
        "    if isinstance(v,str) and (v.startswith('/') or '/' in v or '.' in v):\n"
        "      v=v.strip()\n"
        "      exists=os.path.exists(v)\n"
        "      checked=[v]\n"
        "      if not exists:\n"
        "        candidates=[]\n"
        "        candidates.append(os.path.join(OUT,v.lstrip('/')))\n"
        "        candidates.append(os.path.join(OUT,os.path.basename(v)))\n"
        "        if v.startswith('artifacts/'):\n"
        "          tail=v.split('artifacts/',1)[1].lstrip('/')\n"
        "          candidates.append(os.path.join(OUT,'artifacts',tail))\n"
        "          candidates.append(os.path.join(OUT,'artifacts',os.path.basename(v)))\n"
        "        for cand in candidates:\n"
        "          if not cand or cand in checked:\n"
        "            continue\n"
        "          checked.append(cand)\n"
        "          if os.path.exists(cand):\n"
        "            exists=True\n"
        "            break\n"
        "      if not exists:\n"
        "        ok=False\n"
        "        err=f'Artifact verification failed: {v} does not exist on remote disk (checked: {checked})'\n"
        "        break\n"
        "print(json.dumps({\n"
        "  'ok': ok,\n"
        "  'rc': int(p.returncode or 0),\n"
        "  'stdout': (preflight + (p.stdout or ''))[-4000:],\n"
        "  'stderr': (preflight + (p.stderr or ''))[-4000:],\n"
        "  'manifest': manifest if os.path.exists(manifest) else None,\n"
        "  'outputs': outputs,\n"
        "  'error': err,\n"
        "}))\n"
    )
    try:
        payload = backend._run_remote_python_json(
            core_cfg,
            script,
            logger=app.logger,
            label=f'flow.generator.remote.{generator_id}',
            timeout=max(30.0, float(timeout_s or 120)),
        )
    except Exception as exc:
        return False, f'remote generator exception: {exc}', None, None, None, None

    ok = bool(payload.get('ok')) if isinstance(payload, dict) else False
    rc = payload.get('rc') if isinstance(payload, dict) else None
    stdout = str(payload.get('stdout') or '') if isinstance(payload, dict) else ''
    stderr = str(payload.get('stderr') or '') if isinstance(payload, dict) else ''
    manifest_path = payload.get('manifest') if isinstance(payload, dict) else None
    outputs = payload.get('outputs') if isinstance(payload, dict) else None
    remote_err = payload.get('error') if isinstance(payload, dict) else None
    note = 'ok'
    if not ok:
        tail = (stderr or stdout).strip()
        if remote_err:
            note = str(remote_err)
        else:
            note = f'remote generator failed (rc={rc}): {tail[-800:] if tail else "(no output)"}'
        try:
            app.logger.error(
                '[flow.generator.remote] generator=%s ok=%s rc=%s note=%s manifest=%s stdout_tail=%s stderr_tail=%s',
                generator_id,
                bool(ok),
                rc,
                str(note or ''),
                str(manifest_path or ''),
                (stdout or '').strip()[-4000:],
                (stderr or '').strip()[-4000:],
            )
        except Exception:
            pass
    elif not manifest_path:
        tail = (stderr or stdout).strip()
        if tail:
            note = f'no outputs.json (stdout/stderr): {tail[-800:]}'
        else:
            note = 'no outputs.json'
    return ok, note, (str(manifest_path) if manifest_path else None), (outputs if isinstance(outputs, dict) else None), (stdout or ''), (stderr or '')


def preview_host_ip4(host: dict[str, Any], *, backend: Any) -> str:
    try:
        ip4 = host.get('ip4')
        if isinstance(ip4, str) and backend._first_valid_ipv4(ip4):
            return backend._first_valid_ipv4(ip4)
    except Exception:
        pass
    for key in ('ipv4', 'ip', 'ip_addr', 'address'):
        try:
            value = host.get(key)
        except Exception:
            value = None
        ip_str = backend._first_valid_ipv4(value)
        if ip_str:
            return ip_str
    return ''


def apply_outputs_to_hint_text(text_in: str, outs: dict[str, Any]) -> str:
    try:
        text = str(text_in or '')
    except Exception:
        return str(text_in or '')
    if not text or not isinstance(outs, dict) or not outs:
        return text
    try:
        pattern = re.compile(r"\{\{OUTPUT\.([^}:]+?)(?::([^}]+?))?\}\}")
    except Exception:
        return text

    def _render_value(val: Any) -> str:
        if isinstance(val, (dict, list)):
            return json.dumps(val, ensure_ascii=False)
        return str(val)

    def _transform(val: Any, tf: str) -> str:
        transform_name = (tf or '').strip().lower()
        rendered = _render_value(val)
        if not transform_name:
            return rendered
        if transform_name in {'last_octet', 'octet4'}:
            try:
                parts = rendered.strip().split('.')
                if len(parts) == 4:
                    return parts[3]
            except Exception:
                pass
            return rendered
        if transform_name in {'subnet24', 'cidr24'}:
            try:
                parts = rendered.strip().split('.')
                if len(parts) == 4:
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            except Exception:
                pass
            return rendered
        if transform_name in {'redact', 'masked'}:
            try:
                parts = rendered.strip().split('.')
                if len(parts) == 4:
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
            except Exception:
                pass
            return rendered
        return rendered

    def _replace(match: re.Match) -> str:
        key = (match.group(1) or '').strip()
        tf = (match.group(2) or '').strip()
        if not key:
            return match.group(0)
        if key not in outs:
            return match.group(0)
        return _transform(outs.get(key), tf)

    try:
        return pattern.sub(_replace, text)
    except Exception:
        return text


def apply_node_placeholders(text_in: str, *, node_ip4: str) -> str:
    try:
        text = str(text_in or '')
    except Exception:
        return str(text_in or '')
    if not text or not node_ip4:
        return text
    for token in ('<node-ip>', '<node_ip>', '<host-ip>', '<host_ip>', '<target-ip>', '<target_ip>'):
        try:
            text = text.replace(token, node_ip4)
        except Exception:
            continue
    return text


def normalize_inject_src_for_copy(raw_src: str, source_dir: str) -> str:
    def _normalize_rel_artifacts(rel_src: str, base_dir: str) -> str:
        out = str(rel_src or '').replace('\\', '/').strip()
        if out.startswith('./'):
            out = out[2:]
        out = out.lstrip('/')
        try:
            if base_dir and os.path.basename(os.path.normpath(base_dir)) == 'artifacts':
                while out.startswith('artifacts/'):
                    out = out[len('artifacts/'):]
        except Exception:
            pass
        return out

    src = str(raw_src or '').strip()
    if not src:
        return ''
    if src == '/tmp/flag.txt':
        return src
    if not os.path.isabs(src):
        return _normalize_rel_artifacts(src, source_dir)
    try:
        if source_dir:
            src_abs = os.path.abspath(src)
            base_abs = os.path.abspath(source_dir)
            if os.path.commonpath([src_abs, base_abs]) == base_abs:
                return _normalize_rel_artifacts(os.path.relpath(src_abs, base_abs), source_dir)
    except Exception:
        pass
    for marker in ('/artifacts/', '/flow_artifacts/'):
        if marker in src:
            return _normalize_rel_artifacts(src.split(marker, 1)[1], source_dir)
    return src


def normalize_inject_spec_for_copy(raw: str, source_dir: str) -> str:
    text = str(raw or '').strip()
    if not text:
        return ''
    sep = '->' if '->' in text else '=>' if '=>' in text else ''
    if sep:
        left, right = text.split(sep, 1)
        src_norm = normalize_inject_src_for_copy(left.strip(), source_dir)
        if not src_norm:
            return ''
        dest = right.strip()
        return f"{src_norm} -> {dest}" if dest else src_norm
    return normalize_inject_src_for_copy(text, source_dir)


def inject_files_for_copy_from_detail(detail_list: Any, source_dir: str) -> list[str]:
    if not isinstance(detail_list, list):
        return []
    out: list[str] = []
    for entry in detail_list:
        if not isinstance(entry, dict):
            continue
        resolved = str(entry.get('resolved') or '').strip()
        path = str(entry.get('path') or '').strip()
        if not path:
            continue
        dest_dir = os.path.dirname(path) if path.startswith('/') else ''
        if dest_dir == '/' and path.startswith('/'):
            dest_dir = path.rstrip('/') or '/'
        if not dest_dir or dest_dir == '/':
            continue
        src_norm = normalize_inject_src_for_copy(resolved, source_dir)
        if not src_norm:
            continue
        out.append(f"{src_norm} -> {dest_dir}")
    return out


def collect_resolved_path_info(
    *,
    artifacts_dir: str,
    inject_source_dir: str,
    inject_detail_list: Any,
    inject_specs: list[str],
    source_dir: str,
    remote_mode: bool,
    backend: Any,
) -> dict[str, Any]:
    def _info(path_value: str) -> dict[str, Any]:
        path_text = str(path_value or '').strip()
        return {'path': path_text, 'is_remote': bool(remote_mode)}

    def _canonicalize_remote_source_path(path_value: str) -> str:
        path_text = str(path_value or '').strip()
        if not path_text or not remote_mode:
            return path_text
        try:
            path_norm = path_text.replace('\\', '/')
        except Exception:
            path_norm = path_text
        for mount_prefix in ('/exports', '/outputs', '/inputs'):
            if path_norm == mount_prefix or path_norm.startswith(mount_prefix + '/'):
                return path_norm
        try:
            repo_root = os.path.abspath(backend._get_repo_root()).replace('\\', '/').rstrip('/')
        except Exception:
            repo_root = ''
        if repo_root and path_norm.startswith(repo_root + '/'):
            rel = path_norm[len(repo_root) + 1:]
            for mount_name in ('exports', 'outputs', 'inputs'):
                if rel == mount_name or rel.startswith(mount_name + '/'):
                    return '/' + rel
        return path_norm

    def _resolve_src(spec: str) -> str:
        text = str(spec or '').strip()
        if not text:
            return ''
        for sep in ('->', '=>'):
            if sep in text:
                text = text.split(sep, 1)[0].strip()
                break
        if not text:
            return ''
        if os.path.isabs(text):
            return _canonicalize_remote_source_path(text)
        if source_dir:
            if remote_mode:
                try:
                    return _canonicalize_remote_source_path(posixpath.join(source_dir, text.lstrip('/')))
                except Exception:
                    return _canonicalize_remote_source_path(text)
            return os.path.abspath(os.path.join(source_dir, text))
        return _canonicalize_remote_source_path(text)

    seen_sources: set[str] = set()
    sources: list[dict[str, Any]] = []
    if isinstance(inject_detail_list, list):
        for entry in inject_detail_list:
            if not isinstance(entry, dict):
                continue
            resolved = str(entry.get('resolved') or '').strip()
            if not resolved:
                continue
            src = _resolve_src(resolved)
            if not src or src in seen_sources:
                continue
            seen_sources.add(src)
            sources.append(_info(src))
    for spec in inject_specs or []:
        src = _resolve_src(spec)
        if not src or src in seen_sources:
            continue
        seen_sources.add(src)
        sources.append(_info(src))
    return {
        'artifacts_dir': _info(artifacts_dir),
        'inject_source_dir': _info(inject_source_dir),
        'inject_sources': sources,
    }


def validate_resolved_paths_for_generation(paths: dict[str, Any], *, flow_run_remote: bool, backend: Any) -> str:
    try:
        repo_root = os.path.abspath(backend._get_repo_root()).replace('\\', '/').rstrip('/')
    except Exception:
        repo_root = ''
    allowed_remote_prefixes = ('/tmp/vulns', '/exports', '/outputs', '/inputs')

    def _iter_entries() -> list[tuple[str, str]]:
        out_entries: list[tuple[str, str]] = []
        if isinstance(paths.get('artifacts_dir'), dict):
            out_entries.append(('artifacts_dir', str(paths['artifacts_dir'].get('path') or '').strip()))
        if isinstance(paths.get('inject_source_dir'), dict):
            out_entries.append(('inject_source_dir', str(paths['inject_source_dir'].get('path') or '').strip()))
        inject_entries = paths.get('inject_sources') if isinstance(paths.get('inject_sources'), list) else []
        for idx, entry in enumerate(inject_entries):
            if not isinstance(entry, dict):
                continue
            out_entries.append((f'inject_source[{idx + 1}]', str(entry.get('path') or '').strip()))
        return out_entries

    issues: list[str] = []
    for label, path_text in _iter_entries():
        if not path_text:
            continue
        path_norm = path_text.replace('\\', '/')
        if flow_run_remote:
            if repo_root and path_norm.startswith(repo_root + '/'):
                issues.append(f'{label} leaked host-local repo path: {path_text}')
                continue
            if path_norm.startswith('/Users/'):
                issues.append(f'{label} leaked host-local macOS path: {path_text}')
                continue
            if path_norm.startswith('/') and not any(path_norm == pref or path_norm.startswith(pref + '/') for pref in allowed_remote_prefixes):
                issues.append(f'{label} is not in remote flow mount/outdir: {path_text}')
        else:
            if not os.path.isabs(path_text):
                issues.append(f'{label} must be absolute: {path_text}')
                continue
            if label in ('artifacts_dir', 'inject_source_dir'):
                if not (path_norm == '/tmp/vulns' or path_norm.startswith('/tmp/vulns/')):
                    issues.append(f'{label} must be under /tmp/vulns: {path_text}')
                    continue
            if not os.path.exists(path_text):
                issues.append(f'{label} does not exist: {path_text}')
    if issues:
        return '; '.join(issues[:5])
    return ''


def split_inject_spec(raw: str) -> tuple[str, str]:
    text = str(raw or '').strip()
    if not text:
        return '', ''
    for sep in ('->', '=>'):
        if sep in text:
            left, right = text.split(sep, 1)
            return left.strip(), right.strip()
    return text, ''


def stage_inject_uploads(
    injects: list[str],
    run_dir: str,
    *,
    run_index: int | None,
    backend: Any,
) -> list[str]:
    if not injects:
        return []
    allowed_root = os.path.abspath(backend._flow_inject_uploads_dir())
    artifacts_dir = os.path.join(run_dir, 'injects')
    os.makedirs(artifacts_dir, exist_ok=True)

    out_list: list[str] = []
    for raw in injects:
        src_raw, dest_raw = split_inject_spec(str(raw))
        src = str(src_raw or '').strip()
        if src.startswith('upload:'):
            src = src[len('upload:'):].strip()
        if src:
            try:
                abs_src = os.path.abspath(src)
            except Exception:
                abs_src = ''
        else:
            abs_src = ''

        if abs_src and os.path.exists(abs_src):
            try:
                if os.path.commonpath([allowed_root, abs_src]) == allowed_root:
                    base = os.path.basename(abs_src.rstrip('/')) or 'upload'
                    dest_name = flow_unique_dest_filename(artifacts_dir, base, sequence=run_index, backend=backend)
                    dest_path = os.path.join(artifacts_dir, dest_name)
                    if os.path.isdir(abs_src):
                        shutil.copytree(abs_src, dest_path, dirs_exist_ok=True)
                    else:
                        shutil.copy2(abs_src, dest_path)
                    new_src = dest_name
                    if dest_raw:
                        out_list.append(f"{new_src} -> {dest_raw}")
                    else:
                        out_list.append(new_src)
                    continue
            except Exception:
                pass
        out_list.append(str(raw))
    return out_list


def refresh_hints_for_current_chain(
    assignments: list[dict[str, Any]],
    *,
    chain_nodes: list[dict[str, Any]],
    gen_by_id: dict[str, dict[str, Any]],
    scenario_label: str,
    scenario_norm: str,
    backend: Any,
) -> list[dict[str, Any]]:
    if not isinstance(assignments, list) or not isinstance(chain_nodes, list):
        return assignments

    id_to_name_local: dict[str, str] = {}
    id_to_ip_local: dict[str, str] = {}
    chain_ids_local: list[str] = []
    try:
        for node in chain_nodes or []:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get('id') or '').strip()
            if not node_id:
                continue
            chain_ids_local.append(node_id)
            id_to_name_local[node_id] = str(node.get('name') or '').strip() or node_id
            ip_val = backend._first_valid_ipv4(node.get('ip4') or node.get('ipv4') or node.get('ip') or '')
            if ip_val:
                id_to_ip_local[node_id] = ip_val
    except Exception:
        pass

    out_local: list[dict[str, Any]] = []
    for idx, raw in enumerate(assignments or []):
        if not isinstance(raw, dict):
            continue
        assignment = dict(raw)
        this_id = str(assignment.get('node_id') or '').strip() or (chain_ids_local[idx] if idx < len(chain_ids_local) else '')
        next_id = chain_ids_local[idx + 1] if (idx + 1) < len(chain_ids_local) else ''
        assignment['node_id'] = this_id
        assignment['next_node_id'] = str(next_id)
        assignment['next_node_name'] = str(id_to_name_local.get(str(next_id)) or '')

        templates: list[str] = []
        try:
            overrides = assignment.get('hint_overrides') if isinstance(assignment.get('hint_overrides'), list) else None
            if isinstance(overrides, list) and overrides:
                templates = [str(x or '').strip() for x in overrides if str(x or '').strip()]
        except Exception:
            templates = []
        try:
            if not templates:
                hint_templates = assignment.get('hint_templates') if isinstance(assignment.get('hint_templates'), list) else None
                if isinstance(hint_templates, list) and hint_templates:
                    templates = [str(x or '').strip() for x in hint_templates if str(x or '').strip()]
        except Exception:
            pass
        try:
            if not templates:
                single_tpl = str(assignment.get('hint_template') or '').strip()
                if single_tpl:
                    templates = [single_tpl]
        except Exception:
            pass
        if not templates:
            try:
                generator_id = str(assignment.get('id') or '').strip()
                gen_def_local = gen_by_id.get(generator_id) if generator_id else None
                if isinstance(gen_def_local, dict):
                    templates = backend._flow_hint_templates_from_generator(gen_def_local)
            except Exception:
                templates = []
        if not templates:
            templates = ['Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}']

        normalized_templates: list[str] = []
        for template in templates or []:
            text = str(template or '').strip()
            if not text:
                continue
            if ('{{NEXT_NODE_' not in text) and ('{{THIS_NODE_' not in text):
                text = 'Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}'
            normalized_templates.append(text)
        if not normalized_templates:
            normalized_templates = ['Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}']

        rendered = [
            backend._flow_render_hint_template(
                template,
                scenario_label=(scenario_label or scenario_norm),
                id_to_name=id_to_name_local,
                id_to_ip=id_to_ip_local,
                this_id=str(this_id),
                next_id=str(next_id),
            )
            for template in normalized_templates
        ]
        rendered = [str(x or '').strip() for x in rendered if str(x or '').strip()]
        if not rendered:
            rendered = [
                backend._flow_render_hint_template(
                    'Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}',
                    scenario_label=(scenario_label or scenario_norm),
                    id_to_name=id_to_name_local,
                    id_to_ip=id_to_ip_local,
                    this_id=str(this_id),
                    next_id=str(next_id),
                )
            ]

        assignment['hint_templates'] = normalized_templates
        assignment['hint_template'] = str(normalized_templates[0] or '') if normalized_templates else ''
        assignment['hints'] = rendered
        assignment['hint'] = rendered[0] if rendered else ''
        out_local.append(assignment)

    return out_local


def clear_prior_outputs_from_assignments(
    assignments: list[dict[str, Any]],
    *,
    gen_by_id: dict[str, dict[str, Any]],
) -> list[Any]:
    cleaned_assignments: list[Any] = []
    for entry in assignments or []:
        if not isinstance(entry, dict):
            try:
                cleaned_assignments.append(entry)
            except Exception:
                pass
            continue
        assignment = dict(entry)
        for key in (
            'resolved_outputs',
            'resolved_outputs_detail',
            'resolved_paths',
            'inject_files_detail',
            'outputs_manifest',
            'artifacts_dir',
            'run_dir',
            'inject_source_dir',
            'flag_value',
            'generated',
        ):
            assignment.pop(key, None)

        inject_override = assignment.get('inject_files_override')
        has_override = isinstance(inject_override, list) and any(str(x or '').strip() for x in inject_override)
        if not has_override:
            generator_id = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
            gen_def = gen_by_id.get(generator_id) if generator_id else None
            inject_list = gen_def.get('inject_files') if isinstance(gen_def, dict) else None
            if isinstance(inject_list, list):
                cleaned = [str(x or '').strip() for x in inject_list if str(x or '').strip()]
                if cleaned:
                    assignment['inject_files'] = cleaned
                else:
                    assignment.pop('inject_files', None)
            else:
                raw_injects = assignment.get('inject_files')
                if isinstance(raw_injects, list):
                    cleaned = []
                    for raw in raw_injects:
                        text = str(raw or '').strip()
                        if not text:
                            continue
                        src = text
                        for sep in ('->', '=>'):
                            if sep in src:
                                src = src.split(sep, 1)[0].strip()
                                break
                        if src.startswith(('/', '~')) or src.startswith('upload:'):
                            continue
                        cleaned.append(text)
                    if cleaned:
                        assignment['inject_files'] = cleaned
                    else:
                        assignment.pop('inject_files', None)

        cleaned_assignments.append(assignment)
    return cleaned_assignments


def eligible_debug_summary(all_nodes: list[Any], *, backend: Any, max_items: int = 50) -> dict[str, Any]:
    vuln_nodes: list[dict[str, str]] = []
    nonvuln_docker_nodes: list[dict[str, str]] = []
    try:
        for node in all_nodes or []:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get('id') or '').strip()
            name = str(node.get('name') or node_id).strip()
            if not node_id:
                continue
            is_vuln = backend._flow_node_is_vuln(node)
            is_docker = backend._flow_node_is_docker_role(node)
            if is_vuln:
                if len(vuln_nodes) < max_items:
                    vuln_nodes.append({'id': node_id, 'name': name})
                continue
            if is_docker and len(nonvuln_docker_nodes) < max_items:
                nonvuln_docker_nodes.append({'id': node_id, 'name': name})
    except Exception:
        pass
    return {
        'vuln_nodes_count': sum(1 for node in (all_nodes or []) if isinstance(node, dict) and backend._flow_node_is_vuln(node)),
        'nonvuln_docker_nodes_count': sum(
            1
            for node in (all_nodes or [])
            if isinstance(node, dict) and backend._flow_node_is_docker_role(node) and (not backend._flow_node_is_vuln(node))
        ),
        'vuln_nodes_sample': vuln_nodes,
        'nonvuln_docker_nodes_sample': nonvuln_docker_nodes,
    }


def saved_chain_ids_from_flow_state(flow_state_for_prepare: Any) -> list[str]:
    try:
        flow_meta = flow_state_for_prepare if isinstance(flow_state_for_prepare, dict) else None
        saved_chain = flow_meta.get('chain') if isinstance(flow_meta, dict) else None
        if (not isinstance(saved_chain, list)) or (not saved_chain):
            chain_ids_xml = flow_meta.get('chain_ids') if isinstance(flow_meta, dict) else None
            if isinstance(chain_ids_xml, list) and chain_ids_xml:
                saved_chain = [{'id': str(x or '').strip()} for x in chain_ids_xml if str(x or '').strip()]
        saved_ids: list[str] = []
        if isinstance(saved_chain, list) and saved_chain:
            for entry in saved_chain:
                if not isinstance(entry, dict):
                    continue
                chain_id = str(entry.get('id') or '').strip()
                if chain_id:
                    saved_ids.append(chain_id)
        return saved_ids
    except Exception:
        return []


def pick_chain_nodes(
    nodes: list[Any],
    adj: Any,
    *,
    preview: Any,
    preset_steps: list[Any],
    allow_node_duplicates: bool,
    length: int,
    backend: Any,
) -> list[Any]:
    if preset_steps:
        return backend._pick_flag_chain_nodes_for_preset(nodes, adj, steps=preset_steps)
    if allow_node_duplicates:
        try:
            seed_val = int((preview.get('seed') if isinstance(preview, dict) else None) or 0)
        except Exception:
            seed_val = 0
        return backend._pick_flag_chain_nodes_allow_duplicates(nodes, adj, length=length, seed=seed_val)
    return backend._pick_flag_chain_nodes(nodes, adj, length=length)


def repair_explicit_chain_nodes(
    chain_ids: list[str],
    nodes: list[Any],
    adj: Any,
    *,
    preview: Any,
    preset_steps: list[Any],
    allow_node_duplicates: bool,
    length: int,
    requested_length: int,
    best_effort: bool,
    mode: str,
    stats: dict[str, Any],
    eligible_debug: dict[str, Any],
    warning: str,
    backend: Any,
) -> dict[str, Any]:
    id_map = {str(n.get('id') or '').strip(): n for n in (nodes or []) if isinstance(n, dict)}
    chain_nodes: list[Any] = []
    missing_chain_ids: list[str] = []
    for chain_id in chain_ids:
        if chain_id in id_map:
            chain_nodes.append(id_map[chain_id])
        else:
            chain_nodes.append(None)
            missing_chain_ids.append(chain_id)

    if missing_chain_ids:
        try:
            used = {
                str(node.get('id') or '').strip()
                for node in chain_nodes
                if isinstance(node, dict) and str(node.get('id') or '').strip()
            }

            def _needs_nonvuln_docker(pos: int) -> bool:
                if not preset_steps:
                    return False
                if pos < 0 or pos >= len(preset_steps):
                    return False
                return str((preset_steps[pos] or {}).get('kind') or '').strip() == 'flag-node-generator'

            def _eligible(candidate: dict[str, Any], pos: int) -> bool:
                try:
                    candidate_id = str(candidate.get('id') or '').strip()
                    if not candidate_id:
                        return False
                    if (not allow_node_duplicates) and candidate_id in used:
                        return False
                    is_docker = backend._flow_node_is_docker_role(candidate)
                    is_vuln = bool(candidate.get('is_vuln')) or bool(candidate.get('vulnerabilities'))
                    if _needs_nonvuln_docker(pos):
                        return bool(is_docker) and (not is_vuln)
                    return bool(is_vuln)
                except Exception:
                    return False

            for index, node in enumerate(chain_nodes):
                if isinstance(node, dict):
                    continue
                replacement = None
                for candidate in (nodes or []):
                    if not isinstance(candidate, dict):
                        continue
                    if not _eligible(candidate, index):
                        continue
                    replacement = candidate
                    break
                if replacement is not None:
                    replacement_id = str(replacement.get('id') or '').strip()
                    if replacement_id:
                        chain_nodes[index] = replacement
                        chain_ids[index] = replacement_id
                        used.add(replacement_id)

            chain_nodes = [node for node in chain_nodes if isinstance(node, dict)]
            if len(chain_nodes) < length:
                return {
                    'ok': False,
                    'status': 422,
                    'payload': {
                        'ok': False,
                        'error': 'Provided chain_ids do not match the selected preview plan (stale preview_plan?) and could not be fully repaired.',
                        'requested_length': requested_length,
                        'matched_length': len(chain_nodes),
                        'missing_chain_ids': missing_chain_ids,
                        'stats': stats,
                        'best_effort': bool(best_effort),
                    },
                }
        except Exception:
            return {
                'ok': False,
                'status': 422,
                'payload': {
                    'ok': False,
                    'error': 'Provided chain_ids did not match the selected preview plan and repair failed.',
                    'requested_length': requested_length,
                    'missing_chain_ids': missing_chain_ids,
                    'stats': stats,
                    'best_effort': bool(best_effort),
                },
            }

    if preset_steps and chain_nodes:
        try:
            used = {str(node.get('id') or '').strip() for node in chain_nodes if isinstance(node, dict)}
            for index, step in enumerate(preset_steps[:len(chain_nodes)]):
                if str((step or {}).get('kind') or '').strip() != 'flag-node-generator':
                    continue
                node = chain_nodes[index] if index < len(chain_nodes) else None
                if not isinstance(node, dict):
                    continue
                if not bool(node.get('is_vuln')):
                    continue
                replacement = None
                for candidate in (nodes or []):
                    if not isinstance(candidate, dict):
                        continue
                    candidate_id = str(candidate.get('id') or '').strip()
                    if not candidate_id:
                        continue
                    if (not allow_node_duplicates) and candidate_id in used:
                        continue
                    type_raw = str(candidate.get('type') or '')
                    type_name = type_raw.strip().lower()
                    is_docker = ('docker' in type_name) or (type_raw.strip().upper() == 'DOCKER')
                    if is_docker and not bool(candidate.get('is_vuln')):
                        replacement = candidate
                        break
                if replacement is not None:
                    replacement_id = str(replacement.get('id') or '').strip()
                    if replacement_id:
                        chain_nodes[index] = replacement
                        chain_ids[index] = replacement_id
                        used.add(replacement_id)
        except Exception:
            pass

    if chain_nodes:
        try:
            used = {
                str(node.get('id') or '').strip()
                for node in chain_nodes
                if isinstance(node, dict) and str(node.get('id') or '').strip()
            }
            reselect_chain = False
            reselect_reason = ''
            for index, node in enumerate(chain_nodes):
                if not isinstance(node, dict):
                    continue
                type_raw = str(node.get('type') or '')
                type_name = type_raw.strip().lower()
                is_docker = ('docker' in type_name) or (type_raw.strip().upper() == 'DOCKER')
                is_vuln = backend._flow_node_is_vuln(node)

                need_nonvuln_docker = False
                if preset_steps and index < len(preset_steps):
                    need_nonvuln_docker = str((preset_steps[index] or {}).get('kind') or '').strip() == 'flag-node-generator'

                if need_nonvuln_docker:
                    if is_docker and (not is_vuln):
                        continue
                else:
                    if is_vuln:
                        continue

                replacement = None
                for candidate in (nodes or []):
                    if not isinstance(candidate, dict):
                        continue
                    candidate_id = str(candidate.get('id') or '').strip()
                    if not candidate_id:
                        continue
                    if (not allow_node_duplicates) and candidate_id in used:
                        continue
                    candidate_type_raw = str(candidate.get('type') or '')
                    candidate_type_name = candidate_type_raw.strip().lower()
                    candidate_is_docker = ('docker' in candidate_type_name) or (candidate_type_raw.strip().upper() == 'DOCKER')
                    candidate_is_vuln = backend._flow_node_is_vuln(candidate)
                    if need_nonvuln_docker:
                        if not candidate_is_docker:
                            continue
                        if candidate_is_vuln:
                            continue
                    else:
                        if not candidate_is_vuln:
                            continue
                    replacement = candidate
                    break

                if replacement is None:
                    if best_effort or (mode in {'resolve', 'resolve_hints', 'hint', 'hint_only', 'preview'}):
                        reselect_chain = True
                        reselect_reason = 'Provided chain was incompatible with placement rules; selected a new valid chain.'
                        break
                    return {
                        'ok': False,
                        'status': 422,
                        'payload': {
                            'ok': False,
                            'error': 'Not enough eligible nodes for the provided chain. Flag-generators require vulnerability nodes; flag-node-generators require non-vulnerability docker-role nodes.',
                            'stats': stats,
                            'eligible': eligible_debug,
                        },
                    }

                replacement_id = str(replacement.get('id') or '').strip()
                if replacement_id:
                    chain_nodes[index] = replacement
                    chain_ids[index] = replacement_id
                    used.add(replacement_id)

            if reselect_chain:
                chain_nodes = pick_chain_nodes(
                    nodes,
                    adj,
                    preview=preview,
                    preset_steps=preset_steps,
                    allow_node_duplicates=allow_node_duplicates,
                    length=length,
                    backend=backend,
                )
                if len(chain_nodes) < 1:
                    return {
                        'ok': False,
                        'status': 422,
                        'payload': {
                            'ok': False,
                            'error': 'No eligible nodes found in preview plan (vulnerability nodes only for flag-generators).',
                            'available': len(chain_nodes),
                            'stats': stats,
                        },
                    }
                if (not allow_node_duplicates) and len(chain_nodes) < length:
                    return {
                        'ok': False,
                        'status': 422,
                        'payload': {
                            'ok': False,
                            'error': 'Not enough eligible nodes in preview plan to build the requested chain.',
                            'available': len(chain_nodes),
                            'stats': stats,
                            'eligible': eligible_debug,
                        },
                    }
                chain_ids = [
                    str(node.get('id') or '').strip()
                    for node in chain_nodes
                    if isinstance(node, dict) and str(node.get('id') or '').strip()
                ]
                warning = reselect_reason or warning
        except Exception:
            pass

    if (not allow_node_duplicates) and chain_nodes:
        try:
            seen = set()
            unique_nodes: list[dict[str, Any]] = []
            for node in chain_nodes:
                if not isinstance(node, dict):
                    continue
                node_id = str(node.get('id') or '').strip()
                if not node_id or node_id in seen:
                    continue
                seen.add(node_id)
                unique_nodes.append(node)
            chain_nodes = unique_nodes
        except Exception:
            pass

    if (not allow_node_duplicates) and len(chain_nodes) < length:
        chain_nodes = pick_chain_nodes(
            nodes,
            adj,
            preview=preview,
            preset_steps=preset_steps,
            allow_node_duplicates=allow_node_duplicates,
            length=length,
            backend=backend,
        )
    if len(chain_nodes) < 1:
        return {
            'ok': False,
            'status': 422,
            'payload': {
                'ok': False,
                'error': 'Provided chain_ids did not match any nodes in the preview plan.',
                'stats': stats,
            },
        }
    chain_ids = [str(node.get('id') or '').strip() for node in chain_nodes if isinstance(node, dict) and str(node.get('id') or '').strip()]
    return {
        'ok': True,
        'chain_nodes': chain_nodes,
        'chain_ids': chain_ids,
        'explicit_chain': bool(chain_ids),
        'warning': warning,
    }


def reuse_saved_flag_assignments(
    flow_state_for_prepare: Any,
    chain_nodes: list[Any],
    *,
    scenario_label: str,
    scenario_norm: str,
    backend: Any,
) -> list[dict[str, Any]]:
    try:
        flow_meta = flow_state_for_prepare if isinstance(flow_state_for_prepare, dict) else None
        saved_assignments = flow_meta.get('flag_assignments') if isinstance(flow_meta, dict) else None
        if not (isinstance(saved_assignments, list) and saved_assignments):
            return []

        try:
            desired_len = len(chain_nodes or [])
        except Exception:
            desired_len = 0
        if (not desired_len) or len(saved_assignments) < desired_len:
            return []

        ordered: list[dict[str, Any]] = []
        for index in range(desired_len):
            assignment = saved_assignments[index]
            if not isinstance(assignment, dict):
                ordered.append({})
                continue
            assignment_copy = dict(assignment)
            try:
                assignment_copy['node_id'] = str((chain_nodes[index] or {}).get('id') or '').strip()
            except Exception:
                pass
            ordered.append(assignment_copy)

        if not all(isinstance(item, dict) and str(item.get('id') or '').strip() for item in ordered):
            return []

        try:
            ordered = backend._flow_enrich_saved_flag_assignments(
                ordered,
                chain_nodes,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            pass

        if ordered and len(ordered) == len(chain_nodes):
            for index, node in enumerate(chain_nodes):
                assignment = ordered[index] if index < len(ordered) else {}
                if not isinstance(node, dict) or not isinstance(assignment, dict):
                    raise ValueError('invalid chain/assignment')
                node_id = str(node.get('id') or '').strip()
                assignment_node_id = str(assignment.get('node_id') or '').strip()
                if node_id and assignment_node_id and node_id != assignment_node_id:
                    raise ValueError('assignment node mismatch')
                is_docker = backend._flow_node_is_docker_role(node)
                is_vuln = bool(node.get('is_vuln'))
                kind = str(assignment.get('type') or '').strip() or 'flag-generator'
                if kind == 'flag-node-generator':
                    if not (is_docker and (not is_vuln)):
                        raise ValueError('flag-node-generator on ineligible node')
                else:
                    if not (is_docker or is_vuln):
                        raise ValueError('flag-generator on ineligible node')

        return ordered
    except Exception:
        return []


def build_generator_index(flag_generators: Any, flag_node_generators: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    try:
        for generator in (flag_generators or []):
            if not isinstance(generator, dict):
                continue
            generator_id = str(generator.get('id') or '').strip()
            if generator_id:
                out[generator_id] = generator
        for generator in (flag_node_generators or []):
            if not isinstance(generator, dict):
                continue
            generator_id = str(generator.get('id') or '').strip()
            if generator_id and generator_id not in out:
                out[generator_id] = generator
    except Exception:
        return {}
    return out


def find_missing_or_disabled_generators(
    flag_assignments: list[Any],
    chain_nodes: list[Any],
    *,
    gen_by_id: dict[str, dict[str, Any]],
    backend: Any,
) -> list[dict[str, Any]]:
    missing_or_disabled: list[dict[str, Any]] = []
    try:
        for index, assignment in enumerate(flag_assignments or []):
            if not isinstance(assignment, dict):
                continue
            generator_id = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
            if not generator_id:
                continue
            assignment_type = str(assignment.get('type') or '').strip() or 'flag-generator'
            kind = 'flag-node-generator' if assignment_type == 'flag-node-generator' else 'flag-generator'
            exists_enabled = generator_id in gen_by_id
            disabled = backend._is_installed_generator_disabled(kind=kind, generator_id=generator_id)
            if exists_enabled and (not disabled):
                continue
            node_id = ''
            node_name = ''
            try:
                node_id = str(assignment.get('node_id') or '').strip()
            except Exception:
                node_id = ''
            try:
                if index < len(chain_nodes or []):
                    node = chain_nodes[index] if isinstance(chain_nodes[index], dict) else {}
                    node_name = str(node.get('name') or '').strip()
            except Exception:
                node_name = ''
            reason = 'disabled' if disabled else 'not found/enabled'
            missing_or_disabled.append({
                'index': index,
                'node_id': node_id,
                'node_name': node_name,
                'generator_id': generator_id,
                'type': assignment_type,
                'reason': reason,
            })
    except Exception:
        return []
    return missing_or_disabled


def determine_flag_seed_epoch(candidate_paths: list[Any], *, time_module: Any) -> int | None:
    flag_seed_epoch: int | None = None
    try:
        for path in candidate_paths:
            if not path:
                continue
            try:
                abs_path = os.path.abspath(str(path))
            except Exception:
                abs_path = str(path)
            if abs_path and os.path.exists(abs_path):
                try:
                    flag_seed_epoch = int(os.path.getmtime(abs_path))
                    break
                except Exception:
                    continue
    except Exception:
        flag_seed_epoch = None
    if flag_seed_epoch is None:
        try:
            flag_seed_epoch = int(time_module.time())
        except Exception:
            flag_seed_epoch = None
    return flag_seed_epoch


def build_host_index(preview: Any) -> dict[str, dict[str, Any]]:
    host_by_id: dict[str, dict[str, Any]] = {}
    try:
        hosts = preview.get('hosts') or []
        if isinstance(hosts, list):
            for host in hosts:
                if not isinstance(host, dict):
                    continue
                host_by_id[str(host.get('node_id') or '').strip()] = host
    except Exception:
        return {}
    return host_by_id


def build_generator_run_config(
    assignment: dict[str, Any],
    host: dict[str, Any],
    *,
    preview: Any,
    preview_ip4: str,
    flow_context: dict[str, Any],
    gen_by_id: dict[str, dict[str, Any]],
    flow_default_generator_config: Any,
    backend: Any,
    time_module: Any = time,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    cfg_full = flow_default_generator_config(assignment)

    try:
        seed_ts = int(time_module.time() * 1000.0)
    except Exception:
        seed_ts = None
    if seed_ts is not None:
        try:
            cfg_full['seed_ts'] = seed_ts
            cfg_full['seed'] = f"{cfg_full.get('seed')}:{seed_ts}"
            cfg_full['secret'] = f"{cfg_full.get('secret')}:{seed_ts}"
        except Exception:
            pass

    try:
        if preview_ip4:
            cfg_full.setdefault('Knowledge(ip)', preview_ip4)
            cfg_full.setdefault('target_ip', preview_ip4)
            cfg_full.setdefault('host_ip', preview_ip4)
            cfg_full.setdefault('ip4', preview_ip4)
            cfg_full.setdefault('ipv4', preview_ip4)
    except Exception:
        pass

    try:
        node_name_val = str(host.get('name') or '').strip()
        if node_name_val:
            cfg_full['node_name'] = node_name_val
    except Exception:
        pass

    try:
        raw_overrides = assignment.get('config_overrides') or assignment.get('inputs_overrides') or assignment.get('input_overrides')
        if isinstance(raw_overrides, dict) and raw_overrides:
            cleaned_overrides: dict[str, Any] = {}
            for key, value in raw_overrides.items():
                key_text = str(key or '').strip()
                if not key_text:
                    continue
                cfg_full[key_text] = value
                cleaned_overrides[key_text] = value
            assignment['config_overrides'] = cleaned_overrides
    except Exception:
        pass

    cfg = cfg_full
    inputs_mismatch: dict[str, Any] = {}
    gen_def: dict[str, Any] | None = None
    try:
        generator_id = str(assignment.get('id') or '').strip()
        gd = gen_by_id.get(generator_id)
        gen_def = gd if isinstance(gd, dict) else None
    except Exception:
        gen_def = None

    try:
        if isinstance(gen_def, dict):
            allowed = all_input_names_of(gen_def)
            try:
                allowed |= set(backend._flow_synthesized_inputs())
            except Exception:
                pass

            try:
                inputs_def = gen_def.get('inputs')
                if isinstance(inputs_def, list):
                    for inp in inputs_def:
                        if not isinstance(inp, dict):
                            continue
                        name = str(inp.get('name') or '').strip()
                        if not name or 'default' not in inp:
                            continue
                        if name in cfg_full:
                            value = cfg_full.get(name)
                            if value is not None and (not isinstance(value, str) or value.strip()):
                                continue
                        cfg_full[name] = inp.get('default')
            except Exception:
                pass

            declared_required = None
            try:
                if isinstance(assignment.get('input_fields_required'), list):
                    declared_required = {str(x).strip() for x in (assignment.get('input_fields_required') or []) if str(x).strip()}
            except Exception:
                declared_required = None
            if declared_required is None:
                declared_required = required_input_names_of(gen_def)

            try:
                if allowed and flow_context:
                    blocked_keys = {'Flag(flag_id)', 'flag'}
                    for key in allowed:
                        if key in cfg_full:
                            continue
                        if key in blocked_keys and key not in (declared_required or set()):
                            continue
                        if key in flow_context:
                            cfg_full[key] = flow_context[key]
            except Exception:
                pass

            cfg_to_pass = cfg_full
            if allowed:
                keep = set(allowed)
                try:
                    keep |= set(declared_required or set())
                except Exception:
                    pass
                try:
                    keep |= set(backend._flow_synthesized_inputs())
                except Exception:
                    pass
                cfg_to_pass = {key: value for key, value in cfg_full.items() if key in keep}
            cfg = cfg_to_pass

            try:
                provided_keys = {str(key).strip() for key in (cfg_to_pass or {}).keys() if str(key).strip()}
            except Exception:
                provided_keys = set()

            missing_required = sorted([key for key in (declared_required or set()) if key not in provided_keys])

            unset_required: list[str] = []
            try:
                for key in sorted(list(declared_required or set())):
                    if key not in (cfg_to_pass or {}):
                        continue
                    value = (cfg_to_pass or {}).get(key)
                    if value is None:
                        unset_required.append(key)
                    elif isinstance(value, str) and (not value.strip()):
                        unset_required.append(key)
            except Exception:
                unset_required = []

            dropped_keys: list[str] = []
            try:
                if allowed:
                    dropped_keys = sorted([key for key in (cfg_full or {}).keys() if key not in (cfg_to_pass or {})])
                    try:
                        synthesized = set(backend._flow_synthesized_inputs())
                    except Exception:
                        synthesized = set()
                    dropped_keys = [key for key in dropped_keys if str(key) not in synthesized]
            except Exception:
                dropped_keys = []

            inputs_mismatch = {
                'declared_required': sorted(list(declared_required or set())),
                'provided': sorted(list(provided_keys)),
                'missing_required': missing_required,
                'unset_required': unset_required,
                'dropped': dropped_keys,
                'ok': (not missing_required and not unset_required and not dropped_keys),
            }
    except Exception:
        cfg = cfg_full
        inputs_mismatch = {}

    return cfg_full, cfg, inputs_mismatch, gen_def


def prepare_assignment_for_run(
    assignment: dict[str, Any],
    *,
    cfg: dict[str, Any],
    cfg_full: dict[str, Any],
    redact_kv_for_ui: Any,
) -> list[str]:
    declared_output_keys: list[str] = []
    try:
        declared_src = assignment.get('output_fields') if isinstance(assignment.get('output_fields'), list) else None
        if declared_src is None:
            declared_src = assignment.get('outputs') if isinstance(assignment.get('outputs'), list) else []
        declared_output_keys = sorted([str(x) for x in (declared_src or []) if str(x).strip()])
        prod_src = assignment.get('produces') if isinstance(assignment.get('produces'), list) else []
        prod_keys = [str(x).strip() for x in (prod_src or []) if str(x).strip()]
        if prod_keys:
            declared_output_keys = sorted(set(declared_output_keys) | set(prod_keys))
    except Exception:
        declared_output_keys = []

    try:
        assignment['resolved_inputs'] = redact_kv_for_ui(cfg)
        try:
            if isinstance(assignment.get('resolved_inputs'), dict) and isinstance(cfg_full, dict):
                if 'Knowledge(ip)' in cfg_full and 'Knowledge(ip)' not in assignment['resolved_inputs']:
                    assignment['resolved_inputs']['Knowledge(ip)'] = cfg_full.get('Knowledge(ip)')
        except Exception:
            pass
    except Exception:
        pass

    try:
        inject_override = assignment.get('inject_files_override')
        if isinstance(inject_override, list):
            cleaned = [str(x or '').strip() for x in (inject_override or [])]
            cleaned = [x for x in cleaned if x]
            assignment['inject_files'] = cleaned
    except Exception:
        pass

    try:
        flag_override = str(assignment.get('flag_override') or '').strip()
        if flag_override:
            assignment['flag_value'] = flag_override
            assignment['resolved_outputs'] = redact_kv_for_ui({'Flag(flag_id)': flag_override})
    except Exception:
        pass

    try:
        output_override = assignment.get('output_overrides')
        if isinstance(output_override, dict) and output_override:
            cleaned: dict[str, Any] = {}
            for key, value in (output_override or {}).items():
                key_text = str(key or '').strip()
                if not key_text:
                    continue
                cleaned[key_text] = value
            if cleaned:
                assignment['resolved_outputs'] = redact_kv_for_ui(cleaned)
                try:
                    if isinstance(cleaned.get('Flag(flag_id)'), str) and str(cleaned.get('Flag(flag_id)') or '').strip():
                        assignment['flag_value'] = str(cleaned.get('Flag(flag_id)') or '').strip()
                    elif isinstance(cleaned.get('flag'), str) and str(cleaned.get('flag') or '').strip():
                        assignment['flag_value'] = str(cleaned.get('flag') or '').strip()
                except Exception:
                    pass
    except Exception:
        pass

    return declared_output_keys


def prepare_generator_run_dir(
    generator_id: str,
    assignment_type: str,
    scenario_norm: str,
    *,
    host_name: str,
    node_id: str,
    run_index: int,
    flow_run_remote: bool,
    cleaned_scenario_roots: set[str],
) -> str:
    subdir = 'flag_node_generators_runs' if assignment_type == 'flag-node-generator' else 'flag_generators_runs'
    scenario_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', scenario_norm)
    scenario_root = os.path.join('/tmp/vulns', subdir, f"flow-{scenario_safe}")

    if not flow_run_remote:
        try:
            if scenario_root not in cleaned_scenario_roots:
                if os.path.exists(scenario_root):
                    shutil.rmtree(scenario_root)

                parent_dir = os.path.dirname(scenario_root)
                if os.path.isdir(parent_dir):
                    legacy_patterns = [
                        f"flow-{scenario_safe}-*",
                        f"flow-{scenario_norm}-*",
                    ]
                    for pattern in legacy_patterns:
                        for legacy_path in glob.glob(os.path.join(parent_dir, pattern)):
                            if os.path.isdir(legacy_path):
                                try:
                                    shutil.rmtree(legacy_path)
                                except Exception:
                                    pass

                os.makedirs(scenario_root, exist_ok=True)
                cleaned_scenario_roots.add(scenario_root)
            else:
                os.makedirs(scenario_root, exist_ok=True)
        except Exception:
            pass

    safe_gen_lbl = re.sub(r'[^a-zA-Z0-9_-]', '_', generator_id)
    safe_node_lbl = re.sub(r'[^a-zA-Z0-9_-]', '_', str(host_name or node_id))
    unique_sub = f"{run_index:02d}_{safe_gen_lbl[:30]}_{safe_node_lbl[:30]}"
    flow_out_dir = os.path.join(scenario_root, unique_sub)

    if not flow_run_remote:
        try:
            os.makedirs(flow_out_dir, exist_ok=True)
        except Exception:
            pass

    return flow_out_dir


def resolve_and_stage_inject_files(
    assignment: dict[str, Any],
    *,
    artifact_context: dict[str, str],
    flow_context: dict[str, Any],
    created_run_dirs: list[str],
    flow_out_dir: str,
    flow_run_remote: bool,
    run_index: int | None,
    backend: Any,
) -> list[str] | None:
    def _prior_run_dirs() -> list[str]:
        try:
            prior = [str(path) for path in (created_run_dirs or []) if str(path).strip()]
            prior = [path for path in prior if path and path != str(flow_out_dir or '')]
            return list(reversed(prior))
        except Exception:
            return []

    def _resolve_relative_from_prior_dirs(rel_path: str, prior_dirs: list[str]) -> str:
        for run_dir in prior_dirs:
            try:
                if not run_dir or not os.path.isdir(run_dir):
                    continue
                candidate = os.path.join(run_dir, rel_path.lstrip('/'))
                if os.path.exists(candidate):
                    return candidate
                flat = os.path.basename(rel_path)
                if flat:
                    candidate_flat = os.path.join(run_dir, flat)
                    if os.path.exists(candidate_flat):
                        return candidate_flat
            except Exception:
                continue
        return ''

    def _resolve_output_key_from_manifests(key: str, prior_dirs: list[str]) -> str:
        for run_dir in prior_dirs:
            try:
                if not run_dir or not os.path.isdir(run_dir):
                    continue
                manifest_path = os.path.join(run_dir, 'outputs.json')
                if not os.path.exists(manifest_path):
                    continue
                with open(manifest_path, 'r', encoding='utf-8') as manifest_file:
                    manifest = json.load(manifest_file) or {}
                outputs = manifest.get('outputs') if isinstance(manifest, dict) else None
                if not isinstance(outputs, dict):
                    continue
                value = outputs.get(key)
                if not isinstance(value, str) or not value.strip():
                    continue
                value_text = value.strip()
                if os.path.isabs(value_text) and os.path.exists(value_text):
                    return value_text
                candidate = os.path.join(run_dir, value_text.lstrip('/'))
                if os.path.exists(candidate):
                    return candidate
                flat = os.path.basename(value_text)
                if flat:
                    candidate_flat = os.path.join(run_dir, flat)
                    if os.path.exists(candidate_flat):
                        return candidate_flat
            except Exception:
                continue
        return ''

    try:
        raw_injects = assignment.get('inject_files')
        if isinstance(raw_injects, list):
            prior_dirs = _prior_run_dirs()
            resolved_injects: list[str] = []
            for item in raw_injects:
                text = str(item or '').strip()
                if not text:
                    continue

                src, dest = split_inject_spec(text)
                final_src = src

                if src in artifact_context:
                    final_src = artifact_context[src]
                elif f"artifacts/{src}" in artifact_context:
                    final_src = artifact_context[f"artifacts/{src}"]
                elif src in flow_context:
                    try:
                        flow_value = flow_context.get(src)
                    except Exception:
                        flow_value = None
                    if isinstance(flow_value, str) and flow_value.strip():
                        candidate = flow_value.strip()
                        if os.path.isabs(candidate):
                            final_src = candidate
                        else:
                            resolved = _resolve_relative_from_prior_dirs(candidate, prior_dirs)
                            if resolved:
                                final_src = resolved

                try:
                    if final_src == src and src and (not os.path.isabs(src)):
                        manifest_resolved = _resolve_output_key_from_manifests(src, prior_dirs)
                        if manifest_resolved:
                            final_src = manifest_resolved
                except Exception:
                    pass

                if dest:
                    resolved_injects.append(f"{final_src} -> {dest}")
                else:
                    resolved_injects.append(final_src)
            assignment['inject_files'] = resolved_injects
    except Exception:
        pass

    effective_injects = None
    if not flow_run_remote:
        try:
            inject_files = assignment.get('inject_files') if isinstance(assignment, dict) else None
            if isinstance(inject_files, list) and inject_files:
                effective_injects = stage_inject_uploads(
                    list(inject_files),
                    str(flow_out_dir),
                    run_index=run_index,
                    backend=backend,
                )
                assignment['inject_files'] = list(effective_injects)
        except Exception:
            effective_injects = None
    return effective_injects


def process_generator_outputs(
    assignment: dict[str, Any],
    outputs: dict[str, Any],
    *,
    ok_run: bool,
    note: str,
    manifest_path: str | None,
    flow_out_dir: str,
    assignment_type: str,
    gen_def: dict[str, Any] | None,
    preview_ip4: str,
    node_id: str,
    generator_id: str,
    flow_context: dict[str, Any],
    seen_flag_values: set[str],
    redact_kv_for_ui: Any,
    apply_outputs_to_hint_text: Any,
    apply_node_placeholders: Any,
    backend: Any,
) -> dict[str, Any]:
    app = backend.app

    try:
        flag_override = str((assignment or {}).get('flag_override') or '').strip()
        if flag_override:
            outputs['Flag(flag_id)'] = flag_override
            outputs['flag'] = flag_override
    except Exception:
        pass

    try:
        output_overrides = (assignment or {}).get('output_overrides')
        if isinstance(output_overrides, dict) and output_overrides:
            for key, value in (output_overrides or {}).items():
                key_text = str(key or '').strip()
                if key_text:
                    outputs[key_text] = value
    except Exception:
        pass

    try:
        if 'flag' in outputs and 'Flag(flag_id)' not in outputs:
            outputs['Flag(flag_id)'] = outputs.get('flag')
    except Exception:
        pass

    try:
        if flow_out_dir and os.path.isdir(flow_out_dir):
            updates: dict[str, str] = {}
            for key, value in outputs.items():
                if not isinstance(value, str) or not value.strip():
                    continue
                if value.startswith('/') or '://' in value:
                    continue
                flat_value = os.path.basename(value)
                abs_candidate = os.path.join(flow_out_dir, value.lstrip('/'))
                if not os.path.exists(abs_candidate):
                    candidate = os.path.join(flow_out_dir, flat_value)
                    if os.path.exists(candidate):
                        abs_candidate = candidate
                if os.path.exists(abs_candidate):
                    updates[str(key)] = abs_candidate

            if updates:
                outputs.update(updates)
                try:
                    for key, value in (updates or {}).items():
                        key_text = str(key)
                        if key_text:
                            flow_context[key_text] = value
                except Exception:
                    pass
                if manifest_path:
                    try:
                        with open(manifest_path, 'w', encoding='utf-8') as manifest_file:
                            json.dump({'outputs': outputs}, manifest_file, indent=2)
                    except Exception:
                        pass
    except Exception:
        pass

    try:
        if preview_ip4:
            ip_keys = {
                'Knowledge(ip)',
                'host.ip',
                'host_ip',
                'target_ip',
                'ip',
                'ip4',
                'ipv4',
                'address',
            }
            for key in list(outputs.keys()):
                key_text = str(key)
                if key_text not in ip_keys:
                    continue
                old_value = outputs.get(key)
                old_ip = backend._first_valid_ipv4(old_value)
                if old_ip and old_ip != preview_ip4:
                    outputs[key] = preview_ip4
                    try:
                        app.logger.info(
                            '[flow.prepare_preview_for_execute] clamped %s=%s -> %s for node=%s',
                            key_text,
                            old_ip,
                            preview_ip4,
                            node_id,
                        )
                    except Exception:
                        pass
    except Exception:
        pass

    try:
        if assignment_type == 'flag-node-generator':
            compose_cfg = gen_def.get('compose') if isinstance(gen_def, dict) else None
            if not isinstance(compose_cfg, dict):
                ok_run = False
                note = 'flag-node-generator must declare docker-compose runtime.'
            else:
                compose_file_val = str(
                    outputs.get('File(path)')
                    or outputs.get('file')
                    or outputs.get('File')
                    or ''
                ).strip()
                if not compose_file_val:
                    ok_run = False
                    note = 'flag-node-generator must output File(path) for docker-compose file.'
                else:
                    compose_base = os.path.basename(compose_file_val).strip().lower()
                    if compose_base not in ('docker-compose.yml', 'docker-compose.yaml'):
                        ok_run = False
                        note = f'flag-node-generator File(path) must be docker-compose.yml/.yaml (got {compose_file_val}).'
                    else:
                        compose_candidates = []
                        if os.path.isabs(compose_file_val):
                            compose_candidates.append(compose_file_val)
                        if flow_out_dir:
                            compose_candidates.extend([
                                os.path.join(flow_out_dir, compose_file_val.lstrip('/')),
                                os.path.join(flow_out_dir, compose_base),
                            ])
                        if not any(os.path.exists(path) for path in compose_candidates if path):
                            ok_run = False
                            note = f'flag-node-generator compose output missing on disk: {compose_file_val}'
    except Exception as exc:
        ok_run = False
        note = f'flag-node-generator compose validation failed: {exc}'

    actual_output_keys = sorted([str(key) for key in outputs.keys() if str(key).strip()])

    try:
        for key, value in outputs.items():
            key_text = str(key)
            if key_text:
                flow_context[key_text] = value
    except Exception:
        pass

    try:
        assignment['resolved_outputs'] = redact_kv_for_ui(outputs)
    except Exception:
        pass

    try:
        if isinstance(assignment.get('hints'), list) and assignment.get('hints'):
            new_hints = [apply_outputs_to_hint_text(str(text), outputs) for text in (assignment.get('hints') or [])]
            new_hints = [apply_node_placeholders(str(text), node_ip4=preview_ip4) for text in new_hints]
            assignment['hints'] = new_hints
            assignment['hint'] = str(new_hints[0] or '') if new_hints else str(assignment.get('hint') or '')
        else:
            hint_final = apply_outputs_to_hint_text(str(assignment.get('hint') or ''), outputs)
            hint_final = apply_node_placeholders(str(hint_final), node_ip4=preview_ip4)
            if hint_final and hint_final != str(assignment.get('hint') or ''):
                assignment['hint'] = hint_final
    except Exception:
        pass

    try:
        flag_value = outputs.get('Flag(flag_id)') or outputs.get('flag')
        if not (isinstance(flag_value, str) and flag_value.strip()):
            try:
                app.logger.warning(
                    '[flow.generator] no flag output for generator=%s node=%s out_dir=%s keys=%s',
                    generator_id,
                    node_id,
                    flow_out_dir,
                    sorted(list(outputs.keys())) if isinstance(outputs, dict) else [],
                )
            except Exception:
                pass
        if isinstance(flag_value, str) and flag_value.strip():
            flag_value_clean = flag_value.strip()
            if flag_value_clean in seen_flag_values:
                raise RuntimeError(f'duplicate flag value: {flag_value_clean}')
            seen_flag_values.add(flag_value_clean)
        if ok_run and flow_out_dir and isinstance(flag_value, str) and flag_value.strip():
            with open(os.path.join(flow_out_dir, 'flag.txt'), 'w', encoding='utf-8') as flag_file:
                flag_file.write(flag_value.strip() + '\n')
            try:
                assignment['flag_value'] = flag_value.strip()
            except Exception:
                pass
    except RuntimeError:
        raise
    except Exception:
        pass

    return {
        'ok_run': bool(ok_run),
        'note': str(note or ''),
        'outs': outputs,
        'actual_output_keys': actual_output_keys,
    }


def finalize_generator_assignment_metadata(
    assignment: dict[str, Any],
    meta_host: dict[str, Any],
    *,
    flow_out_dir: str,
    flow_run_remote: bool,
    generator_catalog: str,
    generator_id: str,
    assignment_type: str,
    cfg: dict[str, Any],
    declared_output_keys: list[str],
    actual_output_keys: list[str],
    mismatch: dict[str, Any],
    inputs_mismatch: dict[str, Any],
    manifest_path: str,
    ok_run: bool,
    note: str,
    backend: Any,
) -> dict[str, Any]:
    inject_source_dir = str(flow_out_dir or '')
    if not flow_run_remote:
        try:
            if flow_out_dir and os.path.isdir(os.path.join(flow_out_dir, 'injected')):
                inject_source_dir = os.path.join(flow_out_dir, 'injected')
            elif flow_out_dir and os.path.isdir(os.path.join(flow_out_dir, 'artifacts')):
                inject_source_dir = os.path.join(flow_out_dir, 'artifacts')
        except Exception:
            inject_source_dir = str(flow_out_dir or '')

    inject_detail_raw = assignment.get('inject_files_detail')
    inject_from_detail = inject_files_for_copy_from_detail(inject_detail_raw, inject_source_dir)
    if isinstance(inject_detail_raw, list):
        normalized_inject_files = inject_from_detail
    else:
        normalized_inject_files = (
            [
                item
                for item in (
                    normalize_inject_spec_for_copy(raw, inject_source_dir)
                    for raw in (assignment.get('inject_files') or [])
                    if raw is not None
                )
                if item
            ]
            if isinstance(assignment.get('inject_files'), list)
            else []
        )

    resolved_paths = collect_resolved_path_info(
        artifacts_dir=str(flow_out_dir or ''),
        inject_source_dir=inject_source_dir,
        inject_detail_list=inject_detail_raw,
        inject_specs=list(assignment.get('inject_files') or []) if isinstance(assignment.get('inject_files'), list) else [],
        source_dir=inject_source_dir,
        remote_mode=bool(flow_run_remote),
        backend=backend,
    )

    if ok_run:
        resolved_path_issue = validate_resolved_paths_for_generation(
            resolved_paths,
            flow_run_remote=bool(flow_run_remote),
            backend=backend,
        )
        if resolved_path_issue:
            ok_run = False
            note = f'flow path validation failed: {resolved_path_issue}'

    meta_host['flow_flag'] = {
        'type': assignment_type,
        'generator_catalog': generator_catalog,
        'generator_id': generator_id,
        'generator_name': str(assignment.get('name') or ''),
        'generator_language': str(assignment.get('language') or ''),
        'generator_source': str(assignment.get('flag_generator') or ''),
        'artifacts_dir': str(flow_out_dir or ''),
        'inject_source_dir': inject_source_dir,
        'inject_files': normalized_inject_files,
        'inputs': list(assignment.get('inputs') or []) if isinstance(assignment.get('inputs'), list) else [],
        'outputs': list(assignment.get('outputs') or []) if isinstance(assignment.get('outputs'), list) else [],
        'hint_template': str(assignment.get('hint_template') or ''),
        'hint': str(assignment.get('hint') or ''),
        'next_node_id': str(assignment.get('next_node_id') or ''),
        'next_node_name': str(assignment.get('next_node_name') or ''),
        'generated': bool(ok_run),
        'generation_note': str(note or ''),
        'run_dir': str(flow_out_dir or ''),
        'outputs_manifest': str(manifest_path or ''),
        'resolved_paths': resolved_paths,
        'actual_outputs': actual_output_keys,
        'declared_outputs': declared_output_keys,
        'outputs_match': bool(mismatch.get('ok')) if isinstance(mismatch, dict) and mismatch else True,
        'outputs_mismatch': mismatch,
        'inputs_match': bool(inputs_mismatch.get('ok')) if isinstance(inputs_mismatch, dict) and inputs_mismatch else True,
        'inputs_mismatch': inputs_mismatch,
        'config': cfg,
    }

    try:
        assignment['generated'] = bool(ok_run)
        assignment['generation_note'] = str(note or '')
        assignment['artifacts_dir'] = str(flow_out_dir or '')
        assignment['inject_source_dir'] = inject_source_dir
        assignment['inject_files'] = list(normalized_inject_files or [])
        if isinstance(inject_detail_raw, list) and not normalized_inject_files:
            assignment['inject_files_detail'] = []
        assignment['outputs_manifest'] = str(manifest_path or '')
        assignment['resolved_paths'] = resolved_paths
        assignment['declared_outputs'] = declared_output_keys
        assignment['actual_outputs'] = actual_output_keys
        assignment['outputs_match'] = bool(mismatch.get('ok')) if isinstance(mismatch, dict) and mismatch else True
        assignment['outputs_mismatch'] = mismatch
        assignment['inputs_match'] = bool(inputs_mismatch.get('ok')) if isinstance(inputs_mismatch, dict) and inputs_mismatch else True
        assignment['inputs_mismatch'] = inputs_mismatch
        assignment['config'] = cfg
    except Exception:
        pass

    return {
        'ok_run': bool(ok_run),
        'note': str(note or ''),
    }


def prepare_disabled_assignment_view(
    assignment: dict[str, Any],
    host: dict[str, Any] | None,
    *,
    preview: Any,
    preview_ip4: str,
    occurrence_idx: int,
    gen_by_id: dict[str, dict[str, Any]],
    flow_default_generator_config: Any,
    redact_kv_for_ui: Any,
    backend: Any,
    time_module: Any = time,
) -> None:
    seed_val = preview.get('seed') if isinstance(preview, dict) else None
    cfg_full, cfg, _inputs_mismatch, _gen_def = build_generator_run_config(
        assignment,
        host or {},
        preview=preview,
        preview_ip4=preview_ip4,
        flow_context={},
        gen_by_id=gen_by_id,
        flow_default_generator_config=lambda a: flow_default_generator_config(
            a,
            seed_val=seed_val,
            occurrence_idx=occurrence_idx,
        ),
        backend=backend,
        time_module=time_module,
    )
    prepare_assignment_for_run(
        assignment,
        cfg=cfg,
        cfg_full=cfg_full,
        redact_kv_for_ui=redact_kv_for_ui,
    )
    assignment['config'] = cfg
    assignment['generated'] = False
    assignment['generation_note'] = 'flags disabled (invalid dependency order)'


def normalize_postrun_inject_files(flag_assignments: list[Any], created_run_dirs: list[str]) -> None:
    artifact_by_key: dict[str, str] = {}
    run_dirs = [str(path) for path in (created_run_dirs or []) if str(path).strip()]
    for run_dir in run_dirs:
        try:
            if not run_dir or not os.path.isdir(run_dir):
                continue
            manifest_path = os.path.join(run_dir, 'outputs.json')
            if not os.path.exists(manifest_path):
                continue
            with open(manifest_path, 'r', encoding='utf-8') as manifest_file:
                manifest = json.load(manifest_file) or {}
            outputs = manifest.get('outputs') if isinstance(manifest, dict) else None
            if not isinstance(outputs, dict):
                continue
            for key, value in outputs.items():
                key_text = str(key or '').strip()
                if not key_text or key_text in artifact_by_key:
                    continue
                if not isinstance(value, str) or not value.strip():
                    continue
                value_text = value.strip()
                if os.path.isabs(value_text) and os.path.exists(value_text):
                    artifact_by_key[key_text] = value_text
                    artifact_by_key.setdefault(value_text, value_text)
                    continue
                candidate = os.path.join(run_dir, value_text.lstrip('/'))
                if os.path.exists(candidate):
                    artifact_by_key[key_text] = candidate
                    artifact_by_key.setdefault(value_text, candidate)
                    flat0 = os.path.basename(value_text)
                    if flat0:
                        artifact_by_key.setdefault(flat0, candidate)
                    continue
                flat = os.path.basename(value_text)
                if flat:
                    candidate2 = os.path.join(run_dir, flat)
                    if os.path.exists(candidate2):
                        artifact_by_key[key_text] = candidate2
                        artifact_by_key.setdefault(value_text, candidate2)
                        artifact_by_key.setdefault(flat, candidate2)
        except Exception:
            continue

    fallback_abs: str | None = None
    try:
        for value in (artifact_by_key or {}).values():
            if isinstance(value, str) and value.strip() and os.path.isabs(value.strip()):
                fallback_abs = value.strip()
                break
    except Exception:
        fallback_abs = None

    if not artifact_by_key:
        return

    for assignment in (flag_assignments or []):
        if not isinstance(assignment, dict):
            continue
        injects = assignment.get('inject_files') if isinstance(assignment.get('inject_files'), list) else None
        if not injects:
            continue
        resolved: list[str] = []
        for raw in injects:
            src, dest = split_inject_spec(str(raw))
            src_resolved = src
            if src and (not os.path.isabs(src)) and src in artifact_by_key:
                src_resolved = artifact_by_key[src]
            if src_resolved and (not os.path.isabs(src_resolved)):
                for run_dir in reversed(run_dirs):
                    try:
                        if not run_dir or not os.path.isdir(run_dir):
                            continue
                        candidate = os.path.join(run_dir, str(src_resolved).lstrip('/'))
                        if os.path.exists(candidate):
                            src_resolved = candidate
                            break
                        flat = os.path.basename(str(src_resolved))
                        if flat:
                            candidate2 = os.path.join(run_dir, flat)
                            if os.path.exists(candidate2):
                                src_resolved = candidate2
                                break
                    except Exception:
                        continue
            try:
                if src_resolved and (not os.path.isabs(str(src_resolved))) and fallback_abs:
                    src_resolved = fallback_abs
            except Exception:
                pass
            resolved.append(f"{src_resolved} -> {dest}" if dest else src_resolved)
        assignment['inject_files'] = resolved


def write_generator_run_log(
    *,
    outputs_dir_getter: Any,
    generator_id: str,
    node_name: str,
    flow_run_id: str,
    ok_run: bool,
    note: str,
    run_stdout: str | None,
    run_stderr: str | None,
) -> str | None:
    try:
        logs_root = os.path.join(outputs_dir_getter(), 'logs', 'flow_generator_logs')
        os.makedirs(logs_root, exist_ok=True)
        safe_gen = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(generator_id or 'generator')).strip('_') or 'generator'
        safe_node = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(node_name or 'node')).strip('_') or 'node'
        safe_run = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(flow_run_id or 'run'))
        filename = f"{safe_gen}_{safe_node}_{safe_run}.log"
        log_path = os.path.join(logs_root, filename)
        with open(log_path, 'w', encoding='utf-8') as log_file:
            log_file.write(f"generator_id={generator_id}\n")
            log_file.write(f"node={safe_node}\n")
            log_file.write(f"ok={bool(ok_run)}\n")
            log_file.write(f"note={str(note or '')}\n\n")
            if isinstance(run_stdout, str) and run_stdout.strip():
                log_file.write('--- stdout ---\n')
                log_file.write(run_stdout.strip())
                log_file.write('\n')
            if isinstance(run_stderr, str) and run_stderr.strip():
                log_file.write('--- stderr ---\n')
                log_file.write(run_stderr.strip())
                log_file.write('\n')
        return log_path
    except Exception:
        return None


def capture_artifact_context(artifact_context: dict[str, str], outs: dict[str, Any], flow_out_dir: str) -> None:
    try:
        if not flow_out_dir:
            return
        for key, value in (outs or {}).items():
            if not isinstance(value, str):
                continue
            value_text = value.strip()
            if value_text and os.path.isabs(value_text) and os.path.exists(value_text):
                artifact_context[str(key).strip()] = value_text
                continue
            candidate = os.path.join(flow_out_dir, value_text)
            if os.path.exists(candidate):
                artifact_context[str(key).strip()] = candidate
    except Exception:
        pass


def materialize_hint_file(
    assignment: dict[str, Any],
    *,
    flow_out_dir: str,
    flow_run_remote: bool,
    flow_core_cfg: dict[str, Any] | None,
    backend: Any,
) -> None:
    try:
        flow_mount_dir = str(flow_out_dir or '')
        allow_hint_file = True
        if not flow_run_remote:
            try:
                if flow_out_dir:
                    injected = os.path.join(flow_out_dir, 'injected')
                    artifacts = os.path.join(flow_out_dir, 'artifacts')
                    if os.path.isdir(injected):
                        flow_mount_dir = injected
                    elif os.path.isdir(artifacts):
                        flow_mount_dir = artifacts
            except Exception:
                flow_mount_dir = str(flow_out_dir or '')
        else:
            try:
                flow_mount_dir = posixpath.join(str(flow_out_dir or ''), 'artifacts')
            except Exception:
                flow_mount_dir = str(flow_out_dir or '')

        try:
            inject_list = assignment.get('inject_files') if isinstance(assignment, dict) else None
            if isinstance(inject_list, list) and inject_list:
                allow_hint = False
                for raw in inject_list:
                    source = str(raw or '').strip().replace('\\', '/')
                    for sep in ('->', '=>'):
                        if sep in source:
                            source = source.split(sep, 1)[0].strip()
                            break
                    if not source:
                        continue
                    if source == 'hint.txt' or source.endswith('/hint.txt'):
                        allow_hint = True
                        break
                if not allow_hint:
                    allow_hint_file = False
        except Exception:
            pass

        if not allow_hint_file:
            return

        hint_texts: list[str] = []
        if isinstance(assignment.get('hints'), list):
            hint_texts = [str(x or '').strip() for x in (assignment.get('hints') or []) if str(x or '').strip()]
        if not hint_texts:
            single = str(assignment.get('hint') or '').strip()
            if single:
                hint_texts = [single]
        if not (flow_mount_dir and hint_texts):
            return

        if flow_run_remote and isinstance(flow_core_cfg, dict):
            hint_payload = ''.join(
                [
                    (f"Hint {idx + 1}/{len(hint_texts)}: {text}\n" if len(hint_texts) > 1 else f"{text}\n")
                    for idx, text in enumerate(hint_texts)
                ]
            )
            script = (
                'import os\n'
                f"p={json.dumps(posixpath.join(flow_mount_dir, 'hint.txt'))}\n"
                'd=os.path.dirname(p)\n'
                'os.makedirs(d, exist_ok=True)\n'
                f"open(p,'w',encoding='utf-8').write({json.dumps(hint_payload)})\n"
                "print('{}')\n"
            )
            try:
                backend._run_remote_python_json(
                    flow_core_cfg,
                    script,
                    logger=backend.app.logger,
                    label='flow.hint.remote',
                    timeout=20.0,
                )
            except Exception:
                pass
        else:
            with open(os.path.join(flow_mount_dir, 'hint.txt'), 'w', encoding='utf-8') as hint_file:
                if len(hint_texts) == 1:
                    hint_file.write(hint_texts[0] + '\n')
                else:
                    for idx, text in enumerate(hint_texts, start=1):
                        hint_file.write(f"Hint {idx}/{len(hint_texts)}: {text}\n")
    except Exception:
        pass


def compute_output_mismatch(declared_output_keys: list[str], actual_output_keys: list[str], *, ok_run: bool) -> dict[str, Any]:
    if not (ok_run and actual_output_keys):
        return {}
    try:
        ignore_actual = {'node_name', 'nodename', 'nodeName'}
        declared_set = set(declared_output_keys or [])
        actual_set = {key for key in (actual_output_keys or []) if key not in ignore_actual}
        missing = sorted(list(declared_set - actual_set))
        extra = sorted(list(actual_set - declared_set))
        return {
            'declared': declared_output_keys,
            'actual': actual_output_keys,
            'missing': missing,
            'extra': extra,
            'ok': (not missing and not extra),
        }
    except Exception:
        return {}


def invoke_generator_run(
    generator_id: str,
    *,
    flow_run_remote: bool,
    flow_remote_repo_dir: str | None,
    flow_core_cfg: dict[str, Any] | None,
    flow_out_dir: str,
    cfg: dict[str, Any],
    assignment_type: str,
    gen_timeout_s: int,
    effective_injects: list[str] | None,
    flow_try_run_generator_remote: Any,
    flow_try_run_generator: Any,
) -> dict[str, Any]:
    manifest_outputs: dict[str, Any] | None = None
    run_stdout: str | None = None
    run_stderr: str | None = None

    if flow_run_remote and flow_remote_repo_dir and isinstance(flow_core_cfg, dict):
        ok_run, note, manifest_path, manifest_outputs, run_stdout, run_stderr = flow_try_run_generator_remote(
            generator_id,
            out_dir=flow_out_dir,
            config=cfg,
            kind=assignment_type,
            timeout_s=gen_timeout_s,
            inject_files_override=effective_injects,
            core_cfg=flow_core_cfg,
            repo_dir=flow_remote_repo_dir,
        )
    else:
        ok_run, note, manifest_path, run_stdout, run_stderr = flow_try_run_generator(
            generator_id,
            out_dir=flow_out_dir,
            config=cfg,
            kind=assignment_type,
            timeout_s=gen_timeout_s,
            inject_files_override=effective_injects,
        )

        if ok_run and not manifest_path and flow_out_dir:
            try:
                flag_path = os.path.join(flow_out_dir, 'flag.txt')
                if os.path.exists(flag_path):
                    with open(flag_path, 'r', encoding='utf-8', errors='ignore') as flag_file:
                        flag_val = (flag_file.read() or '').strip()
                    if flag_val:
                        manifest_outputs = {'Flag(flag_id)': flag_val, 'flag': flag_val}
            except Exception:
                pass

        if ok_run and flow_out_dir and os.path.isdir(flow_out_dir):
            verification_outs = manifest_outputs
            if not verification_outs and manifest_path and os.path.exists(manifest_path):
                try:
                    with open(manifest_path, 'r', encoding='utf-8') as manifest_file:
                        manifest = json.load(manifest_file) or {}
                        verification_outs = manifest.get('outputs')
                except Exception:
                    pass
            if ok_run and verification_outs:
                for _key, value in verification_outs.items():
                    if isinstance(value, str) and (value.startswith('/') or '/' in value or '.' in value):
                        exists = os.path.exists(value)
                        if not exists:
                            candidate = os.path.join(flow_out_dir, value.lstrip('/'))
                            if os.path.exists(candidate):
                                exists = True
                        if not exists:
                            ok_run = False
                            note = f'Artifact verification failed: {value} does not exist on local disk'
                            break

    return {
        'ok_run': bool(ok_run),
        'note': str(note or ''),
        'manifest_path': str(manifest_path or ''),
        'manifest_outputs': manifest_outputs,
        'run_stdout': run_stdout,
        'run_stderr': run_stderr,
    }


def handle_generation_failures(
    generation_failures: list[Any],
    *,
    created_run_dirs: list[str],
    failed_run_dirs: list[str],
    best_effort: bool,
) -> dict[str, Any]:
    force_fail = False
    try:
        force_fail = any(
            'duplicate flag value' in str(item.get('error', '') or '')
            for item in (generation_failures or [])
            if isinstance(item, dict)
        )
    except Exception:
        force_fail = False

    try:
        base_dir = os.path.abspath(os.path.join('/tmp', 'vulns'))
        to_remove = (created_run_dirs or [])
        if best_effort:
            to_remove = (failed_run_dirs or [])
        for run_dir in to_remove:
            try:
                abs_dir = os.path.abspath(str(run_dir))
                if os.path.commonpath([abs_dir, base_dir]) != base_dir:
                    continue
                shutil.rmtree(abs_dir, ignore_errors=True)
            except Exception:
                continue
    except Exception:
        pass

    return {
        'force_fail': bool(force_fail),
        'should_fail': bool((not best_effort) or force_fail),
    }


def persist_prepare_preview_plan(
    *,
    meta: dict[str, Any] | None,
    preview: dict[str, Any],
    flow_meta: dict[str, Any],
    base_plan_path: str,
    scenario_label: str,
    scenario_norm: str,
    backend: Any,
) -> dict[str, Any]:
    try:
        meta_out: dict[str, Any] | None
        if isinstance(meta, dict):
            meta_out = dict(meta)
            meta_out['flow'] = flow_meta
            meta_out['updated_at'] = backend._iso_now()
        else:
            meta_out = {'flow': flow_meta, 'updated_at': backend._iso_now()}

        out_path = ''
        xml_target = backend._existing_xml_path_or_none(str((meta_out or {}).get('xml_path') or '').strip())
        if not xml_target:
            xml_target = backend._existing_xml_path_or_none(base_plan_path)
        if not xml_target:
            xml_target = backend._existing_xml_path_or_none(backend._latest_xml_path_for_scenario(scenario_norm) or '')
        if not xml_target:
            return {'ok': False, 'error': 'Failed to persist flow-modified preview plan: XML path not found.'}

        if isinstance(meta_out, dict):
            meta_out['xml_path'] = xml_target
        out_payload = {'full_preview': preview, 'metadata': meta_out}
        ok, err = backend._update_plan_preview_in_xml(xml_target, scenario_label or scenario_norm, out_payload)
        if not ok:
            return {'ok': False, 'error': f'Failed to persist flow-modified preview plan: {err}'}
        try:
            backend._update_flow_state_in_xml(xml_target, scenario_label or scenario_norm, flow_meta)
        except Exception:
            pass
        out_path = xml_target
        try:
            backend._planner_set_plan(scenario_norm, plan_path=xml_target, xml_path=xml_target, seed=(meta_out or {}).get('seed'))
        except Exception:
            pass
        return {'ok': True, 'out_path': out_path, 'meta': meta_out}
    except Exception as exc:
        return {'ok': False, 'error': f'Failed to persist flow-modified preview plan: {exc}'}


def build_host_ip_map(host_by_id: dict[str, Any], *, preview_host_ip4: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for host_id, host in (host_by_id or {}).items():
            ip_val = preview_host_ip4(host) if isinstance(host, dict) else ''
            if ip_val:
                out[str(host_id)] = ip_val
    except Exception:
        return {}
    return out


def collect_realized_flags(flag_assignments: list[Any]) -> list[str]:
    realized_flags: list[str] = []
    try:
        for assignment in (flag_assignments or []):
            if not isinstance(assignment, dict):
                continue
            resolved_outputs = assignment.get('resolved_outputs') if isinstance(assignment.get('resolved_outputs'), dict) else {}
            flag_val = None
            if isinstance(resolved_outputs, dict):
                flag_val = resolved_outputs.get('Flag(flag_id)') or resolved_outputs.get('flag')
            if not flag_val:
                flag_val = assignment.get('flag_value')
            if isinstance(flag_val, str) and flag_val.strip():
                realized_flags.append(flag_val.strip())
    except Exception:
        return []
    return realized_flags


def cleanup_generated_run_dirs(
    *,
    cleanup_generated_artifacts: bool,
    created_run_dirs: list[str],
    failed_run_dirs: list[str],
) -> list[str]:
    if not cleanup_generated_artifacts:
        return []
    try:
        cleanup_deleted_run_dirs: list[str] = []
        cleanup_targets = [
            str(path or '').strip()
            for path in ((created_run_dirs or []) + (failed_run_dirs or []))
            if str(path or '').strip()
        ]
        seen_cleanup: set[str] = set()
        for path in cleanup_targets:
            if path in seen_cleanup:
                continue
            seen_cleanup.add(path)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                if not os.path.exists(path):
                    cleanup_deleted_run_dirs.append(path)
            except Exception:
                continue
        return cleanup_deleted_run_dirs
    except Exception:
        return []


def build_prepare_preview_success_payload(
    *,
    scenario_label: str,
    scenario_norm: str,
    length: int,
    requested_length: int,
    stats: dict[str, Any],
    chain_nodes: list[Any],
    flag_assignments_out: list[Any],
    flags_enabled: bool,
    flow_valid: bool,
    flow_errors: list[Any],
    flow_errors_detail: Any,
    host_ip_map: dict[str, str],
    meta: dict[str, Any] | None,
    base_plan_path: str,
    out_path: str,
    best_effort: bool,
    elapsed_s: float,
    generator_runs: list[Any],
    progress_log: list[Any],
    generation_failures: list[Any],
    generation_skipped: list[Any],
    created_run_dirs: list[Any],
    failed_run_dirs: list[Any],
    cleanup_generated_artifacts: bool,
    cleanup_deleted_run_dirs: list[str],
    debug_dag: bool,
    dag_debug: Any,
    warning: str | None,
    backend: Any,
) -> dict[str, Any]:
    payload = {
        'ok': True,
        'scenario': scenario_label or scenario_norm,
        'length': length,
        'requested_length': requested_length,
        'stats': stats,
        'chain': [
            {
                'id': str(node.get('id') or ''),
                'name': str(node.get('name') or ''),
                'type': str(node.get('type') or ''),
                'is_vuln': bool(node.get('is_vuln')),
                'ip4': str(node.get('ip4') or ''),
                'ipv4': str(node.get('ipv4') or ''),
                'interfaces': list(node.get('interfaces') or []) if isinstance(node.get('interfaces'), list) else [],
            }
            for node in chain_nodes
        ],
        'flag_assignments': flag_assignments_out,
        'flags_enabled': bool(flags_enabled),
        'flow_valid': bool(flow_valid),
        'flow_errors': list(flow_errors or []),
        'xml_path': (
            backend._abs_path_or_original(
                (meta or {}).get('xml_path') or '',
                base_dir=os.path.dirname(backend._abs_path_or_original(base_plan_path)) if base_plan_path else None,
            )
            or backend._abs_path_or_original(base_plan_path)
        ),
        'preview_plan_path': backend._abs_path_or_original(out_path),
        'base_preview_plan_path': backend._abs_path_or_original(base_plan_path),
        'best_effort': bool(best_effort),
        'elapsed_s': round(float(elapsed_s), 3),
        'generator_runs': generator_runs,
        'progress_log': progress_log,
        'generation_failures': generation_failures,
        'generation_skipped': generation_skipped,
        'created_run_dirs': created_run_dirs,
        'failed_run_dirs': failed_run_dirs,
        'cleanup_generated_artifacts': bool(cleanup_generated_artifacts),
        'cleanup_deleted_run_dirs': cleanup_deleted_run_dirs,
    }
    if flow_errors_detail:
        payload['flow_errors_detail'] = flow_errors_detail
    if host_ip_map:
        payload['host_ip_map'] = host_ip_map
    if debug_dag:
        payload['sequencer_dag'] = dag_debug or {'ok': False, 'errors': ['not computed (explicit chain)']}
    if warning:
        payload['warning'] = warning
    return payload
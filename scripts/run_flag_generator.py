#!/usr/bin/env python

import argparse
import json
import os
import sys
import subprocess
import time
import shutil
from pathlib import Path
from typing import Any


def repo_root_from_here() -> Path:
    return Path(__file__).resolve().parents[1]


def _docker_use_sudo() -> bool:
    flag = str(os.getenv('CORETG_DOCKER_USE_SUDO') or '').strip().lower()
    return flag in ('1', 'true', 'yes', 'y', 'on')


def _docker_sudo_password() -> str | None:
    pw = os.getenv('CORETG_DOCKER_SUDO_PASSWORD')
    if pw is None:
        return None
    pw = str(pw).rstrip('\n')
    return pw if pw else None


def _wrap_docker_cmd(cmd: list[str]) -> tuple[list[str], str | None]:
    if not cmd or cmd[0] != 'docker':
        return cmd, None
    use_sudo = _docker_use_sudo() or (_docker_sudo_password() is not None)
    if not use_sudo:
        return cmd, None
    pw = _docker_sudo_password()
    if pw is None:
        return ['sudo', '-E'] + cmd, None
    return ['sudo', '-E', '-S'] + cmd, (pw + '\n')


def _norm_inject_path(raw: str) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    s = s.replace('\\', '/')
    while s.startswith('./'):
        s = s[2:]
    while s.startswith('/'):
        s = s[1:]
    if s.startswith('flow_artifacts/'):
        s = s[len('flow_artifacts/'):]
    if s.startswith('artifacts/'):
        s = s[len('artifacts/'):]
    while s.startswith('./'):
        s = s[2:]
    s = s.strip('/')
    if not s:
        return ""
    # Reject path traversal attempts.
    try:
        parts = [p for p in s.split('/') if p]
        if any(p == '..' for p in parts):
            return ""
    except Exception:
        return ""
    return s


def _split_inject_spec(raw: str) -> tuple[str, str]:
    """Return (source, dest_dir) from an inject spec.

    Supported formats:
      - "path/to/file"
      - "path/to/file -> /dest/dir"
      - "path/to/file => /dest/dir"
    """
    text = str(raw or '').strip()
    if not text:
        return '', ''
    for sep in ('->', '=>'):
        if sep in text:
            left, right = text.split(sep, 1)
            return left.strip(), right.strip()
    return text, ''


def _normalize_inject_dest_dir(raw: str) -> str:
    """Normalize destination directory; fall back to /tmp on failure."""
    s = str(raw or '').strip()
    if not s:
        return '/tmp'
    if not s.startswith('/'):
        return '/tmp'
    parts = [p for p in s.split('/') if p]
    if any(p == '..' for p in parts):
        return '/tmp'
    return '/' + '/'.join(parts) if parts else '/tmp'


def _copy_tree_or_file(src: Path, dest: Path) -> None:
    if src.is_dir():
        shutil.copytree(src, dest, dirs_exist_ok=True)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def _stage_injected_dir(out_dir: Path, inject_files: list[str]) -> Path | None:
    """Create/refresh out_dir/injected with only allowlisted paths.

    Paths are treated as relative to the injected root. We accept a few common
    prefixes (artifacts/, /flow_artifacts/) and strip them.
    """
    cleaned = []
    for raw in inject_files or []:
        src_raw, _dest = _split_inject_spec(str(raw))
        p = _norm_inject_path(str(src_raw))
        if p:
            cleaned.append(p)
    cleaned = sorted(set(cleaned))
    if not cleaned:
        return None

    injected_dir = (out_dir / 'injected').resolve()
    injected_dir.mkdir(parents=True, exist_ok=True)

    # Rebuild injected dir from scratch to guarantee no extra files remain.
    for child in injected_dir.iterdir():
        try:
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        except Exception:
            pass

    artifacts_dir = (out_dir / 'artifacts').resolve()

    missing: list[str] = []
    for rel in cleaned:
        dest = (injected_dir / rel).resolve()
        try:
            src1 = (artifacts_dir / rel).resolve()
            src2 = (out_dir / rel).resolve()
            src = None
            if src1.exists():
                src = src1
            elif src2.exists():
                src = src2
            if src is None:
                missing.append(rel)
                continue
            _copy_tree_or_file(src, dest)
        except Exception:
            missing.append(rel)

    if missing:
        missing_set = set(missing)
        # hint.txt is commonly materialized after generator execution (e.g., by Flow)
        # and may not exist at staging time.
        if missing_set != {'hint.txt'}:
            print(f"[inject_files] warning: missing {len(missing)} paths: {missing[:8]}{'...' if len(missing) > 8 else ''}")
    return injected_dir


def _rewrite_compose_injected_to_volume_copy(
    out_dir: Path,
    compose_path: Path,
    inject_files: list[str],
) -> Path | None:
    """Rewrite relative binds to named volumes and add an init-copy service.

    The init service copies allowlisted injected files into per-destination
    volumes. Services then mount those volumes at destination directories.
    """
    try:
        import yaml  # type: ignore
    except Exception:
        print('[inject_files] warning: PyYAML unavailable; cannot rewrite docker-compose.yml')
        return None

    try:
        obj = yaml.safe_load(compose_path.read_text('utf-8', errors='ignore')) or {}
    except Exception as exc:
        print(f"[inject_files] warning: failed to parse compose yaml: {exc}")
        return None

    services = obj.get('services') if isinstance(obj, dict) else None
    if not isinstance(services, dict):
        return None

    # Build inject mapping: normalized source -> dest_dir (default /tmp).
    inject_map: dict[str, str] = {}
    for raw in inject_files or []:
        src_raw, dest_raw = _split_inject_spec(str(raw))
        src_norm = _norm_inject_path(src_raw)
        if not src_norm:
            continue
        dest_dir = _normalize_inject_dest_dir(dest_raw)
        inject_map[src_norm] = dest_dir

    if not inject_map:
        return None

    def _is_relative_bind_src(src: str) -> bool:
        s = (src or '').strip()
        if not s:
            return False
        if s.startswith('/'):
            return False
        # named volume: no slashes, no dot prefix
        if '/' not in s and not s.startswith('.'):
            return False
        return True

    def _volume_name_for_dest(dest_dir: str) -> str:
        slug = dest_dir.strip('/') or 'tmp'
        slug = ''.join([c if c.isalnum() else '-' for c in slug])
        while '--' in slug:
            slug = slug.replace('--', '-')
        slug = slug.strip('-') or 'tmp'
        return f"inject-{slug}"[:50]

    dest_to_volume: dict[str, str] = {}
    used_services: set[str] = set()

    for _svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        vols = svc.get('volumes')
        if not vols:
            continue
        if not isinstance(vols, list):
            vols = [vols]
        new_vols: list[Any] = []
        for v in vols:
            if isinstance(v, str):
                text = v.strip()
                if not text:
                    new_vols.append(v)
                    continue
                parts = text.split(':')
                if len(parts) < 2:
                    new_vols.append(v)
                    continue
                src = parts[0]
                if _is_relative_bind_src(src):
                    src_norm = src
                    while src_norm.startswith('./'):
                        src_norm = src_norm[2:]
                    src_norm = _norm_inject_path(src_norm)
                    dest_dir = inject_map.get(src_norm) or '/tmp'
                    dest_dir = _normalize_inject_dest_dir(dest_dir)
                    vol_name = dest_to_volume.setdefault(dest_dir, _volume_name_for_dest(dest_dir))
                    parts[0] = vol_name
                    parts[1] = dest_dir
                    new_vols.append(':'.join(parts[:3]))
                    used_services.add(_svc_name)
                else:
                    new_vols.append(v)
                continue
            if isinstance(v, dict):
                # long syntax
                typ = str(v.get('type') or '').strip().lower()
                src = v.get('source')
                if (typ in ('', 'bind')) and isinstance(src, str) and _is_relative_bind_src(src):
                    src_norm = src
                    while src_norm.startswith('./'):
                        src_norm = src_norm[2:]
                    src_norm = _norm_inject_path(src_norm)
                    dest_dir = inject_map.get(src_norm) or '/tmp'
                    dest_dir = _normalize_inject_dest_dir(dest_dir)
                    vol_name = dest_to_volume.setdefault(dest_dir, _volume_name_for_dest(dest_dir))
                    v2 = dict(v)
                    v2['type'] = 'volume'
                    v2['source'] = vol_name
                    v2['target'] = dest_dir
                    v2.pop('bind', None)
                    new_vols.append(v2)
                    used_services.add(_svc_name)
                else:
                    new_vols.append(v)
                continue
            new_vols.append(v)
        svc['volumes'] = new_vols

    if not dest_to_volume:
        return None

    # Add init-copy service to populate volumes.
    copy_service_name = 'inject_copy'
    if copy_service_name in services:
        i = 2
        while f"inject_copy_{i}" in services:
            i += 1
        copy_service_name = f"inject_copy_{i}"

    copy_vols: list[Any] = []
    copy_vols.append('./injected:/src:ro')
    dest_mounts: dict[str, str] = {}
    for dest_dir, vol_name in dest_to_volume.items():
        slug = vol_name.replace('inject-', '')
        mount_path = f"/dst/{slug}"
        dest_mounts[dest_dir] = mount_path
        copy_vols.append(f"{vol_name}:{mount_path}")

    cmds: list[str] = []
    for raw in inject_files or []:
        src_raw, dest_raw = _split_inject_spec(str(raw))
        src_norm = _norm_inject_path(src_raw)
        if not src_norm:
            continue
        dest_dir = _normalize_inject_dest_dir(dest_raw)
        mount_path = dest_mounts.get(dest_dir)
        if not mount_path:
            continue
        rel_dir = os.path.dirname(src_norm)
        rel_dir_escaped = rel_dir.replace('"', '\\"')
        src_escaped = src_norm.replace('"', '\\"')
        dst_escaped = src_norm.replace('"', '\\"')
        if rel_dir:
            cmds.append(f"mkdir -p \"{mount_path}/{rel_dir_escaped}\"")
        cmds.append(f"cp -a \"/src/{src_escaped}\" \"{mount_path}/{dst_escaped}\" || true")

    if not cmds:
        return None

    services[copy_service_name] = {
        'image': 'alpine:3.19',
        'volumes': copy_vols,
        'command': ['sh', '-lc', ' && '.join(cmds)],
    }

    for svc_name in used_services:
        svc = services.get(svc_name)
        if not isinstance(svc, dict):
            continue
        dep = svc.get('depends_on')
        if isinstance(dep, dict):
            dep.setdefault(copy_service_name, {'condition': 'service_completed_successfully'})
            svc['depends_on'] = dep
        elif isinstance(dep, list):
            if copy_service_name not in dep:
                dep.append(copy_service_name)
            svc['depends_on'] = dep
        else:
            svc['depends_on'] = {copy_service_name: {'condition': 'service_completed_successfully'}}

    top_vols = obj.get('volumes')
    if not isinstance(top_vols, dict):
        top_vols = {}
    for vol_name in dest_to_volume.values():
        top_vols.setdefault(vol_name, {})
    obj['volumes'] = top_vols

    try:
        compose_path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding='utf-8')
        return compose_path
    except Exception as exc:
        try:
            alt_path = compose_path.with_name(f"{compose_path.stem}.inject{compose_path.suffix}")
            alt_path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding='utf-8')
            print(
                f"[inject_files] warning: failed to write rewritten compose to {compose_path}: {exc}; "
                f"wrote {alt_path} instead"
            )
            return alt_path
        except Exception as exc2:
            print(f"[inject_files] warning: failed to write rewritten compose: {exc}; {exc2}")
            return None


def _rewrite_compose_host_network(compose_path: Path) -> None:
    """Force docker-compose services/builds to use host networking."""
    try:
        import yaml  # type: ignore
    except Exception:
        print('[compose] warning: PyYAML unavailable; cannot rewrite docker-compose.yml for host network')
        return

    try:
        obj = yaml.safe_load(compose_path.read_text('utf-8', errors='ignore')) or {}
    except Exception as exc:
        print(f"[compose] warning: failed to parse compose yaml for host network: {exc}")
        return

    services = obj.get('services') if isinstance(obj, dict) else None
    if not isinstance(services, dict):
        return

    for _svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        svc['network_mode'] = 'host'
        svc.pop('networks', None)
        build = svc.get('build')
        if isinstance(build, dict):
            build = dict(build)
            build.setdefault('network', 'host')
            svc['build'] = build
        elif isinstance(build, str):
            svc['build'] = {'context': build, 'network': 'host'}

    try:
        compose_path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding='utf-8')
    except Exception as exc:
        print(f"[compose] warning: failed to write host-network compose: {exc}")


def find_generator(repo_root: Path, kind: str, generator_id: str) -> tuple[dict[str, Any], Path]:
    # When executed as a script (python scripts/run_flag_generator.py), Python
    # adds only the scripts/ directory to sys.path. Ensure the repo root is on
    # sys.path so imports like `core_topo_gen.*` work without requiring an
    # installed package.
    try:
        rr = Path(repo_root).resolve()
        rr_s = str(rr)
        if rr_s and rr_s not in sys.path:
            sys.path.insert(0, rr_s)
    except Exception:
        pass

    # Strict: per-generator YAML manifests (repo + installed generator packs)
    try:
        from core_topo_gen.generator_manifests import discover_generator_manifests

        gens, _plugins_by_id, errs = discover_generator_manifests(repo_root=repo_root, kind=kind)
        if errs:
            # Keep this noisy but non-fatal; generator lookup can still succeed.
            print(f"[manifest] warnings: {len(errs)}")
        for g in gens:
            if str(g.get('id') or '') == generator_id:
                # Return the generator view dict and the manifest path as a hint.
                return g, Path(str(g.get('_source_path') or ''))
    except Exception as exc:
        print(f"[manifest] failed to load manifests: {exc}")

    raise SystemExit(f"Generator not found: {generator_id}")


def substitute_vars(value: Any, mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        out = value
        for k, v in mapping.items():
            out = out.replace("${" + k + "}", v)
        return out
    if isinstance(value, list):
        return [substitute_vars(x, mapping) for x in value]
    if isinstance(value, dict):
        return {k: substitute_vars(v, mapping) for k, v in value.items()}
    return value


def expand_inject_files(inject_files: list[str], env: dict[str, str]) -> list[str]:
    """Expand ${VARNAME} placeholders in inject_files using env.

    This allows generator catalogs to declare injected file allowlists that
    depend on runtime inputs (e.g., ${CHALLENGE} for per-node filenames).
    """
    out: list[str] = []
    for raw in inject_files or []:
        src_raw, dest_raw = _split_inject_spec(str(raw))
        try:
            expanded_src = substitute_vars(src_raw, env)
        except Exception:
            expanded_src = src_raw
        try:
            expanded_dest = substitute_vars(dest_raw, env)
        except Exception:
            expanded_dest = dest_raw

        def _emit(src_val: str) -> None:
            s = str(src_val or '').strip()
            if not s:
                return
            if expanded_dest:
                out.append(f"{s} -> {str(expanded_dest).strip()}")
            else:
                out.append(s)

        if isinstance(expanded_src, list):
            for x in expanded_src:
                _emit(str(x))
            continue
        _emit(str(expanded_src))
    return out


def expand_inject_files_from_outputs(out_dir: Path, inject_files: list[str]) -> list[str]:
    """Expand inject_files entries that reference output artifact keys.

    If an inject_files entry matches a key in outputs.json (doc['outputs']), we
    expand it to the corresponding output value(s) when they look like paths.

    Example:
        inject_files: ['File(path)']
        outputs.json: {"outputs": {"File(path)": "artifacts/challenge"}}
        -> expanded inject_files includes 'artifacts/challenge'
    """
    manifest = (out_dir / 'outputs.json').resolve()
    if not manifest.exists():
        return list(inject_files or [])

    try:
        doc = json.loads(manifest.read_text('utf-8', errors='ignore'))
    except Exception:
        return list(inject_files or [])

    outputs = doc.get('outputs') if isinstance(doc, dict) else None
    if not isinstance(outputs, dict):
        return list(inject_files or [])

    def _looks_like_path(s: str) -> bool:
        # Heuristic: treat slash-containing values as paths.
        return '/' in (s or '')

    out: list[str] = []
    for raw in inject_files or []:
        src_raw, dest_raw = _split_inject_spec(str(raw))
        key = str(src_raw or '').strip()
        if not key:
            continue
        if key in outputs:
            v = outputs.get(key)
            if isinstance(v, str):
                vv = v.strip()
                if vv and _looks_like_path(vv):
                    if dest_raw:
                        out.append(f"{vv} -> {dest_raw}")
                    else:
                        out.append(vv)
                    continue
            if isinstance(v, list):
                vals: list[str] = []
                for item in v:
                    s = str(item or '').strip()
                    if s and _looks_like_path(s):
                        vals.append(s)
                if vals:
                    if dest_raw:
                        out.extend([f"{vv} -> {dest_raw}" for vv in vals])
                    else:
                        out.extend(vals)
                    continue
            # If the output value doesn't look like a path, fall through and
            # treat the entry as a literal path.
        if dest_raw:
            out.append(f"{key} -> {dest_raw}")
        else:
            out.append(key)
    return out


def run_cmd(cmd: list[str], workdir: Path, env: dict[str, str]) -> None:
    wrapped_cmd, stdin_data = _wrap_docker_cmd(cmd)
    p = subprocess.run(
        wrapped_cmd,
        cwd=str(workdir),
        env={**os.environ, **env},
        check=False,
        text=True,
        capture_output=True,
        input=stdin_data,
    )
    out = (p.stdout or '').strip()
    err = (p.stderr or '').strip()
    if out:
        print(out)
    if err:
        print(err)
    if p.returncode != 0:
        if out:
            print(f"[cmd] stdout: {out[-1200:]}")
        if err:
            print(f"[cmd] stderr: {err[-1200:]}")
        raise subprocess.CalledProcessError(p.returncode, wrapped_cmd, output=p.stdout, stderr=p.stderr)


def run_cmd_capture(cmd: list[str], workdir: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    wrapped_cmd, stdin_data = _wrap_docker_cmd(cmd)
    return subprocess.run(
        wrapped_cmd,
        cwd=str(workdir),
        env={**os.environ, **env},
        check=False,
        capture_output=True,
        text=True,
        input=stdin_data,
    )


def slugify(value: str) -> str:
    out = []
    for ch in value.lower():
        if ch.isalnum():
            out.append(ch)
        else:
            out.append("-")
    s = "".join(out)
    while "--" in s:
        s = s.replace("--", "-")
    return s.strip("-") or "fg"


def run_compose(
    source_dir: Path,
    compose_file: str,
    service: str,
    inputs_dir: Path,
    outputs_dir: Path,
    env: dict[str, str],
) -> None:
    project = f"fg_{slugify(source_dir.name)}_{os.getpid()}_{int(time.time())}"
    compose_path = (source_dir / compose_file).resolve()
    if not compose_path.exists():
        raise SystemExit(f"compose file not found: {compose_path}")

    compose_env = {
        **env,
        "INPUTS_DIR": str(inputs_dir.resolve()),
        "OUTPUTS_DIR": str(outputs_dir.resolve()),
    }

    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "-p",
        project,
        "run",
        "--rm",
    ]
    for k, v in env.items():
        cmd.extend(["-e", f"{k}={v}"])
    cmd.append(service)

    try:
        run_cmd(cmd, source_dir, compose_env)
    finally:
        # `docker compose run --rm` removes the container, but it does not remove
        # the project's network, and it won't remove any images built locally.
        # Since each run uses a fresh project name, we must tear down explicitly
        # to avoid exhausting Docker's default address pools.
        down_cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_path),
            "-p",
            project,
            "down",
            "--remove-orphans",
            "--rmi",
            "local",
        ]
        print(f"[cleanup] compose project={project}")
        print(f"[cleanup] running: {' '.join(down_cmd)}")
        try:
            p = run_cmd_capture(down_cmd, source_dir, compose_env)
            print(f"[cleanup] compose down rc={p.returncode}")
            if p.returncode != 0:
                err = (p.stderr or "").strip()
                if err:
                    print(f"[cleanup] compose down stderr: {err[-800:]}")
        except Exception as e:
            print(f"[cleanup] compose down failed: {e}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a generator from manifest-based generator packs.")
    ap.add_argument("--generator-id", required=True)
    ap.add_argument(
        "--kind",
        default="flag-generator",
        help="Generator kind: flag-generator or flag-node-generator (default: flag-generator)",
    )
    ap.add_argument("--out-dir", default="/tmp/flag_generator_out")
    ap.add_argument("--config", default="{}", help="JSON object of inputs")
    ap.add_argument("--repo-root", default="", help="Path to repo root (optional)")
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve() if args.repo_root else repo_root_from_here()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    inputs_dir = out_dir / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)

    try:
        config = json.loads(args.config)
    except Exception as e:
        raise SystemExit(f"Invalid --config JSON: {e}")
    if not isinstance(config, dict):
        raise SystemExit("--config must be a JSON object")

    gen, _src_path = find_generator(repo_root, str(args.kind or "flag-generator"), args.generator_id)
    inject_files = gen.get('inject_files')
    if not isinstance(inject_files, list):
        inject_files = []
    # Optional override from environment (e.g., Flow inject overrides).
    try:
        raw_override = os.environ.get('CORETG_INJECT_FILES_JSON')
        if raw_override:
            parsed = json.loads(raw_override)
            if isinstance(parsed, list):
                inject_files = [str(x) for x in parsed if str(x).strip()]
    except Exception:
        pass
    source = gen.get("source") or {}
    src_path = source.get("path") or ""
    source_dir = (repo_root / src_path).resolve() if not Path(src_path).is_absolute() else Path(src_path).resolve()

    mapping = {
        "source.path": str(source_dir),
        "out_dir": str(out_dir),
    }

    # Write inputs config (mounted into compose at /inputs/config.json)
    config_path = inputs_dir / "config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    # Env: pass OUT_DIR and also config keys uppercased
    env = {"OUT_DIR": str(out_dir), "CONFIG_PATH": str(config_path)}
    for k, v in config.items():
        raw_key = str(k).upper()
        key = "".join([c if c.isalnum() else "_" for c in raw_key])
        if key and not (key[0].isalpha() or key[0] == "_"):
            key = f"VAR_{key}"
        if key:
            env[key] = str(v)

    # Allow generator definitions to include fixed env values.
    gen_env = gen.get("env")
    if isinstance(gen_env, dict):
        for k, v in gen_env.items():
            try:
                kk = str(k)
                if not kk:
                    continue
                env.setdefault(kk, str(v))
            except Exception:
                continue

    # Needed for compose generators that mount the repo.
    env.setdefault("REPO_ROOT", str(repo_root))

    # Prefer compose execution when present
    compose = gen.get("compose")
    if isinstance(compose, dict):
        compose_file = str(compose.get("file") or "docker-compose.yml")
        service = str(compose.get("service") or "generator")

        # Optional: force host networking (useful when docker bridge is disabled).
        try:
            use_host_network = str(os.getenv('CORETG_DOCKER_HOST_NETWORK') or '').strip().lower() in (
                '1', 'true', 'yes', 'y', 'on'
            )
        except Exception:
            use_host_network = False
        if use_host_network:
            try:
                compose_src = (source_dir / compose_file).resolve() if not Path(compose_file).is_absolute() else Path(compose_file).resolve()
                compose_out = compose_src.parent / f"{compose_src.stem}.hostnet{compose_src.suffix}"
                compose_out.write_text(compose_src.read_text('utf-8', errors='ignore'), encoding='utf-8')
                _rewrite_compose_host_network(compose_out)
                compose_file = str(compose_out)
            except Exception as exc:
                print(f"[compose] warning: host-network rewrite failed: {exc}")

        run_compose(
            source_dir=source_dir,
            compose_file=compose_file,
            service=service,
            inputs_dir=inputs_dir,
            outputs_dir=out_dir,
            env={
                **env,
                # inside container, OUT_DIR should resolve to /outputs; leave host OUT_DIR too
                "OUT_DIR": "/outputs",
                "CONFIG_PATH": "/inputs/config.json",
            },
        )

        # If this generator declares inject_files, stage and enforce that only
        # staged files can be mounted into the generated compose container.
        expanded_inject = expand_inject_files([str(x) for x in inject_files if x is not None], env)
        expanded_inject = expand_inject_files_from_outputs(out_dir, expanded_inject)
        injected_dir = _stage_injected_dir(out_dir, expanded_inject)
        if injected_dir is not None:
            compose_out = out_dir / 'docker-compose.yml'
            if compose_out.exists():
                rewritten_path = _rewrite_compose_injected_to_volume_copy(out_dir, compose_out, expanded_inject)
                if rewritten_path and rewritten_path.name != compose_out.name:
                    try:
                        manifest = out_dir / "outputs.json"
                        if manifest.exists():
                            doc = json.loads(manifest.read_text("utf-8", errors="ignore") or "{}")
                            if isinstance(doc, dict):
                                outputs = doc.get("outputs")
                                if isinstance(outputs, dict):
                                    for key in ("File(path)", "File", "file", "path"):
                                        val = outputs.get(key)
                                        if isinstance(val, str) and val.strip() == compose_out.name:
                                            outputs[key] = rewritten_path.name
                                manifest.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
                    except Exception:
                        pass

        manifest = out_dir / "outputs.json"
        if manifest.exists():
            print(manifest.read_text("utf-8"))
        else:
            print(f"No outputs.json found at {manifest}")
        return 0

    build = gen.get("build")
    if isinstance(build, dict) and isinstance(build.get("cmd"), list):
        cmd = substitute_vars(build.get("cmd"), mapping)
        workdir = substitute_vars(build.get("workdir", "${source.path}"), mapping)
        run_cmd([str(x) for x in cmd], Path(str(workdir)), env)

    run = gen.get("run")
    if isinstance(run, dict) and isinstance(run.get("cmd"), list):
        cmd = substitute_vars(run.get("cmd"), mapping)
        workdir = substitute_vars(run.get("workdir", "${source.path}"), mapping)
        run_cmd([str(x) for x in cmd], Path(str(workdir)), env)

    expanded_inject = expand_inject_files([str(x) for x in inject_files if x is not None], env)
    expanded_inject = expand_inject_files_from_outputs(out_dir, expanded_inject)
    injected_dir = _stage_injected_dir(out_dir, expanded_inject)
    if injected_dir is not None:
        compose_out = out_dir / 'docker-compose.yml'
        if compose_out.exists():
            rewritten_path = _rewrite_compose_injected_to_volume_copy(out_dir, compose_out, expanded_inject)
            if rewritten_path and rewritten_path.name != compose_out.name:
                try:
                    manifest = out_dir / "outputs.json"
                    if manifest.exists():
                        doc = json.loads(manifest.read_text("utf-8", errors="ignore") or "{}")
                        if isinstance(doc, dict):
                            outputs = doc.get("outputs")
                            if isinstance(outputs, dict):
                                for key in ("File(path)", "File", "file", "path"):
                                    val = outputs.get(key)
                                    if isinstance(val, str) and val.strip() == compose_out.name:
                                        outputs[key] = rewritten_path.name
                            manifest.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
                except Exception:
                    pass

    # Print manifest if present
    manifest = out_dir / "outputs.json"
    if manifest.exists():
        print(manifest.read_text("utf-8"))
    else:
        print(f"No outputs.json found at {manifest}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

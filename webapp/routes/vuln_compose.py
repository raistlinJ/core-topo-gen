from __future__ import annotations

import os
import shutil
import subprocess
from typing import Callable

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    vuln_base_dir: Callable[[], str],
    safe_name: Callable[[str], str],
    parse_github_url: Callable[[str], dict],
    vuln_repo_subdir: Callable[[], str],
    compose_candidates: Callable[[str], list[str]],
    get_repo_root: Callable[[], str],
) -> None:
    if not begin_route_registration(app, 'vuln_compose_routes'):
        return

    def _vuln_resolve_local_path(path_raw: str) -> str | None:
        """Resolve a local vuln compose path (file or directory) under the repo root."""
        try:
            path_value = str(path_raw or '').strip()
            if not path_value:
                return None
            abs_path = os.path.abspath(os.path.expanduser(path_value))
            if not os.path.exists(abs_path):
                return None
            repo_root = os.path.abspath(get_repo_root())
            try:
                if os.path.commonpath([repo_root, abs_path]) != repo_root:
                    return None
            except Exception:
                return None
            return abs_path
        except Exception:
            return None

    def _status_view():
        try:
            data = request.get_json(silent=True) or {}
            items = data.get('items') or []
            out = []
            logs: list[str] = []
            base_out = os.path.abspath(vuln_base_dir())
            os.makedirs(base_out, exist_ok=True)
            for it in items:
                name = (it.get('Name') or '').strip()
                path = (it.get('Path') or '').strip()
                compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
                safe = safe_name(name or 'vuln')
                vdir = os.path.join(base_out, safe)
                base_dir = vdir
                compose_file = None
                exists = False

                local = _vuln_resolve_local_path(path)
                if local:
                    if os.path.isdir(local):
                        base_dir = local
                        preferred = os.path.join(base_dir, compose_name)
                        if os.path.exists(preferred):
                            compose_file = preferred
                        else:
                            cand = compose_candidates(base_dir)
                            compose_file = cand[0] if cand else None
                        exists = bool(compose_file and os.path.exists(compose_file))
                    else:
                        compose_file = local
                        base_dir = os.path.dirname(local)
                        exists = os.path.exists(compose_file)
                else:
                    gh = parse_github_url(path)
                    if gh.get('is_github'):
                        try:
                            logs.append(f"[status] {name}: Path={path}")
                            logs.append(f"[status] {name}: git_url={gh.get('git_url')} branch={gh.get('branch')} subpath={gh.get('subpath')} mode={gh.get('mode')}")
                        except Exception:
                            pass
                        repo_dir = os.path.join(vdir, vuln_repo_subdir())
                        sub = gh.get('subpath') or ''
                        is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                        if is_file_sub:
                            compose_file = os.path.join(repo_dir, sub)
                            base_dir = os.path.dirname(compose_file)
                            exists = os.path.exists(compose_file)
                        else:
                            base_dir = os.path.join(repo_dir, sub) if sub else repo_dir
                            exists = os.path.isdir(base_dir)
                            if exists and compose_name:
                                preferred = os.path.join(base_dir, compose_name)
                                if os.path.exists(preferred):
                                    compose_file = preferred
                            if not compose_file and exists:
                                cand = compose_candidates(base_dir)
                                compose_file = cand[0] if cand else None
                            exists = bool(compose_file and os.path.exists(compose_file)) if compose_file else bool(exists)
                        try:
                            logs.append(f"[status] {name}: base={base_dir} exists={exists} compose={compose_name}")
                        except Exception:
                            pass
                        try:
                            cands = compose_candidates(base_dir) if os.path.isdir(base_dir) else []
                            logs.append(f"[status] {name}: compose candidates={cands[:4]}")
                        except Exception:
                            pass
                    else:
                        compose_file = os.path.join(vdir, compose_name or 'docker-compose.yml')
                        base_dir = vdir
                        exists = os.path.exists(compose_file)
                        try:
                            logs.append(f"[status] {name}: non-github Path={path} compose_path={compose_file} exists={exists}")
                        except Exception:
                            pass
                pulled = False
                if exists and compose_file and shutil.which('docker'):
                    try:
                        proc = subprocess.run(['docker', 'compose', '-f', compose_file, 'config', '--images'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
                        try:
                            logs.append(f"[status] docker compose config --images rc={proc.returncode}")
                        except Exception:
                            pass
                        if proc.returncode == 0:
                            images = [ln.strip() for ln in (proc.stdout or '').splitlines() if ln.strip()]
                            try:
                                logs.append(f"[status] images discovered: {len(images)}")
                                logs.append(f"[status] images sample: {images[:4]}")
                            except Exception:
                                pass
                            if images:
                                present = []
                                for img in images:
                                    inspect_proc = subprocess.run(['docker', 'image', 'inspect', img], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                    try:
                                        logs.append(f"[status] image inspect {img} rc={inspect_proc.returncode}")
                                    except Exception:
                                        pass
                                    present.append(inspect_proc.returncode == 0)
                                pulled = all(present)
                    except Exception:
                        pulled = False
                out.append({'Name': name, 'Path': path, 'compose': compose_name, 'compose_path': compose_file, 'exists': bool(exists), 'pulled': bool(pulled), 'dir': base_dir})
            return jsonify({'items': out, 'log': logs})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    def _status_images_view():
        try:
            data = request.get_json(silent=True) or {}
            items = data.get('items') or []
            out: list[dict] = []
            base_out = os.path.abspath(vuln_base_dir())
            docker_ok = bool(shutil.which('docker'))
            try:
                import yaml  # type: ignore
            except Exception:  # pragma: no cover
                yaml = None  # type: ignore

            def _resolve_compose_path(name: str, path: str, compose_name: str) -> tuple[bool, str | None]:
                safe = safe_name(name or 'vuln')
                vdir = os.path.join(base_out, safe)
                compose_file: str | None = None
                exists = False

                local = _vuln_resolve_local_path(path)
                if local:
                    if os.path.isdir(local):
                        preferred = os.path.join(local, compose_name)
                        if os.path.exists(preferred):
                            compose_file = preferred
                        else:
                            cand = compose_candidates(local)
                            compose_file = cand[0] if cand else None
                        return bool(compose_file and os.path.exists(compose_file)), compose_file
                    return bool(os.path.exists(local)), local

                gh = parse_github_url(path)
                if gh.get('is_github'):
                    repo_dir = os.path.join(vdir, vuln_repo_subdir())
                    sub = gh.get('subpath') or ''
                    is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                    if is_file_sub:
                        compose_file = os.path.join(repo_dir, sub)
                        exists = os.path.exists(compose_file)
                    else:
                        base_dir = os.path.join(repo_dir, sub) if sub else repo_dir
                        exists = os.path.isdir(base_dir)
                        if exists:
                            preferred = os.path.join(base_dir, compose_name)
                            if os.path.exists(preferred):
                                compose_file = preferred
                            else:
                                cand = compose_candidates(base_dir)
                                compose_file = cand[0] if cand else None
                    return bool(exists and compose_file and os.path.exists(compose_file)), compose_file

                compose_file = os.path.join(vdir, compose_name)
                exists = os.path.exists(compose_file)
                return bool(exists), compose_file if exists else compose_file

            def _images_from_compose_yaml(compose_path: str) -> list[str]:
                if not yaml:
                    return []
                try:
                    with open(compose_path, 'r', encoding='utf-8', errors='ignore') as handle:
                        doc = yaml.safe_load(handle) or {}
                    if not isinstance(doc, dict):
                        return []
                    services = doc.get('services')
                    if not isinstance(services, dict):
                        return []
                    images: list[str] = []
                    for service in services.values():
                        if not isinstance(service, dict):
                            continue
                        image = service.get('image')
                        if isinstance(image, str) and image.strip():
                            images.append(image.strip())
                    seen: set[str] = set()
                    ordered: list[str] = []
                    for image in images:
                        if image in seen:
                            continue
                        seen.add(image)
                        ordered.append(image)
                    return ordered
                except Exception:
                    return []

            for it in items:
                name = (it.get('Name') or '').strip()
                path = (it.get('Path') or '').strip()
                compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
                exists, compose_path = _resolve_compose_path(name, path, compose_name)
                images: list[str] = []
                missing: list[str] = []
                pulled = False
                if exists and compose_path and docker_ok:
                    images = _images_from_compose_yaml(compose_path)
                    if not images:
                        try:
                            proc = subprocess.run(['docker', 'compose', '-f', compose_path, 'config', '--images'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
                            if proc.returncode == 0:
                                images = [ln.strip() for ln in (proc.stdout or '').splitlines() if ln.strip()]
                        except Exception:
                            images = []
                    if images:
                        for image in images:
                            try:
                                inspect_proc = subprocess.run(['docker', 'image', 'inspect', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                if inspect_proc.returncode != 0:
                                    missing.append(image)
                            except Exception:
                                missing.append(image)
                        pulled = len(missing) == 0
                    else:
                        pulled = True
                out.append({
                    'Name': name,
                    'Path': path,
                    'compose': compose_name,
                    'compose_path': compose_path,
                    'exists': bool(exists),
                    'pulled': bool(pulled),
                    'images': images,
                    'missing_images': missing,
                    'docker_available': docker_ok,
                })
            return jsonify({'items': out})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    def _download_view():
        try:
            try:
                from core_topo_gen.utils.vuln_process import _github_tree_to_raw as _to_raw
            except Exception:
                def _to_raw(base_url: str, filename: str) -> str | None:
                    try:
                        from urllib.parse import urlparse
                        url = urlparse(base_url)
                        if url.netloc.lower() != 'github.com':
                            return None
                        parts = [part for part in url.path.strip('/').split('/') if part]
                        if len(parts) < 4 or parts[2] != 'tree':
                            return None
                        owner, repo, _tree, branch = parts[:4]
                        rest = '/'.join(parts[4:])
                        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}/{filename}"
                    except Exception:
                        return None
            data = request.get_json(silent=True) or {}
            items = data.get('items') or []
            out = []
            logs: list[str] = []
            base_out = os.path.abspath(vuln_base_dir())
            os.makedirs(base_out, exist_ok=True)
            import shlex
            import urllib.request

            for it in items:
                name = (it.get('Name') or '').strip()
                path = (it.get('Path') or '').strip()
                compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
                safe = safe_name(name or 'vuln')
                vdir = os.path.join(base_out, safe)
                os.makedirs(vdir, exist_ok=True)

                local = _vuln_resolve_local_path(path)
                if local:
                    if os.path.isdir(local):
                        preferred = os.path.join(local, compose_name)
                        if os.path.exists(preferred):
                            out.append({'Name': name, 'Path': path, 'ok': True, 'dir': local, 'message': 'local compose directory'})
                        else:
                            out.append({'Name': name, 'Path': path, 'ok': False, 'dir': local, 'message': 'compose file missing in local directory'})
                    else:
                        out.append({'Name': name, 'Path': path, 'ok': True, 'dir': os.path.dirname(local), 'message': 'local compose file'})
                    continue

                gh = parse_github_url(path)
                if gh.get('is_github'):
                    if not shutil.which('git'):
                        try:
                            logs.append(f"[download] {name}: git not available in PATH")
                        except Exception:
                            pass
                        out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': 'git not available'})
                        continue
                    repo_dir = os.path.join(vdir, vuln_repo_subdir())
                    try:
                        logs.append(f"[download] {name}: Path={path}")
                        logs.append(f"[download] {name}: git_url={gh.get('git_url')} branch={gh.get('branch')} subpath={gh.get('subpath')} -> repo_dir={repo_dir}")
                    except Exception:
                        pass
                    if os.path.isdir(os.path.join(repo_dir, '.git')):
                        try:
                            logs.append(f"[download] {name}: repo exists {repo_dir}")
                        except Exception:
                            pass
                        base_dir = os.path.join(repo_dir, gh.get('subpath') or '') if gh.get('subpath') else repo_dir
                        try:
                            logs.append(f"[download] {name}: base_dir={base_dir}")
                            if os.path.isdir(base_dir):
                                entries = []
                                for nm in os.listdir(base_dir)[:10]:
                                    candidate = os.path.join(base_dir, nm)
                                    kind = 'dir' if os.path.isdir(candidate) else 'file'
                                    entries.append(f"{nm}({kind})")
                                logs.append(f"[download] {name}: base_dir entries: {entries}")
                        except Exception:
                            pass
                        out.append({'Name': name, 'Path': path, 'ok': True, 'dir': base_dir, 'message': 'already downloaded'})
                        continue
                    try:
                        if os.path.exists(repo_dir):
                            shutil.rmtree(repo_dir)
                    except Exception:
                        pass
                    cmd = ['git', 'clone', '--depth', '1']
                    if gh.get('branch'):
                        cmd += ['--branch', gh.get('branch')]
                    cmd += [gh.get('git_url'), repo_dir]
                    try:
                        try:
                            logs.append(f"[download] {name}: running: {' '.join(shlex.quote(part) for part in cmd)}")
                        except Exception:
                            pass
                        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
                        try:
                            logs.append(f"[download] git clone rc={proc.returncode} dir={repo_dir}")
                            if proc.stdout:
                                for line in proc.stdout.splitlines()[:100]:
                                    logs.append(f"[git] {line}")
                        except Exception:
                            pass
                        if proc.returncode == 0 and os.path.isdir(repo_dir):
                            base_dir = os.path.join(repo_dir, gh.get('subpath') or '') if gh.get('subpath') else repo_dir
                            try:
                                logs.append(f"[download] {name}: base_dir={base_dir}")
                                if os.path.isdir(base_dir):
                                    entries = []
                                    for nm in os.listdir(base_dir)[:10]:
                                        candidate = os.path.join(base_dir, nm)
                                        kind = 'dir' if os.path.isdir(candidate) else 'file'
                                        entries.append(f"{nm}({kind})")
                                    logs.append(f"[download] {name}: base_dir entries: {entries}")
                            except Exception:
                                pass
                            out.append({'Name': name, 'Path': path, 'ok': True, 'dir': base_dir, 'message': 'downloaded'})
                        else:
                            msg = (proc.stdout or '').strip()
                            out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': msg[-1000:] if msg else 'git clone failed'})
                    except Exception as exc:
                        out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': str(exc)})
                else:
                    raw = _to_raw(path, compose_name) or (path.rstrip('/') + '/' + compose_name)
                    yml_path = os.path.join(vdir, compose_name)
                    try:
                        try:
                            logs.append(f"[download] {name}: Path={path}")
                            logs.append(f"[download] {name}: GET {raw}")
                        except Exception:
                            pass
                        with urllib.request.urlopen(raw, timeout=30) as resp:
                            status = getattr(resp, 'status', None) or getattr(resp, 'code', None)
                            data_bin = resp.read(1_000_000)
                            try:
                                logs.append(f"[download] {name}: HTTP {status} bytes={len(data_bin) if data_bin else 0}")
                            except Exception:
                                pass
                        with open(yml_path, 'wb') as handle:
                            handle.write(data_bin)
                        out.append({'Name': name, 'Path': path, 'ok': True, 'dir': vdir, 'message': 'downloaded', 'compose': compose_name})
                    except Exception as exc:
                        out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': str(exc), 'compose': compose_name})
            return jsonify({'items': out, 'log': logs})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    def _pull_view():
        try:
            data = request.get_json(silent=True) or {}
            items = data.get('items') or []
            out = []
            logs: list[str] = []
            base_out = os.path.abspath(vuln_base_dir())
            for it in items:
                name = (it.get('Name') or '').strip()
                path = (it.get('Path') or '').strip()
                compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
                safe = safe_name(name or 'vuln')
                vdir = os.path.join(base_out, safe)

                local = _vuln_resolve_local_path(path)
                if local:
                    if os.path.isdir(local):
                        preferred = os.path.join(local, compose_name)
                        if os.path.exists(preferred):
                            yml_path = preferred
                        else:
                            cand = compose_candidates(local)
                            yml_path = cand[0] if cand else None
                    else:
                        yml_path = local
                else:
                    gh = parse_github_url(path)
                    if gh.get('is_github'):
                        repo_dir = os.path.join(vdir, vuln_repo_subdir())
                        sub = gh.get('subpath') or ''
                        is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                        base_dir = os.path.join(repo_dir, os.path.dirname(sub)) if is_file_sub else (os.path.join(repo_dir, sub) if sub else repo_dir)
                        try:
                            logs.append(f"[pull] {name}: git_url={gh.get('git_url')} branch={gh.get('branch')} subpath={gh.get('subpath')} base_dir={base_dir}")
                        except Exception:
                            pass
                        yml_path = os.path.join(repo_dir, sub) if is_file_sub else os.path.join(base_dir, compose_name)
                        if not os.path.exists(yml_path):
                            cand = compose_candidates(base_dir)
                            yml_path = cand[0] if cand else None
                        try:
                            logs.append(f"[pull] {name}: yml_path={yml_path}")
                        except Exception:
                            pass
                    else:
                        yml_path = os.path.join(vdir, compose_name)
                        try:
                            logs.append(f"[pull] {name}: non-github base_dir={vdir}")
                        except Exception:
                            pass
                if not yml_path or not os.path.exists(yml_path):
                    out.append({'Name': name, 'Path': path, 'ok': False, 'message': 'compose file missing', 'compose': compose_name})
                    continue
                if not shutil.which('docker'):
                    out.append({'Name': name, 'Path': path, 'ok': False, 'message': 'docker not available', 'compose': compose_name})
                    continue
                try:
                    proc = subprocess.run(['docker', 'compose', '-f', yml_path, 'pull'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    try:
                        logs.append(f"[pull] {name}: docker compose pull rc={proc.returncode} file={yml_path}")
                        if proc.stdout:
                            for line in proc.stdout.splitlines()[:200]:
                                logs.append(f"[docker] {line}")
                    except Exception:
                        pass
                    ok = proc.returncode == 0
                    msg = 'ok' if ok else ((proc.stdout or '')[-1000:] if proc.stdout else 'failed')
                    out.append({'Name': name, 'Path': path, 'ok': ok, 'message': msg, 'compose': compose_name})
                except Exception as exc:
                    out.append({'Name': name, 'Path': path, 'ok': False, 'message': str(exc), 'compose': compose_name})
            return jsonify({'items': out, 'log': logs})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    def _remove_view():
        try:
            data = request.get_json(silent=True) or {}
            items = data.get('items') or []
            out = []
            logs: list[str] = []
            base_out = os.path.abspath(vuln_base_dir())
            for it in items:
                name = (it.get('Name') or '').strip()
                path = (it.get('Path') or '').strip()
                compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
                safe = safe_name(name or 'vuln')
                vdir = os.path.join(base_out, safe)
                yml_path = None
                base_dir = vdir
                is_local = False
                try:
                    logs.append(f"[remove] {name}: Path={path}")
                except Exception:
                    pass

                local = _vuln_resolve_local_path(path)
                if local:
                    is_local = True
                    if os.path.isdir(local):
                        base_dir = local
                        preferred = os.path.join(base_dir, compose_name)
                        if os.path.exists(preferred):
                            yml_path = preferred
                        else:
                            cand = compose_candidates(base_dir)
                            yml_path = cand[0] if cand else None
                    else:
                        yml_path = local
                        base_dir = os.path.dirname(local)
                else:
                    gh = parse_github_url(path)
                    if gh.get('is_github'):
                        repo_dir = os.path.join(vdir, vuln_repo_subdir())
                        sub = gh.get('subpath') or ''
                        is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                        base_dir = os.path.join(repo_dir, os.path.dirname(sub)) if is_file_sub else (os.path.join(repo_dir, sub) if sub else repo_dir)
                        yml_path = os.path.join(repo_dir, sub) if is_file_sub else os.path.join(base_dir, compose_name)
                        if not os.path.exists(yml_path):
                            cand = compose_candidates(base_dir)
                            yml_path = cand[0] if cand else None
                    else:
                        yml_path = os.path.join(vdir, compose_name)
                if yml_path and os.path.exists(yml_path) and shutil.which('docker'):
                    try:
                        logs.append(f"[remove] {name}: docker compose down file={yml_path}")
                    except Exception:
                        pass
                    try:
                        proc = subprocess.run(['docker', 'compose', '-f', yml_path, 'down', '--volumes', '--remove-orphans', '--rmi', 'all'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        try:
                            logs.append(f"[remove] docker compose down rc={proc.returncode}")
                            if proc.stdout:
                                for line in proc.stdout.splitlines()[:200]:
                                    logs.append(f"[docker] {line}")
                        except Exception:
                            pass
                    except Exception as exc:
                        try:
                            logs.append(f"[remove] compose down error: {exc}")
                        except Exception:
                            pass
                    try:
                        proc2 = subprocess.run(['docker', 'compose', '-f', yml_path, 'config', '--images'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        if proc2.returncode == 0:
                            images = [ln.strip() for ln in (proc2.stdout or '').splitlines() if ln.strip()]
                            for image in images:
                                image_proc = subprocess.run(['docker', 'image', 'rm', '-f', image], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                                try:
                                    logs.append(f"[remove] image rm {image} rc={image_proc.returncode}")
                                except Exception:
                                    pass
                    except Exception:
                        pass
                try:
                    if is_local:
                        pass
                    else:
                        gh = parse_github_url(path)
                        if gh.get('is_github'):
                            repo_dir = os.path.join(vdir, vuln_repo_subdir())
                            if os.path.isdir(repo_dir):
                                shutil.rmtree(repo_dir, ignore_errors=True)
                                logs.append(f"[remove] {name}: deleted {repo_dir}")
                        else:
                            yml = os.path.join(vdir, compose_name)
                            if os.path.exists(yml):
                                try:
                                    os.remove(yml)
                                    logs.append(f"[remove] {name}: deleted {yml}")
                                except Exception:
                                    pass
                        try:
                            if os.path.isdir(vdir) and not os.listdir(vdir):
                                os.rmdir(vdir)
                                logs.append(f"[remove] {name}: cleaned empty {vdir}")
                        except Exception:
                            pass
                except Exception as exc:
                    try:
                        logs.append(f"[remove] cleanup error: {exc}")
                    except Exception:
                        pass
                out.append({'Name': name, 'Path': path, 'ok': True, 'message': 'removed', 'compose': compose_name})
            return jsonify({'items': out, 'log': logs})
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500

    app.add_url_rule('/vuln_compose/status', endpoint='vuln_compose_status', view_func=_status_view, methods=['POST'])
    app.add_url_rule('/vuln_compose/status_images', endpoint='vuln_compose_status_images', view_func=_status_images_view, methods=['POST'])
    app.add_url_rule('/vuln_compose/download', endpoint='vuln_compose_download', view_func=_download_view, methods=['POST'])
    app.add_url_rule('/vuln_compose/pull', endpoint='vuln_compose_pull', view_func=_pull_view, methods=['POST'])
    app.add_url_rule('/vuln_compose/remove', endpoint='vuln_compose_remove', view_func=_remove_view, methods=['POST'])
    mark_routes_registered(app, 'vuln_compose_routes')
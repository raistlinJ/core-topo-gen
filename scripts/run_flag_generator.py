#!/usr/bin/env python

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any


def repo_root_from_here() -> Path:
    return Path(__file__).resolve().parents[1]


def load_enabled_sources(repo_root: Path) -> list[dict[str, Any]]:
    # Support multiple generator catalogs that share the same schema.
    # Default remains "flag_generators" to preserve existing behavior.
    catalog = os.environ.get("FLAG_GENERATOR_CATALOG", "flag_generators").strip() or "flag_generators"
    state_path = repo_root / "data_sources" / catalog / "_state.json"
    if not state_path.exists():
        return []
    state = json.loads(state_path.read_text("utf-8"))
    sources = state.get("sources")
    if not isinstance(sources, list):
        return []
    out: list[dict[str, Any]] = []
    for s in sources:
        if isinstance(s, dict) and s.get("enabled"):
            out.append(s)
    return out


def load_generators_from_source(path: Path) -> list[dict[str, Any]]:
    doc = json.loads(path.read_text("utf-8"))
    if not isinstance(doc, dict):
        return []
    try:
        schema_version = int(doc.get("schema_version") or 0)
    except Exception:
        schema_version = 0
    if schema_version != 3:
        return []

    plugins = doc.get("plugins")
    if not isinstance(plugins, list):
        plugins = []
    plugins_by_id: dict[str, dict[str, Any]] = {}
    for p in plugins:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("plugin_id") or "").strip()
        if pid and pid not in plugins_by_id:
            plugins_by_id[pid] = p

    impls = doc.get("implementations")
    if not isinstance(impls, list):
        return []
    out: list[dict[str, Any]] = []
    for impl in impls:
        if not isinstance(impl, dict):
            continue
        pid = str(impl.get("plugin_id") or "").strip()
        if not pid:
            continue
        rec: dict[str, Any] = {
            "id": pid,
            "plugin_id": pid,
            "name": impl.get("name") or pid,
            "language": impl.get("language"),
            "source": impl.get("source"),
            "compose": impl.get("compose"),
            "build": impl.get("build"),
            "run": impl.get("run"),
            "env": impl.get("env"),
            "hint_template": impl.get("hint_template"),
            "handoff": impl.get("handoff"),
        }
        plugin = plugins_by_id.get(pid)
        if isinstance(plugin, dict):
            rec["plugin"] = plugin
        out.append(rec)
    return out


def find_generator(repo_root: Path, generator_id: str) -> tuple[dict[str, Any], Path]:
    for src in load_enabled_sources(repo_root):
        p = Path(src.get("path") or "")
        if not p.is_absolute():
            p = (repo_root / p).resolve()
        if not p.exists():
            continue
        for g in load_generators_from_source(p):
            if str(g.get("id")) == generator_id:
                return g, p
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


def run_cmd(cmd: list[str], workdir: Path, env: dict[str, str]) -> None:
    subprocess.run(cmd, cwd=str(workdir), env={**os.environ, **env}, check=True)


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
            p = subprocess.run(
                down_cmd,
                cwd=str(source_dir),
                env={**os.environ, **compose_env},
                check=False,
                capture_output=True,
                text=True,
            )
            print(f"[cleanup] compose down rc={p.returncode}")
            if p.returncode != 0:
                err = (p.stderr or "").strip()
                if err:
                    print(f"[cleanup] compose down stderr: {err[-800:]}")
        except Exception as e:
            print(f"[cleanup] compose down failed: {e}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a Flag-Generator definition from the enabled catalog sources.")
    ap.add_argument("--generator-id", required=True)
    ap.add_argument("--out-dir", default="/tmp/flag_generator_out")
    ap.add_argument("--config", default="{}", help="JSON object of inputs")
    ap.add_argument("--repo-root", default="", help="Path to repo root (optional)")
    ap.add_argument("--catalog", default="flag_generators", help="Catalog directory under data_sources/ (default: flag_generators)")
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve() if args.repo_root else repo_root_from_here()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Catalog selection (used by load_enabled_sources/find_generator)
    try:
        os.environ["FLAG_GENERATOR_CATALOG"] = str(args.catalog or "flag_generators")
    except Exception:
        pass

    inputs_dir = out_dir / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)

    try:
        config = json.loads(args.config)
    except Exception as e:
        raise SystemExit(f"Invalid --config JSON: {e}")
    if not isinstance(config, dict):
        raise SystemExit("--config must be a JSON object")

    gen, _src_path = find_generator(repo_root, args.generator_id)
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
        env[str(k).upper()] = str(v)

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

    # Print manifest if present
    manifest = out_dir / "outputs.json"
    if manifest.exists():
        print(manifest.read_text("utf-8"))
    else:
        print(f"No outputs.json found at {manifest}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Quick remote inject copy test on CORE VM with scenario lifecycle.

Usage (env vars):
  CORE_SSH_HOST, CORE_SSH_PORT, CORE_SSH_USERNAME, CORE_SSH_PASSWORD
Optional:
  CORE_SSH_KEY (path), CORE_SSH_KEY_PASSPHRASE
  CORE_SSH_TIMEOUT (seconds)

This script:
  - kills existing core-daemon processes
  - runs core-cleanup
  - starts a new core-daemon
  - creates a simple 2-node CORE scenario (router + vulnerable node)
  - runs the inject test within the scenario
  - cleans up CORE session
  - presents results in a formatted table
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
import textwrap
from dataclasses import dataclass
from typing import Any

try:
    import paramiko  # type: ignore
except Exception:  # pragma: no cover
    paramiko = None


@dataclass
class SSHConfig:
    host: str
    port: int
    username: str
    password: str | None
    key_path: str | None
    key_passphrase: str | None
    timeout: int
    sudo: bool
    sudo_password: str | None


@dataclass
class ResultRow:
    step: str
    ok: bool
    detail: str
    required: bool = True


def _env(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default) or "").strip()


def _load_cfg(args: argparse.Namespace) -> SSHConfig:
    host = str(args.host or _env("CORE_SSH_HOST"))
    port = int(str(args.port or _env("CORE_SSH_PORT", "22") or "22"))
    username = str(args.username or _env("CORE_SSH_USERNAME"))
    password = args.password or _env("CORE_SSH_PASSWORD") or None
    key_path = args.key or _env("CORE_SSH_KEY") or None
    key_passphrase = args.key_passphrase or _env("CORE_SSH_KEY_PASSPHRASE") or None
    timeout = int(str(args.timeout or _env("CORE_SSH_TIMEOUT", "20") or "20"))
    sudo = bool(args.sudo)
    sudo_password = password
    if not host or not username:
        raise RuntimeError("Missing --host/CORE_SSH_HOST or --username/CORE_SSH_USERNAME")
    return SSHConfig(
        host=host,
        port=port,
        username=username,
        password=password,
        key_path=key_path,
        key_passphrase=key_passphrase,
        timeout=timeout,
        sudo=sudo,
        sudo_password=sudo_password,
    )


def _connect(cfg: SSHConfig):
    if paramiko is None:
        raise RuntimeError("paramiko not installed")
    print(f"[connect] host={cfg.host} port={cfg.port} user={cfg.username} sudo={cfg.sudo}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": cfg.host,
        "port": cfg.port,
        "username": cfg.username,
        "timeout": cfg.timeout,
    }
    if cfg.key_path:
        kwargs["key_filename"] = cfg.key_path
        if cfg.key_passphrase:
            kwargs["passphrase"] = cfg.key_passphrase
    if cfg.password and not cfg.key_path:
        kwargs["password"] = cfg.password
    client.connect(**kwargs)
    return client


def _sudo_wrap(cmd: str, *, use_sudo: bool, sudo_password: str | None) -> str:
    if not use_sudo:
        return cmd
    cmd_escaped = cmd.replace('"', '\\"')
    if sudo_password:
        pw = shlex.quote(sudo_password)
        return f"printf '%s\\n' {pw} | sudo -S -p '' sh -lc \"{cmd_escaped}\""
    return f"sudo -n sh -lc \"{cmd_escaped}\""


def _run(client, cmd: str, *, timeout: int = 30, use_sudo: bool = False, sudo_password: str | None = None) -> tuple[int, str]:
    full_cmd = _sudo_wrap(cmd, use_sudo=use_sudo, sudo_password=sudo_password)
    print(f"[exec] sudo={use_sudo} timeout={timeout}s cmd={cmd}")
    stdin, stdout, stderr = client.exec_command(full_cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "ignore")
    err = stderr.read().decode("utf-8", "ignore")
    code = stdout.channel.recv_exit_status()
    text = (out + err).strip()
    print(f"[exec] rc={code}")
    if text:
        print(f"[exec] output:\n{text}")
    return code, text


def _record(results: list[ResultRow], step: str, ok: bool, detail: str, *, required: bool = True) -> None:
    results.append(ResultRow(step=step, ok=ok, detail=detail, required=required))


def _shorten_detail(detail: str, width: int = 88) -> str:
    text = str(detail or "").strip()
    if not text:
        return "-"
    return textwrap.shorten(text, width=width, placeholder="…")


def _render_table(rows: list[ResultRow]) -> str:
    headers = ("Step", "Status", "Details")
    display_rows = [(r.step, "OK" if r.ok else "FAIL", _shorten_detail(r.detail)) for r in rows]
    col1 = max(len(headers[0]), *(len(r[0]) for r in display_rows))
    col2 = max(len(headers[1]), *(len(r[1]) for r in display_rows))
    col3 = max(len(headers[2]), *(len(r[2]) for r in display_rows))
    sep = f"+-{'-' * col1}-+-{'-' * col2}-+-{'-' * col3}-+"
    lines = [
        sep,
        f"| {headers[0].ljust(col1)} | {headers[1].ljust(col2)} | {headers[2].ljust(col3)} |",
        sep,
    ]
    for step, status, detail in display_rows:
        lines.append(f"| {step.ljust(col1)} | {status.ljust(col2)} | {detail.ljust(col3)} |")
    lines.append(sep)
    return "\n".join(lines)


def _parse_json_from_output(text: str) -> dict[str, Any]:
    if not text:
        return {}
    for line in reversed(text.splitlines()):
        candidate = line.strip()
        if not candidate:
            continue
        if candidate.startswith("{") and candidate.endswith("}"):
            try:
                return json.loads(candidate)
            except Exception:
                continue
    try:
        return json.loads(text)
    except Exception:
        return {}


def _parse_report_path(text: str) -> str:
    for line in text.splitlines():
        if "Scenario report written to" in line:
            return line.split("Scenario report written to", 1)[-1].strip()
    return ""


def _parse_docker_nodes(text: str) -> list[str]:
    for line in text.splitlines():
        if "Docker nodes created:" in line and "->" in line:
            tail = line.split("->", 1)[-1].strip()
            if tail:
                return [x.strip() for x in tail.split(",") if x.strip()]
    return []


def _parse_compose_assignments(text: str) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for line in text.splitlines():
        if "Docker node compose assignment node=" in line and " Name=" in line:
            try:
                frag = line.split("Docker node compose assignment node=", 1)[-1]
                node_part, rest = frag.split(" Name=", 1)
                node_name = node_part.strip()
                name_part = rest.split(" ", 1)[0].strip()
                if node_name and name_part:
                    assignments[node_name] = name_part
            except Exception:
                continue
    return assignments


def main() -> int:
    ap = argparse.ArgumentParser(description="Quick remote inject copy test on CORE VM")
    ap.add_argument("--host", help="CORE SSH host")
    ap.add_argument("--port", type=int, default=None, help="CORE SSH port (default: 22)")
    ap.add_argument("--username", help="CORE SSH username")
    ap.add_argument("--password", help="CORE SSH password (omit if using key)")
    ap.add_argument("--key", help="Path to SSH private key")
    ap.add_argument("--key-passphrase", help="Passphrase for SSH key")
    ap.add_argument("--timeout", type=int, default=None, help="SSH timeout seconds")
    ap.add_argument("--sudo", action="store_true", help="Run docker commands with sudo")
    ap.add_argument("--core-host", default="127.0.0.1", help="core-daemon gRPC host (on CORE VM)")
    ap.add_argument("--core-port", type=int, default=50051, help="core-daemon gRPC port (default: 50051)")
    ap.add_argument(
        "--core-python",
        default="/opt/core/venv/bin/python",
        help="Python executable on CORE VM that has CORE gRPC libs",
    )
    ap.add_argument(
        "--core-repo",
        default="/tmp/core-topo-gen",
        help="Path to core-topo-gen repo on CORE VM",
    )
    ap.add_argument("--scenario-name", default="Quick Inject", help="Scenario name")
    ap.add_argument(
        "--docker-remove-conflicts",
        action="store_true",
        help="Allow CLI to remove conflicting Docker resources",
    )
    ap.add_argument("--router-name", default="r1", help="Router node name")
    ap.add_argument("--vuln-name", default="vuln1", help="Vulnerable node name")
    args = ap.parse_args()

    cfg = _load_cfg(args)
    client = _connect(cfg)
    results: list[ResultRow] = []
    session_id: str | None = None
    try:
        ts = str(int(time.time()))
        base = f"/tmp/coretg_inject_test_{ts}"
        compose = os.path.join(base, "docker-compose.yml")
        src_dir = os.path.join(base, "src")
        print(f"[setup] base={base}")
        cmd = " && ".join(
            [
                f"mkdir -p {src_dir}",
                f"echo 'hello from inject test' > {src_dir}/hello.txt",
                f"cat > {compose} <<'YML'\n"
                "services:\n"
                f"  {args.vuln_name}:\n"
                "    image: alpine:3.19\n"
                "    volumes:\n"
                "      - inject-flow:/flow_injects\n"
                "    command: [\"sh\", \"-lc\", \"sleep 300\"]\n"
                "    depends_on:\n"
                "      inject_copy:\n"
                "        condition: service_completed_successfully\n"
                "  inject_copy:\n"
                "    image: alpine:3.19\n"
                "    volumes:\n"
                f"      - {src_dir}:/src:ro\n"
                "      - inject-flow:/dst/injects\n"
                "    command: [\"sh\", \"-lc\", \"mkdir -p /dst/injects && cp -a /src/. /dst/injects/\"]\n"
                "volumes:\n"
                "  inject-flow: {}\n"
                "YML",
            ]
        )
        code, text = _run(client, cmd, timeout=30)
        _record(results, "prepare files", code == 0, text or "ok")
        if code != 0:
            raise RuntimeError(f"setup failed: {text}")

        print("[core] killing core-daemon")
        kill_cmd = "pkill -f core-daemon || true"
        code, text = _run(client, kill_cmd, timeout=30, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
        _record(results, "kill core-daemon", code in (0, -1), text or "ok", required=False)

        print("[core] running core-cleanup")
        cleanup_cmd = "core-cleanup"
        code, text = _run(client, cleanup_cmd, timeout=120, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
        _record(results, "core-cleanup", code == 0, text or "ok")

        print("[core] starting core-daemon")
        start_cmd = (
            "if command -v systemctl >/dev/null 2>&1; then "
            "systemctl restart core-daemon; "
            "else nohup core-daemon -d > /tmp/core-daemon.log 2>&1 & fi"
        )
        code, text = _run(client, start_cmd, timeout=30, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
        _record(results, "start core-daemon", code == 0, text or "ok")
        if code != 0:
            raise RuntimeError(f"core-daemon start failed: {text}")

        print("[core] waiting for gRPC port")
        wait_cmd = (
            "for i in "
            + " ".join(str(i) for i in range(1, 31))
            + "; do "
            f"if ss -ltn 2>/dev/null | grep -q ':{args.core_port} '; then exit 0; fi; "
            f"if netstat -ltn 2>/dev/null | grep -q ':{args.core_port} '; then exit 0; fi; "
            "sleep 1; "
            "done; exit 1"
        )
        code, text = _run(client, wait_cmd, timeout=40, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
        _record(results, "wait core gRPC", code == 0, text or "ok")
        if code != 0:
            raise RuntimeError("core-daemon gRPC port not ready")

        print("[core] creating scenario via CLI")
        scenario_xml = os.path.join(base, "scenario.xml")
        scenario_contents = textwrap.dedent(
            f"""\
            <?xml version='1.0' encoding='utf-8'?>
            <Scenarios>
              <Scenario name="{args.scenario_name}" scenario_total_nodes="2">
                <ScenarioEditor>
                  <BaseScenario filepath="" />
                  <section name="Node Information" density_count="1" base_nodes="1" additive_nodes="0" combined_nodes="1" weight_rows="0" count_rows="1" weight_sum="1.000" normalized_weight_sum="1.000">
                    <item selected="Docker" factor="1.000" v_metric="Count" v_count="1" />
                  </section>
                  <section name="Routing" density="0.5" explicit_count="1" derived_count="0" total_planned="1" weight_rows="0" count_rows="1" weight_sum="1.000">
                    <item selected="RIP" factor="1.000" r2r_mode="Min" r2s_mode="Uniform" r2s_hosts_min="1" r2s_hosts_max="1" v_metric="Count" v_count="1" />
                  </section>
                  <section name="Vulnerabilities" flag_type="text" density="1.0" explicit_count="1" derived_count="0" total_planned="1" weight_rows="0" count_rows="1" weight_sum="1.000">
                    <item selected="Specific" factor="1.000" v_name="custom/inject_test" v_path="{compose}" v_metric="Count" v_count="1" />
                  </section>
                  <section name="Services" density="0.0" />
                  <section name="Traffic" density="0.0" />
                  <section name="Segmentation" density="0.0" />
                </ScenarioEditor>
              </Scenario>
            </Scenarios>
            """
        ).strip()
        xml_cmd = f"cat > {shlex.quote(scenario_xml)} <<'XML'\n{scenario_contents}\nXML"
        code, text = _run(client, xml_cmd, timeout=30, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
        _record(results, "write scenario xml", code == 0, text or "ok")
        if code != 0:
            raise RuntimeError(f"scenario xml write failed: {text}")

        docker_conflict_flag = "--docker-remove-conflicts" if args.docker_remove_conflicts else ""
        cli_cmd = (
            f"cd {shlex.quote(args.core_repo)} && "
            f"{shlex.quote(args.core_python)} -m core_topo_gen.cli "
            f"--xml {shlex.quote(scenario_xml)} --scenario {shlex.quote(args.scenario_name)} "
            f"--host {shlex.quote(args.core_host)} --port {shlex.quote(str(args.core_port))} --verbose "
            f"{docker_conflict_flag}"
        )
        code, text = _run(client, cli_cmd, timeout=300, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
        report_path = _parse_report_path(text)
        ok = code == 0 and bool(report_path)
        _record(results, "run cli", ok, report_path or text or "ok")
        if not ok:
            raise RuntimeError(f"scenario creation failed: {text}")

        docker_nodes = _parse_docker_nodes(text)
        compose_assignments = _parse_compose_assignments(text)
        target_nodes = []
        for node_name, compose_name in compose_assignments.items():
            if compose_name != "standard-ubuntu-docker-core":
                target_nodes.append(node_name)
        if not target_nodes:
            target_nodes = docker_nodes or [args.vuln_name]

        print("[verify] waiting for vuln container")
        container_name = ""
        for name in target_nodes:
            for _ in range(30):
                find_cmd = "docker ps --format '{{.Names}}' | grep -E '^" + name + "($|_)' | head -n 1"
                code, text = _run(client, find_cmd, timeout=10, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
                if code == 0 and text:
                    container_name = text.splitlines()[0].strip()
                    break
                time.sleep(1)
            if container_name:
                break
        _record(results, "locate vuln container", bool(container_name), container_name or "not found")

        print("[verify] checking /flow_injects/hello.txt")
        if container_name:
            check_cmd = f"docker exec {shlex.quote(container_name)} cat /flow_injects/hello.txt"
            code, text = _run(client, check_cmd, timeout=30, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
            ok = code == 0 and "hello from inject test" in text
            _record(results, "verify inject", ok, text or "missing")
        else:
            _record(results, "verify inject", False, "container not found")

        overall_ok = all(r.ok for r in results if r.required)
        print(_render_table(results))
        return 0 if overall_ok else 2
    finally:
        print("[cleanup] cleaning CORE session and temp files")
        if session_id:
            cleanup_session_cmd = textwrap.dedent(
                f"""
                CORETG_SESSION_ID={shlex.quote(session_id)} \
                CORETG_CORE_HOST={shlex.quote(args.core_host)} \
                CORETG_CORE_PORT={shlex.quote(str(args.core_port))} \
                {shlex.quote(args.core_python)} - <<'PY'
                import os
                from core.api.grpc.client import CoreGrpcClient

                session_id = os.environ.get("CORETG_SESSION_ID")
                core_host = os.environ.get("CORETG_CORE_HOST", "127.0.0.1")
                core_port = int(os.environ.get("CORETG_CORE_PORT", "50051"))

                if session_id:
                    core = CoreGrpcClient(address=f"{{core_host}}:{{core_port}}")
                    core.connect()
                    try:
                        if hasattr(core, "stop_session"):
                            core.stop_session(session_id)
                    except Exception:
                        pass
                    try:
                        if hasattr(core, "close_session"):
                            core.close_session(session_id)
                    except Exception:
                        pass
                    try:
                        if hasattr(core, "delete_session"):
                            core.delete_session(session_id)
                    except Exception:
                        pass
                PY
                """
            ).strip()
            _run(client, cleanup_session_cmd, timeout=60, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
        _run(client, f"rm -rf {base}", timeout=30, use_sudo=cfg.sudo, sudo_password=cfg.sudo_password)
        try:
            client.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())

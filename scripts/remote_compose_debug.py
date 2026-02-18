from __future__ import annotations

import json
import re
import sys
from pathlib import Path
import shlex


def _find_first_ssh_cfg(obj: object) -> dict | None:
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            sh = str(cur.get("ssh_host") or "").strip()
            su = str(cur.get("ssh_username") or "").strip()
            sp_raw = cur.get("ssh_port")
            try:
                sp = int(sp_raw) if sp_raw is not None else 22
            except Exception:
                sp = 22
            pw = str(cur.get("ssh_password") or "").strip()
            if sh and su and pw:
                return {"ssh_host": sh, "ssh_port": sp, "ssh_username": su, "ssh_password": pw}
            for v in cur.values():
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def main() -> int:
    try:
        import paramiko  # type: ignore
    except Exception as exc:
        print(f"ERROR: paramiko not available: {exc}")
        return 2

    snap = Path("outputs/editor_snapshots/coreadmin.json")
    if not snap.exists():
        print("ERROR: missing outputs/editor_snapshots/coreadmin.json")
        return 2

    cfg = json.loads(snap.read_text(encoding="utf-8"))
    ssh_cfg = _find_first_ssh_cfg(cfg)
    if not ssh_cfg:
        print("ERROR: could not find ssh_host/ssh_username/ssh_password in snapshot")
        return 2

    host = ssh_cfg["ssh_host"]
    port = int(ssh_cfg.get("ssh_port") or 22)
    user = ssh_cfg["ssh_username"]
    password = ssh_cfg["ssh_password"]

    # Optional journal time filter: e.g. "5 minutes ago", "2026-02-17 23:50:00".
    since = None
    try:
        if "--since" in sys.argv:
            i = sys.argv.index("--since")
            if i + 1 < len(sys.argv):
                since = str(sys.argv[i + 1]).strip() or None
    except Exception:
        since = None

    # Common nodes we care about across scenarios.
    # (Some planner outputs generate docker-11..docker-15 + workstation-8, while
    # others use docker-1..docker-5.)
    nodes = [
        "docker-1",
        "docker-3",
        "docker-11",
        "docker-12",
        "docker-13",
        "docker-14",
        "docker-15",
        "workstation-1",
        "workstation-2",
        "workstation-4",
        "workstation-6",
        "workstation-8",
            "workstation-9",
        "workstation-10",
    ]

    def wrapper_df_cmd(node: str) -> str:
        # Prefer reading the *actual* build context from the node's compose file.
        # Directory mtime is not reliable (it does not update when Dockerfile contents
        # are overwritten), so `ls -dt docker-wrap-*` can select stale dirs.
        f = f"/tmp/vulns/docker-compose-{node}.yml"
        return (
            f"echo '\n=== {node} wrapper Dockerfile (best-effort) ==='\n"
            f"d=$(python3 - <<'PY'\n"
            f"import re\n"
            f"from pathlib import Path\n"
            f"p = Path({f!r})\n"
            f"if not p.exists():\n"
            f"    print('')\n"
            f"    raise SystemExit(0)\n"
            f"lines = p.read_text(encoding='utf-8', errors='ignore').splitlines()\n"
            f"# crude YAML walk for: services: -> <node>: -> build: -> context:\n"
            f"in_services = False\n"
            f"svc_indent = None\n"
            f"in_target = False\n"
            f"target_indent = None\n"
            f"in_build = False\n"
            f"build_indent = None\n"
            f"node = {node!r}\n"
            f"ctx = ''\n"
            f"for line in lines:\n"
            f"    if not in_services:\n"
            f"        if re.match(r'^\\s*services\\s*:\\s*$', line):\n"
            f"            in_services = True\n"
            f"        continue\n"
            f"    if svc_indent is None:\n"
            f"        m = re.match(r'^(\\s+)([^\\s:#]+)\\s*:\\s*$', line)\n"
            f"        if m:\n"
            f"            svc_indent = len(m.group(1))\n"
            f"        else:\n"
            f"            continue\n"
            f"    msvc = re.match(r'^(\\s+)([^\\s:#]+)\\s*:\\s*$', line)\n"
            f"    if msvc and len(msvc.group(1)) == svc_indent:\n"
            f"        in_target = (msvc.group(2) == node)\n"
            f"        target_indent = len(msvc.group(1))\n"
            f"        in_build = False\n"
            f"        build_indent = None\n"
            f"        continue\n"
            f"    if not in_target:\n"
            f"        continue\n"
            f"    mb = re.match(r'^(\\s*)build\\s*:\\s*$', line)\n"
            f"    if mb:\n"
            f"        in_build = True\n"
            f"        build_indent = len(mb.group(1))\n"
            f"        continue\n"
            f"    if in_build:\n"
            f"        mc = re.match(r'^(\\s*)context\\s*:\\s*(.+)\\s*$', line)\n"
            f"        if mc:\n"
            f"            ctx = mc.group(2).strip().strip(\"\\\"'\")\n"
            f"            break\n"
            f"print(ctx)\n"
            f"PY\n"
            f")\n"
            f"if [ -n \"$d\" ] && [ -f \"$d/Dockerfile\" ]; then\n"
            f"  echo \"wrapper_dir=$d\"\n"
            f"  ls -l \"$d/Dockerfile\" | cat\n"
            f"  sed -n '1,120p' \"$d/Dockerfile\" | cat\n"
            f"else\n"
            f"  echo 'wrapper Dockerfile not found (no build.context or no Dockerfile)'\n"
            f"fi\n"
        )

    def compose_cmd(node: str) -> str:
        f = f"/tmp/vulns/docker-compose-{node}.yml"
        return (
            f"echo '\n=== {node} compose ==='\n"
            f"if [ -f {f} ]; then\n"
            f"  ls -l {f} | cat\n"
            f"  python3 - <<'PY'\n"
            f"import re\n"
            f"from pathlib import Path\n"
            f"p = Path({f!r})\n"
            f"lines = p.read_text(encoding='utf-8', errors='ignore').splitlines()\n"
            f"in_services = False\n"
            f"svc_indent = None\n"
            f"current = None\n"
            f"svc_images = {{}}\n"
            f"svc_ports = {{}}\n"
            f"svc_cmd = {{}}\n"
            f"svc_entry = {{}}\n"
            f"svc_user = {{}}\n"
            f"svc_cn = {{}}\n"
            f"for line in lines:\n"
            f"    if not in_services:\n"
            f"        if re.match(r'^\\s*services\\s*:\\s*$', line):\n"
            f"            in_services = True\n"
            f"        continue\n"
            f"    if svc_indent is None:\n"
            f"        m = re.match(r'^(\\s+)([^\\s:#]+)\\s*:\\s*$', line)\n"
            f"        if m:\n"
            f"            svc_indent = len(m.group(1))\n"
            f"            current = m.group(2)\n"
            f"            svc_images.setdefault(current, None)\n"
            f"            svc_ports.setdefault(current, False)\n"
            f"            svc_cmd.setdefault(current, None)\n"
            f"            svc_entry.setdefault(current, None)\n"
            f"            svc_user.setdefault(current, None)\n"
            f"            svc_cn.setdefault(current, None)\n"
            f"        continue\n"
            f"    m = re.match(r'^(\\s+)([^\\s:#]+)\\s*:\\s*$', line)\n"
            f"    if m and len(m.group(1)) == svc_indent:\n"
            f"        current = m.group(2)\n"
            f"        svc_images.setdefault(current, None)\n"
            f"        svc_ports.setdefault(current, False)\n"
            f"        svc_cmd.setdefault(current, None)\n"
            f"        svc_entry.setdefault(current, None)\n"
            f"        svc_user.setdefault(current, None)\n"
            f"        svc_cn.setdefault(current, None)\n"
            f"        continue\n"
            f"    if current:\n"
            f"        mi = re.match(r'^\\s*image\\s*:\\s*(.+)\\s*$', line)\n"
            f"        if mi and svc_images.get(current) is None:\n"
            f"            svc_images[current] = mi.group(1).strip().strip(\"\\\"'\")\n"
            f"        mc = re.match(r'^\\s*command\\s*:\\s*(.+)\\s*$', line)\n"
            f"        if mc and svc_cmd.get(current) is None:\n"
            f"            svc_cmd[current] = mc.group(1).strip()\n"
            f"        me = re.match(r'^\\s*entrypoint\\s*:\\s*(.+)\\s*$', line)\n"
            f"        if me and svc_entry.get(current) is None:\n"
            f"            svc_entry[current] = me.group(1).strip()\n"
            f"        mu = re.match(r'^\\s*user\\s*:\\s*(.+)\\s*$', line)\n"
            f"        if mu and svc_user.get(current) is None:\n"
            f"            svc_user[current] = mu.group(1).strip()\n"
            f"        mcn = re.match(r'^\\s*container_name\\s*:\\s*(.+)\\s*$', line)\n"
            f"        if mcn and svc_cn.get(current) is None:\n"
            f"            svc_cn[current] = mcn.group(1).strip()\n"
            f"        if re.match(r'^\\s*ports\\s*:\\s*$', line):\n"
            f"            svc_ports[current] = True\n"
            f"print('services:')\n"
            f"for k in sorted(svc_images):\n"
            f"    img = svc_images.get(k) or ''\n"
            f"    ports = ' ports' if svc_ports.get(k) else ''\n"
            f"    cmd = svc_cmd.get(k)\n"
            f"    ent = svc_entry.get(k)\n"
            f"    usr = svc_user.get(k)\n"
            f"    cn = svc_cn.get(k)\n"
            f"    extra = ''\n"
            f"    if cn: extra += f' container_name={{cn}}'\n"
            f"    if usr: extra += f' user={{usr}}'\n"
            f"    if ent: extra += f' entrypoint={{ent}}'\n"
            f"    if cmd: extra += f' command={{cmd}}'\n"
            f"    print(f'  - {{k}} -> {{img}}{{ports}}{{extra}}')\n"
            f"PY\n"
            f"else\n"
            f"  echo 'MISSING: {f}'\n"
            f"fi\n"
        )

    def inspect_cmd(node: str) -> str:
        return (
            f"echo '\n=== {node} container ==='\n"
            f"((docker inspect --format '{{{{.Name}}}} {{{{.Config.Image}}}} {{{{.State.Status}}}}' {node} 2>&1 "
            f"|| sudo -n docker inspect --format '{{{{.Name}}}} {{{{.Config.Image}}}} {{{{.State.Status}}}}' {node} 2>&1) | head -n 8) || true\n"
            f"echo '-- docker ps match --'\n"
            f"((docker ps --format '{{{{.Names}}}} {{{{.Image}}}} {{{{.Status}}}}' | egrep '^{node} ' "
            f"|| sudo -n docker ps --format '{{{{.Names}}}} {{{{.Image}}}} {{{{.Status}}}}' | egrep '^{node} ') 2>/dev/null) || true\n"
            f"echo '-- docker logs (tail) --'\n"
            f"((sudo -n docker logs --tail 80 {node} 2>&1) | tail -n 80) || true\n"
            f"echo '-- ip addr inside container (best-effort) --'\n"
            f"((sudo -n docker exec {node} sh -lc 'ip addr show 2>/dev/null || /sbin/ip addr show 2>/dev/null || ifconfig -a 2>/dev/null || true' 2>&1) | head -n 120) || true\n"
        )

    def compose_runtime_cmd(node: str) -> str:
        f = f"/tmp/vulns/docker-compose-{node}.yml"
        # Compose ps can fail if docker requires sudo; use sudo -n.
        return (
            f"echo '-- docker compose ps (for per-node file) --'\n"
            f"((sudo -n docker compose -f {f} ps 2>&1) | head -n 120) || true\n"
            f"echo '-- docker ps: related containers --'\n"
            f"(sudo -n docker ps -a --format '{{{{.Names}}}} {{{{.Image}}}} {{{{.Status}}}}' | egrep '(^({node})$)|({node}.*inject_copy)|(inject_copy.*{node})' || true) | head -n 120\n"
        )

    journal_lines = 2500
    try:
        if "--journal-lines" in sys.argv:
            i = sys.argv.index("--journal-lines")
            if i + 1 < len(sys.argv):
                journal_lines = max(100, int(str(sys.argv[i + 1]).strip()))
    except Exception:
        journal_lines = 2500

    if since:
        since_q = shlex.quote(str(since))
        journal_cmd = (
            f"(sudo -n journalctl -u core-daemon --since {since_q} -n {journal_lines} -o short-iso --no-pager 2>/dev/null || "
            f"journalctl -u core-daemon --since {since_q} -n {journal_lines} -o short-iso --no-pager 2>/dev/null || true) | cat"
        )
    else:
        journal_cmd = (
            "(sudo -n journalctl -u core-daemon -n 400 -o short-iso --no-pager 2>/dev/null || "
            "journalctl -u core-daemon -n 400 -o short-iso --no-pager 2>/dev/null || true) | cat"
        )

    remote_cmd = "set -euo pipefail\n" + "\n".join(
        [
            "echo REMOTE_OK",
            "hostname",
            "whoami",
            # Pre-auth sudo so subsequent `sudo -n docker ...` calls work without prompting.
            # We feed the password via stdin from Paramiko (not echoed).
            "echo '[sudo] validating (best-effort)'",
            "sudo -S -p '' -v || true",
            "echo '\n=== compose_assignments.json ==='",
            "(ls -l /tmp/vulns/compose_assignments.json 2>/dev/null || echo 'MISSING: /tmp/vulns/compose_assignments.json') | cat",
            "(head -n 120 /tmp/vulns/compose_assignments.json 2>/dev/null || true) | cat",
            *[compose_cmd(n) + wrapper_df_cmd(n) + compose_runtime_cmd(n) + inspect_cmd(n) for n in nodes],
            "echo '\n=== core-daemon journal ==='",
            journal_cmd,
        ]
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=user, password=password, timeout=12, banner_timeout=12, auth_timeout=12)
    except Exception as exc:
        print(f"ERROR: SSH connect failed to {user}@{host}:{port}: {exc}")
        return 2

    stdin, stdout, stderr = client.exec_command(remote_cmd, get_pty=True)
    try:
        # Provide sudo password once for the `sudo -S -v` step (ignored if sudo doesn't need it).
        stdin.write(password + "\n")
        stdin.flush()
    except Exception:
        pass
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    client.close()

    out = (out or "").strip()
    err = (err or "").strip()

    # Make sure we never accidentally echo the SSH password.
    if password and password in out:
        out = out.replace(password, "<redacted>")
    if password and password in err:
        err = err.replace(password, "<redacted>")

    print(out)
    if err:
        print("\n[stderr]")
        print(err)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations
import os
import stat
import random
from typing import Dict, List, Tuple
from ..types import NodeInfo, TrafficInfo


def _ip_only(cidr: str) -> str:
    return cidr.split("/")[0] if "/" in cidr else cidr


def _clean_traffic_dir(out_dir: str) -> None:
    """Remove previously generated traffic scripts from the output directory.

    For safety, only removes regular files whose names start with "traffic_".
    """
    try:
        for name in os.listdir(out_dir):
            path = os.path.join(out_dir, name)
            # remove files like traffic_<id>_rN.py or traffic_<id>_sN.py
            if os.path.isfile(path) and name.startswith("traffic_"):
                try:
                    os.remove(path)
                except Exception:
                    # best-effort cleanup; ignore failures
                    pass
    except FileNotFoundError:
        pass


def _tcp_receiver_script(port: int) -> str:
    return f"""#!/usr/bin/env python3
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.listen(5)
print("[traffic] TCP receiver listening on {port}")
try:
    while True:
        conn, addr = s.accept()
        with conn:
            while True:
                data = conn.recv(8192)
                if not data:
                    break
except KeyboardInterrupt:
    pass
"""


def _tcp_sender_script(host: str, port: int) -> str:
    return f"""#!/usr/bin/env python3
import socket, time
host = "{host}"; port = {port}
print(f"[traffic] TCP sender to {{host}}:{{port}}")
for i in range(100):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((host, port))
        s.sendall(b"x" * 1024)
        s.close()
    except Exception:
        pass
    time.sleep(1.0)
"""


def _udp_receiver_script(port: int) -> str:
    return f"""#!/usr/bin/env python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", {port}))
print("[traffic] UDP receiver listening on {port}")
try:
    while True:
        data, addr = s.recvfrom(8192)
except KeyboardInterrupt:
    pass
"""


def _udp_sender_script(host: str, port: int) -> str:
    return f"""#!/usr/bin/env python3
import socket, time
host = "{host}"; port = {port}
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print(f"[traffic] UDP sender to {{host}}:{{port}}")
for i in range(300):
    try:
        s.sendto(b"x" * 512, (host, port))
    except Exception:
        pass
    time.sleep(0.2)
"""


def _choose_kind(kinds: List[Tuple[str, float]]) -> str:
    total = sum(w for _, w in kinds)
    if total <= 0:
        return "TCP"
    r = random.random() * total
    acc = 0.0
    for k, w in kinds:
        acc += w
        if r <= acc:
            return k
    return kinds[-1][0]


def generate_traffic_scripts(hosts: List[NodeInfo], density: float, items: List[TrafficInfo], out_dir: str = "/tmp/traffic") -> Dict[int, List[str]]:
    """Generate simple TCP/UDP sender/receiver scripts for a subset of hosts.

    Returns a mapping of node_id -> list of script file paths (created locally).
    """
    result: Dict[int, List[str]] = {}
    if not hosts or density <= 0:
        return result

    os.makedirs(out_dir, exist_ok=True)
    # Clean out any existing generated traffic scripts before writing new ones
    _clean_traffic_dir(out_dir)

    # Build weighted kinds; expand 'Random' into TCP/UDP choice later
    weighted: List[Tuple[str, float]] = []
    for it in items or []:
        k = (it.kind or "").strip()
        if not k:
            continue
        if k.lower() == "random":
            # split weight evenly between TCP and UDP for selection
            w = max(0.0, float(it.factor))
            if w > 0:
                weighted.append(("TCP", w / 2.0))
                weighted.append(("UDP", w / 2.0))
        else:
            weighted.append((k.upper(), max(0.0, float(it.factor))))
    if not weighted:
        weighted = [("TCP", 1.0)]

    # Select subset of hosts by density
    k = max(1, int(len(hosts) * density))
    selected = hosts.copy()
    random.shuffle(selected)
    selected = selected[:k]

    # Maintain per-node indices for naming and per-node per-protocol RX offsets
    recv_idx_by_node: Dict[int, int] = {}
    send_idx_by_node: Dict[int, int] = {}
    rx_proto_idx: Dict[str, Dict[int, int]] = {"TCP": {}, "UDP": {}}

    # For each selected host, create sender scripts for that host and receiver scripts on the chosen target
    for host in selected:
        others = [h for h in hosts if h.node_id != host.node_id]
        # Decide which items to use (default to single TCP if none provided)
        items_to_use = items if items else [TrafficInfo(kind="TCP", factor=1.0)]
        for it in items_to_use:
            ik = (it.kind or "").strip()
            if not ik:
                continue
            kind = _choose_kind(weighted) if ik.lower() == "random" else ik.upper()

            base = 5000 if kind == "TCP" else 6000

            target = random.choice(others) if others else None

            # Determine the receiver node: prefer target; if none, fall back to host
            rx_node = target if target is not None else host
            rx_node_id = rx_node.node_id

            # Compute per-node per-protocol receiver port index to avoid collisions
            proto_map = rx_proto_idx[kind]
            idx = proto_map.get(rx_node_id, 1)
            rx_port = base + (rx_node_id % 1000) + (idx - 1)
            proto_map[rx_node_id] = idx + 1

            # Receiver script named with the receiver node's id
            r_index = recv_idx_by_node.get(rx_node_id, 1)
            recv_name = os.path.join(out_dir, f"traffic_{rx_node_id}_r{r_index}.py")
            recv_content = _tcp_receiver_script(rx_port) if kind == "TCP" else _udp_receiver_script(rx_port)
            with open(recv_name, "w", encoding="utf-8") as f:
                f.write(recv_content)
            os.chmod(recv_name, os.stat(recv_name).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            recv_idx_by_node[rx_node_id] = r_index + 1
            # Track in result mapping under receiver node id
            result.setdefault(rx_node_id, []).append(recv_name)

            # Sender script from the current host to the receiver node/port
            if target is not None:
                dst_ip = _ip_only(rx_node.ip4)
                dst_port = rx_port
                s_index = send_idx_by_node.get(host.node_id, 1)
                send_name = os.path.join(out_dir, f"traffic_{host.node_id}_s{s_index}.py")
                send_content = _tcp_sender_script(dst_ip, dst_port) if kind == "TCP" else _udp_sender_script(dst_ip, dst_port)
                with open(send_name, "w", encoding="utf-8") as f:
                    f.write(send_content)
                os.chmod(send_name, os.stat(send_name).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                send_idx_by_node[host.node_id] = s_index + 1
                result.setdefault(host.node_id, []).append(send_name)

    return result

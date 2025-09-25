from __future__ import annotations
import os
import ipaddress
import random
import logging
from typing import Dict, List, Tuple, Optional
import shutil
from ..types import NodeInfo, SegmentationInfo
from .services import ensure_service
from ..plugins import segmentation as seg_plugins

logger = logging.getLogger(__name__)

"""
Segmentation types available via GUI and planning logic.

Only keep Firewall and NAT, and add CUSTOM which is handled by a pluggable
segmentation plugin infrastructure similar to Traffic's CUSTOM.
"""
SEGMENTATION_GUI_TYPES: List[str] = [
    "Firewall",   # iptables-based filtering
    "NAT",        # network address translation (iptables nat table)
    "CUSTOM",     # handled by plugin
]

# Map GUI labels to concrete service names typically present in CORE
# If a mapping is missing, we fall back to attempting the same label.
SERVICE_ENABLE_MAP: Dict[str, str] = {
    # Use a single custom service for all segmentation
    # GUI labels map to the unified Segmentation service
    "NAT": "Segmentation",
    "Firewall": "Segmentation",
    # CUSTOM is plugin-defined; don't force-enable a specific service here
}


def _group_hosts_by_subnet(hosts: List[NodeInfo]) -> Dict[str, List[NodeInfo]]:
    groups: Dict[str, List[NodeInfo]] = {}
    for h in hosts:
        try:
            ip, prefix = h.ip4.split("/") if "/" in h.ip4 else (h.ip4, "24")
            net = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        except Exception:
            # fall back to /24 bucket by first three octets
            parts = h.ip4.split(".")
            key = ".".join(parts[:3]) + ".0/24" if len(parts) >= 3 else h.ip4
            net = key
        groups.setdefault(net, []).append(h)
    return groups


def _choose_service_name(items: List[SegmentationInfo]) -> str:
    # Build weighted list; expand Random to GUI-aligned pool
    weighted: List[Tuple[str, float]] = []
    for it in items or []:
        name = (it.name or "").strip()
        if not name:
            continue
        if name.lower() == "random":
            w = max(0.0, float(it.factor))
            if w > 0:
                for s in SEGMENTATION_GUI_TYPES:
                    weighted.append((s, w / len(SEGMENTATION_GUI_TYPES)))
        else:
            weighted.append((name, max(0.0, float(it.factor))))
    if not weighted:
        weighted = [(SEGMENTATION_GUI_TYPES[0], 1.0)]
    total = sum(w for _, w in weighted)
    r = random.random() * total
    acc = 0.0
    for name, w in weighted:
        acc += w
        if r <= acc:
            return name
    return weighted[-1][0]


def plan_and_apply_segmentation(
    session: object,
    routers: List[NodeInfo],
    hosts: List[NodeInfo],
    density: float,
    items: List[SegmentationInfo],
    nat_mode: str = "SNAT",
    out_dir: str = "/tmp/segmentation",
    include_hosts: bool = False,
) -> Dict[str, object]:
    """
    Create a number of segmentation "slots" based on density and assign selected services by factor.
    Adds and configures chosen services on nodes. Generates simple iptables scripts to enforce policies.

    Returns a summary dictionary with planned rules per node.
    """
    summary: Dict[str, object] = {"rules": []}
    if not hosts:
        return summary
    os.makedirs(out_dir, exist_ok=True)

    # Track existing NAT rules to avoid duplicates across runs and within this call
    # Key: (node_id, internal_cidr, external_cidr, mode, egress_ip)
    seen_nat_rules: set[Tuple[int, str, str, str, str]] = set()
    # Track nodes that already have a NAT rule to enforce at most one NAT per node
    nat_nodes_taken: set[int] = set()
    # Track nodes that already have Firewall rules (subnet/host/protect) to avoid mixing with NAT
    fw_nodes_taken: set[int] = set()
    try:
        import json
        summary_path = os.path.join(out_dir, "segmentation_summary.json")
        if os.path.exists(summary_path):
            with open(summary_path, "r", encoding="utf-8") as jf:
                prev = json.load(jf) or {}
            for rr in (prev.get("rules") or []):
                r = (rr.get("rule") or {})
                if (r.get("type") or "").lower() == "nat":
                    node_id = int(rr.get("node_id")) if rr.get("node_id") is not None else -1
                    if node_id >= 0:
                        nat_nodes_taken.add(node_id)
                    internal = str(r.get("internal") or "")
                    external = str(r.get("external") or "0.0.0.0/0")
                    mode = str(r.get("mode") or "SNAT").upper()
                    eip = str(r.get("egress_ip") or "")
                    seen_nat_rules.add((node_id, internal, external, mode, eip))
                elif (r.get("type") or "").lower() in ("subnet_block", "host_block", "protect_internal"):
                    node_id = int(rr.get("node_id")) if rr.get("node_id") is not None else -1
                    if node_id >= 0:
                        fw_nodes_taken.add(node_id)
    except Exception:
        # Non-fatal if we can't read the prior summary
        pass

    # Ensure the output directory is empty before writing any new segmentation artifacts
    removed_items = 0
    try:
        for name in os.listdir(out_dir):
            p = os.path.join(out_dir, name)
            try:
                if os.path.isfile(p) or os.path.islink(p):
                    os.unlink(p)
                    removed_items += 1
                elif os.path.isdir(p):
                    shutil.rmtree(p)
                    removed_items += 1
            except Exception:
                # Best-effort clean; ignore failures
                pass
    except Exception:
        # If listing fails, attempt to recreate the folder
        try:
            shutil.rmtree(out_dir, ignore_errors=True)
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            pass
    try:
        logger.info("Segmentation: prepared output dir %s (removed %d items)", out_dir, removed_items)
    except Exception:
        pass

    # Determine the scale for slots: use number of distinct subnets across hosts
    subnets = _group_hosts_by_subnet(hosts)
    base = max(1, len(subnets))
    # Density semantics for segmentation with per-item counts:
    # - Count-based slots (sum of abs_count across items) are ALWAYS applied and do not consume density
    # - Weight-based density adds additional slots: density <=0: 0; 0<density<1: fraction of base; density>=1: absolute slots
    try:
        ds = float(density)
    except Exception:
        ds = 0.0
    abs_slots_total = 0
    try:
        for it in (items or []):
            c = getattr(it, "abs_count", 0) or 0
            if c > 0:
                abs_slots_total += int(c)
    except Exception:
        abs_slots_total = 0

    # Compute density-based slots (weight-based)
    density_slots = 0
    if ds >= 1:
        density_slots = max(1, int(round(ds)))
    elif ds > 0:
        d = max(0.0, min(1.0, ds))
        density_slots = max(1, min(base, int(round(base * d))))
    # If no explicit counts and density <= 0, nothing to plan
    if abs_slots_total <= 0 and density_slots <= 0:
        return summary

    # Total slots = count slots + density slots
    slots = abs_slots_total + density_slots
    dens_for_log = max(0.0, min(1.0, float(density)))

    # Build a deterministic service plan honoring per-item abs_count first.
    # Prioritize NAT first to reserve eligible routers before firewall rules consume them.
    svc_sequence: List[str] = []
    nat_seq: List[str] = []
    other_seq: List[str] = []
    try:
        for it in (items or []):
            c = int(getattr(it, "abs_count", 0) or 0)
            if c <= 0:
                continue
            name = (it.name or "").strip() or "Firewall"
            if name.upper() == "NAT":
                nat_seq.extend([name] * c)
            else:
                other_seq.extend([name] * c)
    except Exception:
        nat_seq, other_seq = [], []
    # Count-based plan occupies the first abs_slots_total positions; remaining positions use weighted selection
    svc_sequence = nat_seq + other_seq

    # Precompute subnet list and pick targets realistically
    nets = list(subnets.keys())

    # Per-(node_id, rule_type) counters for file names
    counters: Dict[Tuple[int, str], int] = {}
    # Track nodes that already received a segmentation rule in this run
    used_nodes: set[int] = set()
    # Index of planned firewall coverage to avoid overlaps per node and chain
    from collections import defaultdict
    fw_index = defaultdict(lambda: {
        "protect_internal": set(),                # {subnet}
        "subnet_block_forward": set(),            # {(src_net, dst_net)}
        "subnet_block_input": set(),              # {src_net}
        "host_block_forward": set(),              # {(src_ip, dst_ip)}
        "host_block_input": set(),                # {(src_ip, dst_ip)}
    })

    try:
        logger.info("Segmentation: planning %d slots across %d subnets (density=%.2f)", slots, len(nets), float(dens_for_log))
    except Exception:
        # Best-effort logging; avoid breaking execution due to logging issues
        pass
    for idx in range(slots):
        if idx < len(svc_sequence):
            try:
                svc = svc_sequence[idx]
            except Exception:
                svc = _choose_service_name(items)
        else:
            svc = _choose_service_name(items)

        # Choose a node based on service, avoiding NAT+Firewall on same node
        node = None
        on_router = False
        if svc.upper() == "NAT":
            # Prefer routers without NAT and without Firewall rules
            candidates = [r for r in (routers or []) if r.node_id not in nat_nodes_taken and r.node_id not in fw_nodes_taken]
            if not candidates:
                candidates = [r for r in (routers or []) if r.node_id not in nat_nodes_taken]
            # Spread across unused nodes if possible
            unused = [r for r in candidates if r.node_id not in used_nodes]
            pick_from = unused or candidates
            if pick_from:
                node = random.choice(pick_from)
                on_router = True
                logger.debug("Segmentation slot %d: NAT on router %s", idx + 1, node.node_id)
            else:
                logger.debug("No eligible router for NAT (avoiding NAT+Firewall overlap); skipping slot")
                continue
        elif svc.upper() == "CUSTOM":
            # Custom can go on routers or hosts; prefer unused nodes
            if routers:
                avail = [r for r in routers if r.node_id not in used_nodes]
                if avail:
                    node = random.choice(avail)
                    on_router = True
                    logger.debug("Segmentation slot %d: CUSTOM on router %s", idx + 1, node.node_id)
            if node is None:
                if include_hosts and hosts:
                    avail = [h for h in hosts if h.node_id not in used_nodes]
                    node = random.choice(avail if avail else hosts)
                    on_router = False
                    logger.debug("Segmentation slot %d: CUSTOM on host %s", idx + 1, node.node_id)
                else:
                    # fallback to routers only if not including hosts
                    if routers:
                        node = random.choice(routers)
                        on_router = True
                        logger.debug("Segmentation slot %d: CUSTOM fallback on router %s", idx + 1, node.node_id)
                    else:
                        logger.debug("No eligible nodes for CUSTOM; skipping slot")
                        continue
        else:
            # Firewall: avoid nodes with NAT
            if routers:
                candidates = [r for r in routers if r.node_id not in nat_nodes_taken]
                unused = [r for r in candidates if r.node_id not in used_nodes]
                pick_from = unused or candidates
                if pick_from:
                    node = random.choice(pick_from)
                    on_router = True
                    logger.debug("Segmentation slot %d: Firewall on router %s", idx + 1, node.node_id)
            if node is None and include_hosts:
                candidates = [h for h in hosts if h.node_id not in nat_nodes_taken]
                unused = [h for h in candidates if h.node_id not in used_nodes]
                pick_from = unused or candidates or hosts
                node = random.choice(pick_from)
                on_router = False
                logger.debug("Segmentation slot %d: Firewall on host %s", idx + 1, node.node_id)

        # Build commands/script via plugin or defaults
        if svc.upper() == "CUSTOM":
            # Use plugin to generate a script body; fall back to a no-op logger
            plugin = seg_plugins.get()
            if plugin:
                try:
                    script_body = plugin(node, on_router, nets, hosts)
                    rule = {"type": "custom", "svc": svc, "node": node.node_id}
                    rtype = "custom"
                except Exception as e:
                    logger.warning("Custom segmentation plugin failed for node %s: %s", node.node_id, e)
                    # Fall back to a simple LOG rule so there is at least an artifact
                    chain = "FORWARD" if on_router else "INPUT"
                    script_body = f"""#!/usr/bin/env python3
import subprocess, shlex
cmds = [
    "iptables -A {chain} -j LOG --log-prefix '[custom-seg]'",
]
for c in cmds:
    try:
        subprocess.check_call(shlex.split(c))
    except Exception:
        pass
print('[segmentation] applied', len(cmds), 'commands')
"""
                    rule = {"type": "custom", "svc": svc, "node": node.node_id, "fallback": True}
                    rtype = "custom"
            else:
                chain = "FORWARD" if on_router else "INPUT"
                script_body = f"""#!/usr/bin/env python3
import subprocess, shlex
cmds = [
    "iptables -A {chain} -j LOG --log-prefix '[custom-seg]'",
]
for c in cmds:
    try:
        subprocess.check_call(shlex.split(c))
    except Exception:
        pass
print('[segmentation] applied', len(cmds), 'commands')
"""
                rule = {"type": "custom", "svc": svc, "node": node.node_id, "fallback": True}
                rtype = "custom"
            # Write the custom script
            key = (node.node_id, rtype)
            cnt = counters.get(key, 1)
            counters[key] = cnt + 1
            script_name = f"seg_{rtype}_{node.node_id}_{cnt}.py"
            script_path = os.path.join(out_dir, script_name)
            try:
                with open(script_path, "w", encoding="utf-8") as f:
                    f.write(script_body if script_body.endswith("\n") else script_body + "\n")
                os.chmod(script_path, 0o755)
                logger.debug("Segmentation: wrote custom script %s for node %s", script_name, node.node_id)
            except Exception as e:
                logger.debug("Failed to write custom policy script for node %s: %s", node.node_id, e)
        else:
            # NAT: set up basic SNAT on router from an internal subnet to an external subnet
            if svc.upper() == "NAT":
                cmd_list: List[str] = []
                rule = {"type": "nat", "svc": svc, "node": node.node_id}
                # Enforce at most one NAT per node: try reassigning to a router without NAT; skip if none
                if node.node_id in nat_nodes_taken or node.node_id in fw_nodes_taken:
                    if routers:
                        alt = [r for r in routers if r.node_id not in nat_nodes_taken and r.node_id not in fw_nodes_taken]
                        if alt:
                            node = random.choice(alt)
                            on_router = True
                            rule["node"] = node.node_id
                        else:
                            logger.debug("Skipping NAT on node %s: NAT already present or node has Firewall on all routers", node.node_id)
                            continue
                    else:
                        logger.debug("Skipping NAT on host node %s: NAT not applicable and already present", node.node_id)
                        continue
                # Only meaningful on routers
                if on_router and nets:
                    # pick an internal subnet as the one with most hosts
                    # and an external subnet as any other (or 0.0.0.0/0 if none)
                    try:
                        # Determine internal as largest group
                        internal = max(subnets.items(), key=lambda kv: len(kv[1]))[0]
                    except Exception:
                        internal = nets[0]
                    others = [n for n in nets if n != internal]
                    external = random.choice(others) if others else None
                    # router ip to use for SNAT
                    router_ip = (node.ip4 or "").split("/", 1)[0]
                    mode = (nat_mode or "SNAT").strip().upper()
                    if external:
                        rule.update({"internal": internal, "external": external, "mode": mode, "egress_ip": router_ip})
                        if mode == "MASQUERADE":
                            cmd_list.append(
                                f"iptables -t nat -A POSTROUTING -s {internal} -d {external} -j MASQUERADE"
                            )
                        else:  # SNAT
                            cmd_list.append(
                                f"iptables -t nat -A POSTROUTING -s {internal} -d {external} -j SNAT --to-source {router_ip}"
                            )
                    else:
                        # Single subnet case: egress to anywhere
                        rule.update({"internal": internal, "external": "0.0.0.0/0", "mode": mode, "egress_ip": router_ip})
                        if mode == "MASQUERADE":
                            cmd_list.append(
                                f"iptables -t nat -A POSTROUTING -s {internal} -j MASQUERADE"
                            )
                        else:
                            cmd_list.append(
                                f"iptables -t nat -A POSTROUTING -s {internal} -j SNAT --to-source {router_ip}"
                            )
                else:
                    # Do not apply NAT on hosts; skip this slot
                    logger.debug("Skipping NAT on non-router node %s", node.node_id)
                    continue

                # If we have a real NAT rule, dedupe against already seen
                nat_key: Optional[Tuple[int, str, str, str, str]] = None
                rinfo = rule or {}
                if (rinfo.get("type") or "").lower() == "nat" and rinfo.get("internal"):
                    nat_key = (
                        int(node.node_id),
                        str(rinfo.get("internal")),
                        str(rinfo.get("external") or "0.0.0.0/0"),
                        str(rinfo.get("mode") or "SNAT").upper(),
                        str(rinfo.get("egress_ip") or ""),
                    )

                if nat_key and nat_key in seen_nat_rules:
                    # Skip writing duplicate NAT rule/script
                    logger.debug("Skipping duplicate NAT rule for node %s: %s", node.node_id, nat_key)
                    # Ensure service is still enabled
                    try:
                        to_enable = SERVICE_ENABLE_MAP.get(svc, svc)
                        ok = ensure_service(session, node.node_id, to_enable)
                        if not ok:
                            logger.warning("Unable to add segmentation service %s on node %s", to_enable, node.node_id)
                    except Exception as e:
                        logger.warning("Error enabling segmentation service on node %s: %s", node.node_id, e)
                    # Move to next slot
                    continue

                # Write NAT script (also enforce default-deny on FORWARD and allow ESTABLISHED/RELATED)
                rtype = rule.get("type", "rule")
                key = (node.node_id, rtype)
                cnt = counters.get(key, 1)
                counters[key] = cnt + 1
                script_name = f"seg_{rtype}_{node.node_id}_{cnt}.py"
                script_path = os.path.join(out_dir, script_name)
                # Build an idempotent script: set default policy to DROP on FORWARD and ensure stateful accept, then NAT rules
                py_lines = [
                    "#!/usr/bin/env python3",
                    "import subprocess, shlex",
                    "def run(cmd: str):",
                    "    try:",
                    "        subprocess.check_call(shlex.split(cmd))",
                    "    except Exception:",
                    "        pass",
                    "def build_check(cmd: str) -> str:",
                    "    tokens = shlex.split(cmd)",
                    "    out = []",
                    "    i = 0",
                    "    while i < len(tokens):",
                    "        t = tokens[i]",
                    "        if t == 'iptables':",
                    "            out.append(t)",
                    "        elif t == '-A' or t == '-I':",
                    "            out.append('-C')",
                    "            if i + 1 < len(tokens):",
                    "                out.append(tokens[i+1])",
                    "                i += 1",
                    "                if t == '-I' and i + 1 < len(tokens) and tokens[i+1].isdigit():",
                    "                    i += 1",
                    "        else:",
                    "            out.append(t)",
                    "        i += 1",
                    "    return ' '.join(out)",
                    "def ensure_rule(cmd: str):",
                    "    check_cmd = build_check(cmd)",
                    "    try:",
                    "        subprocess.check_call(shlex.split(check_cmd))",
                    "        return False",
                    "    except Exception:",
                    "        pass",
                    "    try:",
                    "        subprocess.check_call(shlex.split(cmd))",
                    "        return True",
                    "    except Exception:",
                    "        return False",
                    "# Enforce default deny on FORWARD and allow established/related",
                    "run('iptables -P FORWARD DROP')",
                    "ensure_rule('iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT')",
                    "rules = [",
                ]
                for c in cmd_list:
                    py_lines.append(f"    \"{c}\",")
                py_lines += [
                    "]",
                    "applied = 0",
                    "for cmd in rules:",
                    "    if ensure_rule(cmd):",
                    "        applied += 1",
                    "print('[segmentation-nat] applied', applied, 'new rules (idempotent), default FORWARD policy set to DROP')",
                ]
                try:
                    with open(script_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(py_lines) + "\n")
                    os.chmod(script_path, 0o755)
                except Exception as e:
                    logger.debug("Failed to write NAT policy script for node %s: %s", node.node_id, e)
                # Ensure service for NAT (maps to Firewall)
                try:
                    to_enable = SERVICE_ENABLE_MAP.get(svc, svc)
                    ok = ensure_service(session, node.node_id, to_enable)
                    if not ok:
                        logger.warning("Unable to add segmentation service %s on node %s", to_enable, node.node_id)
                    else:
                        logger.info("Segmentation: enabled %s on node %s", to_enable, node.node_id)
                except Exception as e:
                    logger.warning("Error enabling segmentation service on node %s: %s", node.node_id, e)
                # Mark default-deny presence in the summary so allow-rule logic can react
                rule["default_deny"] = True
                summary["rules"].append({
                    "node_id": node.node_id,
                    "service": SERVICE_ENABLE_MAP.get(svc, svc),
                    "rule": rule,
                    "script": script_path,
                })
                used_nodes.add(node.node_id)
                # Track the NAT rule to avoid duplicates within this run
                if nat_key:
                    seen_nat_rules.add(nat_key)
                # Mark this node as having NAT to enforce one-per-node
                try:
                    nat_nodes_taken.add(int(node.node_id))
                except Exception:
                    pass
                # Skip the rest of the loop for NAT
                continue

            # Default rule construction for Firewall selection
            rule_type = random.choices(
                ["subnet_block", "host_block", "protect_internal"], weights=[5, 3, 2]
            )[0]
            # Build commands list; will be executed by a generated Python script
            cmd_list: List[str] = []
            chain_fw = "FORWARD" if on_router else "INPUT"

            # Basic overlap avoidance using coverage from earlier in this run
            def _cidr_contains(cidr: str, ip: str) -> bool:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    addr = ipaddress.ip_address(ip)
                    return addr in net
                except Exception:
                    return False

            if rule_type == "subnet_block" and len(nets) >= 2:
                src_net, dst_net = random.sample(nets, 2)
                # Skip if covered by existing protect_internal on this node/chain
                if on_router and dst_net in fw_index[int(node.node_id)]["protect_internal"]:
                    # Any non-internal -> internal is already blocked
                    try:
                        logger.debug("Skip subnet_block on node %s: covered by protect_internal %s", node.node_id, dst_net)
                    except Exception:
                        pass
                    rule = {"type": "none", "svc": svc, "node": node.node_id}
                else:
                    if on_router:
                        # Deduplicate identical pair
                        key_pair = (src_net, dst_net)
                        if key_pair in fw_index[int(node.node_id)]["subnet_block_forward"]:
                            rule = {"type": "none", "svc": svc, "node": node.node_id}
                        else:
                            cmd_list.append(f"iptables -A FORWARD -s {src_net} -d {dst_net} -j DROP")
                            rule = {"type": "subnet_block", "svc": svc, "node": node.node_id, "src": src_net, "dst": dst_net}
                            fw_index[int(node.node_id)]["subnet_block_forward"].add(key_pair)
                    else:
                        # host-level: block inbound from src_net
                        if src_net in fw_index[int(node.node_id)]["subnet_block_input"]:
                            rule = {"type": "none", "svc": svc, "node": node.node_id}
                        else:
                            cmd_list.append(f"iptables -A INPUT -s {src_net} -j DROP")
                            rule = {"type": "subnet_block", "svc": svc, "node": node.node_id, "src": src_net, "dst": dst_net}
                            fw_index[int(node.node_id)]["subnet_block_input"].add(src_net)
            elif rule_type == "host_block" and len(hosts) >= 2:
                a, b = random.sample(hosts, 2)
                a_ip = a.ip4.split("/")[0]
                b_ip = b.ip4.split("/")[0]
                chain = "FORWARD" if on_router else "INPUT"
                key_pair = (a_ip, b_ip)
                idx_key = "host_block_forward" if on_router else "host_block_input"
                if key_pair in fw_index[int(node.node_id)][idx_key]:
                    rule = {"type": "none", "svc": svc, "node": node.node_id}
                else:
                    cmd_list.append(f"iptables -A {chain} -s {a_ip} -d {b_ip} -j DROP")
                    rule = {"type": "host_block", "svc": svc, "node": node.node_id, "src": a_ip, "dst": b_ip}
                    fw_index[int(node.node_id)][idx_key].add(key_pair)
            else:
                # protect_internal: pick one subnet, block from all others to it
                if nets:
                    internal = random.choice(nets)
                    # Only one protect_internal per internal subnet per node
                    if internal in fw_index[int(node.node_id)]["protect_internal"]:
                        rule = {"type": "none", "svc": svc, "node": node.node_id}
                    else:
                        if on_router:
                            cmd_list.append(f"iptables -A FORWARD ! -s {internal} -d {internal} -j DROP")
                        else:
                            cmd_list.append(f"iptables -A INPUT ! -s {internal} -j DROP")
                        rule = {"type": "protect_internal", "svc": svc, "node": node.node_id, "subnet": internal}
                        fw_index[int(node.node_id)]["protect_internal"].add(internal)
                else:
                    rule = {"type": "none", "svc": svc, "node": node.node_id}

            # Write Python script as /tmp/segmentation/<type>_<nodeID>_<number>.py
            rtype = rule.get("type", "rule")
            key = (node.node_id, rtype)
            cnt = counters.get(key, 1)
            counters[key] = cnt + 1
            script_name = f"seg_{rtype}_{node.node_id}_{cnt}.py"
            script_path = os.path.join(out_dir, script_name)
            # Make firewall scripts idempotent and enforce default deny on relevant chain
            py_lines = [
                "#!/usr/bin/env python3",
                "import subprocess, shlex",
                "def run(cmd: str):",
                "    try:",
                "        subprocess.check_call(shlex.split(cmd))",
                "    except Exception:",
                "        pass",
                "def build_check(cmd: str) -> str:",
                "    tokens = shlex.split(cmd)",
                "    out = []",
                "    i = 0",
                "    while i < len(tokens):",
                "        t = tokens[i]",
                "        if t == 'iptables':",
                "            out.append(t)",
                "        elif t == '-A' or t == '-I':",
                "            out.append('-C')",
                "            if i + 1 < len(tokens):",
                "                out.append(tokens[i+1])",
                "                i += 1",
                "                if t == '-I' and i + 1 < len(tokens) and tokens[i+1].isdigit():",
                "                    i += 1",
                "        else:",
                "            out.append(t)",
                "        i += 1",
                "    return ' '.join(out)",
                "def ensure_rule(cmd: str):",
                "    check_cmd = build_check(cmd)",
                "    try:",
                "        subprocess.check_call(shlex.split(check_cmd))",
                "        return False",
                "    except Exception:",
                "        pass",
                "    try:",
                "        subprocess.check_call(shlex.split(cmd))",
                "        return True",
                "    except Exception:",
                "        return False",
            ]
            # Set default deny and stateful accept for the chain in use
            if chain_fw in ("FORWARD", "INPUT"):
                py_lines += [
                    f"run('iptables -P {chain_fw} DROP')",
                    f"ensure_rule('iptables -A {chain_fw} -m state --state ESTABLISHED,RELATED -j ACCEPT')",
                ]
            py_lines += [
                "rules = [",
            ]
            for c in cmd_list:
                py_lines.append(f"    \"{c}\",")
            py_lines += [
                "]",
                "applied = 0",
                "for cmd in rules:",
                "    if ensure_rule(cmd):",
                "        applied += 1",
                f"print('[segmentation-{chain_fw.lower()}] applied', applied, 'new rules (idempotent), default {chain_fw} policy set to DROP')",
            ]
            try:
                with open(script_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(py_lines) + "\n")
                os.chmod(script_path, 0o755)
                logger.debug("Segmentation: wrote %s for node %s", script_name, node.node_id)
            except Exception as e:
                logger.debug("Failed to write policy script for node %s: %s", node.node_id, e)

        # Ensure the chosen service is enabled only on routers; hosts should not be assigned the Segmentation service
        try:
            # Enable Segmentation only on routers by default; if include_hosts is True, allow hosts too
            if svc.upper() != "CUSTOM" and (on_router or include_hosts):
                to_enable = SERVICE_ENABLE_MAP.get(svc, svc)
                ok = ensure_service(session, node.node_id, to_enable)
                if not ok:
                    logger.warning("Unable to add segmentation service %s on node %s", to_enable, node.node_id)
                else:
                    logger.info("Segmentation: enabled %s on node %s", to_enable, node.node_id)
        except Exception as e:
            logger.warning("Error enabling segmentation service on node %s: %s", node.node_id, e)

        # Record non-NAT/CUSTOM rule for this node
        if (rule.get("type") or "") not in ("none",):
            # Annotate default-deny chain for allow logic to recognize
            try:
                if chain_fw in ("FORWARD", "INPUT"):
                    rule["default_deny"] = True
                    rule["chain"] = chain_fw
            except Exception:
                pass
        summary["rules"].append({
            "node_id": node.node_id,
            "service": (SERVICE_ENABLE_MAP.get(svc, svc) if svc.upper() != "CUSTOM" else "CUSTOM"),
            "rule": rule,
            "script": script_path,
        })
        used_nodes.add(node.node_id)
        # Mark firewall nodes to avoid mixing with NAT later in the same run
        rtype_l = (rule.get("type") or "").lower()
        if rtype_l in ("subnet_block", "host_block", "protect_internal"):
            try:
                fw_nodes_taken.add(int(node.node_id))
            except Exception:
                pass

    # Summary logging similar to traffic
    try:
        total_rules = len(summary.get("rules", []))
        nat_rules = sum(1 for r in summary.get("rules", []) if (r.get("rule", {}) or {}).get("type") == "nat")
        fw_rules = sum(1 for r in summary.get("rules", []) if (r.get("rule", {}) or {}).get("type") in ("subnet_block", "host_block", "protect_internal"))
        custom_rules = sum(1 for r in summary.get("rules", []) if (r.get("rule", {}) or {}).get("type") == "custom")
        nodes_affected = len({r.get("node_id") for r in summary.get("rules", [])})
        logger.info(
            "Segmentation scripts written to %s (rules=%d on %d nodes; NAT=%d; FW=%d; CUSTOM=%d; slots=%d)",
            out_dir, total_rules, nodes_affected, nat_rules, fw_rules, custom_rules, slots,
        )
    except Exception:
        logger.info("Segmentation planned and applied: %d rules across %d slots", len(summary["rules"]), slots)
    # Write machine-readable summary
    try:
        import json
        with open(os.path.join(out_dir, "segmentation_summary.json"), "w", encoding="utf-8") as jf:
            json.dump(summary, jf, indent=2)
    except Exception:
        pass
    return summary


def write_allow_rules_for_flows(
    session: object,
    routers: List[NodeInfo],
    hosts: List[NodeInfo],
    traffic_summary_path: str,
    out_dir: str = "/tmp/segmentation",
    src_subnet_prob: float = 0.3,
    dst_subnet_prob: float = 0.3,
    include_hosts: bool = False,
) -> Dict[str, object]:
    """
    Ensure generated traffic can flow by inserting iptables ACCEPT rules on endpoints and routers,
    but only when such rules would open flows that are currently blocked by existing segmentation
    policies (subnet/host/protect_internal drops). If the path is already allowed by default,
    no allow rules are inserted.

    For each flow in traffic_summary.json:
    - Receiver host: INPUT accept from src to dst port/proto
    - Sender host: OUTPUT accept to dst port/proto
    - Routers (if any): FORWARD accept for src->dst port/proto

    Returns a dict with list of created rule entries similar to segmentation summary format.
    """
    import json

    os.makedirs(out_dir, exist_ok=True)
    try:
        with open(traffic_summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        flows = data.get("flows", []) or []
    except Exception:
        flows = []

    if not flows:
        logger.info("Segmentation-Allow: no flows found; skipping allow rule generation")
        return {"rules": []}

    # Load existing segmentation summary to identify blocking rules
    summary_path = os.path.join(out_dir, "segmentation_summary.json")
    existing_rules: List[dict] = []
    try:
        if os.path.exists(summary_path):
            with open(summary_path, "r", encoding="utf-8") as jf:
                data_sum = json.load(jf) or {}
                existing_rules = data_sum.get("rules", []) or []
    except Exception:
        existing_rules = []

    # Build a set of seen allow rules to dedupe across runs
    # Key: (node_id, chain, proto, src, dst, port)
    seen_allow: set[Tuple[int, str, str, str, str, int]] = set()
    # Coverage index to prevent overlapping rules. Key: (node_id, chain, proto, port) -> [(src_sel, dst_sel)]
    from collections import defaultdict
    coverage_index: Dict[Tuple[int, str, str, int], List[Tuple[str, str]]] = defaultdict(list)
    for rr in existing_rules:
        r = (rr.get("rule") or {})
        if (r.get("type") or "").lower() == "allow":
            try:
                nid = int(rr.get("node_id"))
            except Exception:
                continue
            chain = str(r.get("chain") or "").upper()
            proto = str(r.get("proto") or "").lower()
            srcv = str(r.get("src") or "")
            dstv = str(r.get("dst") or "")
            try:
                portv = int(r.get("port")) if r.get("port") is not None else -1
            except Exception:
                portv = -1
            seen_allow.add((nid, chain, proto, srcv, dstv, portv))
            coverage_index[(nid, chain, proto, portv)].append((srcv, dstv))

    def cidr_contains(cidr: str, ip: str) -> bool:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            addr = ipaddress.ip_address(ip)
            return addr in net
        except Exception:
            return False

    # Determine if a flow is blocked by any existing DROP-style rule we generate
    # Detect default-deny on FORWARD (from NAT or firewall setup) and on host INPUT from existing summary
    default_deny_forward = False
    default_deny_input_nodes: set[int] = set()
    for rr in existing_rules:
        r = rr.get("rule", {}) or {}
        try:
            if (r.get("type") or "").lower() == "nat" and r.get("default_deny"):
                default_deny_forward = True
            # firewall entries annotated with default_deny and chain
            if (r.get("default_deny") and str(r.get("chain")).upper() == "INPUT"):
                nid = int(rr.get("node_id")) if rr.get("node_id") is not None else None
                if nid is not None:
                    default_deny_input_nodes.add(nid)
        except Exception:
            pass

    def same_subnet_24(a: str, b: str) -> bool:
        try:
            na = ipaddress.ip_network(f"{a}/24", strict=False)
            nb = ipaddress.ip_network(f"{b}/24", strict=False)
            return na.network_address == nb.network_address
        except Exception:
            return False

    def is_flow_blocked(src_ip: str, dst_ip: str, recv_node_id: Optional[int]) -> bool:
        for rr in existing_rules:
            r = rr.get("rule", {}) or {}
            rtype = (r.get("type") or "").lower()
            if rtype == "subnet_block":
                snet = r.get("src"); dnet = r.get("dst")
                if snet and dnet and cidr_contains(snet, src_ip) and cidr_contains(dnet, dst_ip):
                    return True
            elif rtype == "host_block":
                rs = r.get("src"); rd = r.get("dst")
                if rs and rd and rs == src_ip and rd == dst_ip:
                    return True
            elif rtype == "protect_internal":
                internal = r.get("subnet")
                if internal:
                    # Router-level protects: block any non-internal -> internal
                    if (not cidr_contains(internal, src_ip)) and cidr_contains(internal, dst_ip):
                        return True
            # Other types (nat/custom/none) do not block
        # If default-deny on FORWARD is enabled, treat inter-subnet flows as blocked
        if default_deny_forward and not same_subnet_24(src_ip, dst_ip):
            return True
        # If receiver host has INPUT default-deny, inbound flows require explicit allow
        try:
            if recv_node_id is not None and int(recv_node_id) in default_deny_input_nodes:
                return True
        except Exception:
            pass
        return False

    # Helpers for selector coverage
    def _to_network(sel: str):
        try:
            if not sel:
                return None
            if "/" in sel:
                return ipaddress.ip_network(sel, strict=False)
            # treat single IP as /32
            return ipaddress.ip_network(f"{sel}/32", strict=False)
        except Exception:
            return None

    def _covers(sel_super: str, sel_sub: str) -> bool:
        if not sel_super or not sel_sub:
            return False
        if sel_super == sel_sub:
            return True
        net_super = _to_network(sel_super)
        if net_super is None:
            return False
        # If sub is IP
        try:
            ip_sub = ipaddress.ip_address(sel_sub)
            return ip_sub in net_super
        except Exception:
            pass
        # If sub is network
        net_sub = _to_network(sel_sub)
        if net_sub is None:
            return False
        # net_sub is covered if all its addresses are within net_super
        return (net_sub.network_address in net_super) and (net_sub.broadcast_address in net_super)

    def _covering_pair(nid: int, chain: str, proto: str, port: int, src_sel: str, dst_sel: str) -> Optional[Tuple[str, str]]:
        pairs = coverage_index.get((nid, chain, proto, port), [])
        for (s_sup, d_sup) in pairs:
            if _covers(s_sup, src_sel) and _covers(d_sup, dst_sel):
                return (s_sup, d_sup)
        return None

    # Map node id to NodeInfo and IP address (strip mask)
    host_map: Dict[int, NodeInfo] = {h.node_id: h for h in (hosts or [])}
    def ip_only(s: Optional[str]) -> str:
        if not s:
            return ""
        return s.split("/", 1)[0]
    def subnet_of(node: Optional[NodeInfo]) -> str:
        if not node or not node.ip4:
            return ""
        try:
            # accept either ip/mask or ip; default /24 if missing
            if "/" in node.ip4:
                net = ipaddress.ip_network(node.ip4, strict=False)
            else:
                net = ipaddress.ip_network(f"{node.ip4}/24", strict=False)
            return str(net)
        except Exception:
            # conservative fallback: host /32
            ip = ip_only(node.ip4)
            return f"{ip}/32" if ip else ""

    rules_out: List[dict] = []
    counters: Dict[Tuple[int, str], int] = {}

    router_ids = {int(r.node_id) for r in (routers or [])}
    host_ids = {int(h.node_id) for h in (hosts or [])}

    def _write_script(node_id: int, commands: List[str]) -> str:
        key = (node_id, "allow")
        cnt = counters.get(key, 1)
        counters[key] = cnt + 1
        script_name = f"seg_allow_{node_id}_{cnt}.py"
        script_path = os.path.join(out_dir, script_name)
        py_lines = [
            "#!/usr/bin/env python3",
            "import subprocess, shlex",
            "def build_check(cmd: str) -> str:",
            "    # Replace -A/-I with -C and drop index after chain if present",
            "    tokens = shlex.split(cmd)",
            "    out = []",
            "    i = 0",
            "    while i < len(tokens):",
            "        t = tokens[i]",
            "        if t == 'iptables':",
            "            out.append(t)",
            "        elif t == '-A' or t == '-I':",
            "            out.append('-C')",
            "            # next token is chain",
            "            if i + 1 < len(tokens):",
            "                out.append(tokens[i+1])",
            "                i += 1",
            "                # if original was -I and there's a position index, skip it",
            "                if t == '-I' and i + 1 < len(tokens) and tokens[i+1].isdigit():",
            "                    i += 1",
            "        else:",
            "            out.append(t)",
            "        i += 1",
            "    return ' '.join(out)",
            "rules = [",
        ]
        for c in commands:
            py_lines.append(f"    \"{c}\",")
        py_lines += [
            "]",
            "applied = 0",
            "for cmd in rules:",
            "    check_cmd = build_check(cmd)",
            "    try:",
            "        subprocess.check_call(shlex.split(check_cmd))",
            "        # exists; skip",
            "        continue",
            "    except Exception:",
            "        pass",
            "    try:",
            "        subprocess.check_call(shlex.split(cmd))",
            "        applied += 1",
            "    except Exception:",
            "        pass",
            "print('[segmentation-allow] applied', applied, 'new rules (idempotent)')",
        ]
        try:
            with open(script_path, "w", encoding="utf-8") as f:
                f.write("\n".join(py_lines) + "\n")
            os.chmod(script_path, 0o755)
        except Exception:
            pass
        # Ensure Segmentation service is enabled on routers, and optionally hosts if include_hosts=True
        try:
            nid = int(node_id)
            if nid in router_ids or (include_hosts and nid in host_ids):
                ensure_service(session, nid, "Segmentation")
        except Exception:
            pass
        return script_path

    for flow in flows:
        src_id = flow.get("src_id")
        dst_id = flow.get("dst_id")
        proto = (flow.get("protocol") or "").lower()
        dst_ip = ip_only(flow.get("dst_ip"))
        dst_port = flow.get("dst_port")
        if not src_id or not dst_id or not dst_ip or not dst_port or proto not in ("tcp", "udp"):
            continue
        src_host = host_map.get(int(src_id))
        dst_host = host_map.get(int(dst_id))
        if not src_host or not dst_host:
            continue
        src_ip = ip_only(src_host.ip4)

        # Randomly widen to subnet on src and/or dst
        use_src_subnet = random.random() < max(0.0, min(1.0, float(src_subnet_prob)))
        use_dst_subnet = random.random() < max(0.0, min(1.0, float(dst_subnet_prob)))
        src_sel = subnet_of(src_host) if use_src_subnet else src_ip
        dst_sel = subnet_of(dst_host) if use_dst_subnet else dst_ip

        # Only add allow rules if currently blocked by segmentation policies
        if is_flow_blocked(src_ip, dst_ip, int(dst_host.node_id)):
            # Receiver INPUT allow
            recv_key = (int(dst_host.node_id), 'INPUT', proto, src_sel, dst_sel, int(dst_port))
            covering = _covering_pair(int(dst_host.node_id), 'INPUT', proto, int(dst_port), src_sel, dst_sel)
            if recv_key not in seen_allow and covering is None:
                recv_cmds = [
                    f"iptables -I INPUT 1 -p {proto} -s {src_sel} --dport {dst_port} -j ACCEPT",
                ]
                recv_script = _write_script(dst_host.node_id, recv_cmds)
                rules_out.append({
                    "node_id": dst_host.node_id,
                    "service": "Segmentation",
                    "rule": {"type": "allow", "src": src_sel, "dst": dst_sel, "proto": proto, "port": dst_port, "chain": "INPUT"},
                    "script": recv_script,
                })
                seen_allow.add(recv_key)
                coverage_index[(int(dst_host.node_id), 'INPUT', proto, int(dst_port))].append((src_sel, dst_sel))
            elif covering is not None:
                try:
                    logger.debug(
                        "Allow skip (covered): node=%s chain=INPUT proto=%s port=%s src=%s dst=%s by src=%s dst=%s",
                        int(dst_host.node_id), proto, int(dst_port), src_sel, dst_sel, covering[0], covering[1]
                    )
                except Exception:
                    pass

            # Sender OUTPUT allow
            send_key = (int(src_host.node_id), 'OUTPUT', proto, src_sel, dst_sel, int(dst_port))
            covering = _covering_pair(int(src_host.node_id), 'OUTPUT', proto, int(dst_port), src_sel, dst_sel)
            if send_key not in seen_allow and covering is None:
                send_cmds = [
                    f"iptables -I OUTPUT 1 -p {proto} -d {dst_sel} --dport {dst_port} -j ACCEPT",
                ]
                send_script = _write_script(src_host.node_id, send_cmds)
                rules_out.append({
                    "node_id": src_host.node_id,
                    "service": "Segmentation",
                    "rule": {"type": "allow", "src": src_sel, "dst": dst_sel, "proto": proto, "port": dst_port, "chain": "OUTPUT"},
                    "script": send_script,
                })
                seen_allow.add(send_key)
                coverage_index[(int(src_host.node_id), 'OUTPUT', proto, int(dst_port))].append((src_sel, dst_sel))
            elif covering is not None:
                try:
                    logger.debug(
                        "Allow skip (covered): node=%s chain=OUTPUT proto=%s port=%s src=%s dst=%s by src=%s dst=%s",
                        int(src_host.node_id), proto, int(dst_port), src_sel, dst_sel, covering[0], covering[1]
                    )
                except Exception:
                    pass

            # Routers FORWARD allow (insert at top for precedence)
            for r in (routers or []):
                fwd_key = (int(r.node_id), 'FORWARD', proto, src_sel, dst_sel, int(dst_port))
                covering = _covering_pair(int(r.node_id), 'FORWARD', proto, int(dst_port), src_sel, dst_sel)
                if fwd_key in seen_allow or covering is not None:
                    continue
                fwd_cmds = [
                    f"iptables -I FORWARD 1 -p {proto} -s {src_sel} -d {dst_sel} --dport {dst_port} -j ACCEPT",
                ]
                fwd_script = _write_script(r.node_id, fwd_cmds)
                rules_out.append({
                    "node_id": r.node_id,
                    "service": "Segmentation",
                    "rule": {"type": "allow", "src": src_sel, "dst": dst_sel, "proto": proto, "port": dst_port, "chain": "FORWARD"},
                    "script": fwd_script,
                })
                seen_allow.add(fwd_key)
                coverage_index[(int(r.node_id), 'FORWARD', proto, int(dst_port))].append((src_sel, dst_sel))

    # Summary logging before writing
    try:
        nodes_set = {r.get("node_id") for r in rules_out}
        logger.info(
            "Segmentation-Allow: inserted %d allow rules across %d nodes",
            len(rules_out), len(nodes_set),
        )
    except Exception:
        pass
    # Append to segmentation_summary.json if present, else create a new one
    try:
        import json
        summary_path = os.path.join(out_dir, "segmentation_summary.json")
        base = {"rules": []}
        if os.path.exists(summary_path):
            with open(summary_path, "r", encoding="utf-8") as jf:
                base = json.load(jf) or base
            if not isinstance(base, dict):
                base = {"rules": []}
        base.setdefault("rules", [])
        base["rules"].extend(rules_out)
        with open(summary_path, "w", encoding="utf-8") as jf:
            json.dump(base, jf, indent=2)
    except Exception:
        pass

    return {"rules": rules_out}


def write_dnat_for_flows(
    session: object,
    routers: List[NodeInfo],
    hosts: List[NodeInfo],
    traffic_summary_path: str,
    out_dir: str = "/tmp/segmentation",
    dnat_prob: float = 0.3,
) -> Dict[str, object]:
    """
    Create DNAT port-forwarding rules on routers for a subset of generated traffic flows.

    For selected flows (by probability), add on each router:
    - PREROUTING DNAT: router_ip:dst_port -> dst_ip:dst_port
    - FORWARD ACCEPT: allow traffic to dst_ip:dst_port

    Returns a dict with created rule entries.
    """
    import json

    os.makedirs(out_dir, exist_ok=True)
    try:
        with open(traffic_summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        flows = data.get("flows", []) or []
    except Exception:
        flows = []

    if not flows or not routers:
        logger.info("Segmentation-DNAT: no eligible flows/routers; skipping DNAT generation")
        return {"rules": []}

    # Helpers
    def ip_only(s: Optional[str]) -> str:
        if not s:
            return ""
        return s.split("/", 1)[0]

    rules_out: List[dict] = []
    counters: Dict[Tuple[int, str], int] = {}

    # Build dedupe set for DNAT rules from existing summary
    try:
        import json as _json
        summary_path = os.path.join(out_dir, "segmentation_summary.json")
        seen_dnat: set[Tuple[int, str, str, int]] = set()
        if os.path.exists(summary_path):
            with open(summary_path, "r", encoding="utf-8") as jf:
                base = _json.load(jf) or {}
            for rr in (base.get("rules") or []):
                r = (rr.get("rule") or {})
                if (r.get("type") or "").lower() == "dnat":
                    try:
                        nid = int(rr.get("node_id"))
                    except Exception:
                        continue
                    proto = str(r.get("proto") or "").lower()
                    dip = str(r.get("dst") or "")
                    try:
                        portv = int(r.get("port")) if r.get("port") is not None else -1
                    except Exception:
                        portv = -1
                    seen_dnat.add((nid, proto, dip, portv))
    except Exception:
        seen_dnat = set()

    def _write_script(node_id: int, commands: List[str]) -> str:
        key = (node_id, "dnat")
        cnt = counters.get(key, 1)
        counters[key] = cnt + 1
        script_name = f"seg_dnat_{node_id}_{cnt}.py"
        script_path = os.path.join(out_dir, script_name)
        py_lines = [
            "#!/usr/bin/env python3",
            "import subprocess, shlex",
            "def build_check(cmd: str) -> str:",
            "    tokens = shlex.split(cmd)",
            "    out = []",
            "    i = 0",
            "    while i < len(tokens):",
            "        t = tokens[i]",
            "        if t == 'iptables':",
            "            out.append(t)",
            "        elif t == '-A' or t == '-I':",
            "            out.append('-C')",
            "            if i + 1 < len(tokens):",
            "                out.append(tokens[i+1])",
            "                i += 1",
            "                if t == '-I' and i + 1 < len(tokens) and tokens[i+1].isdigit():",
            "                    i += 1",
            "        else:",
            "            out.append(t)",
            "        i += 1",
            "    return ' '.join(out)",
            "rules = [",
        ]
        for c in commands:
            py_lines.append(f"    \"{c}\",")
        py_lines += [
            "]",
            "applied = 0",
            "for cmd in rules:",
            "    check_cmd = build_check(cmd)",
            "    try:",
            "        subprocess.check_call(shlex.split(check_cmd))",
            "        continue",
            "    except Exception:",
            "        pass",
            "    try:",
            "        subprocess.check_call(shlex.split(cmd))",
            "        applied += 1",
            "    except Exception:",
            "        pass",
            "print('[segmentation-dnat] applied', applied, 'new rules (idempotent)')",
        ]
        try:
            with open(script_path, "w", encoding="utf-8") as f:
                f.write("\n".join(py_lines) + "\n")
            os.chmod(script_path, 0o755)
        except Exception:
            pass
        # Ensure Segmentation service is enabled only on routers for DNAT rules
        try:
            ensure_service(session, int(node_id), "Segmentation")
        except Exception:
            pass
        return script_path

    # For each flow, select and generate DNAT rules with some probability
    for flow in flows:
        if random.random() > max(0.0, min(1.0, float(dnat_prob))):
            continue
        proto = (flow.get("protocol") or "").lower()
        if proto not in ("tcp", "udp"):
            continue
        dst_ip = ip_only(flow.get("dst_ip"))
        dst_port = flow.get("dst_port")
        if not dst_ip or not dst_port:
            continue
        for r in (routers or []):
            router_ip = ip_only(getattr(r, "ip4", ""))
            if not router_ip:
                continue
            dkey = (int(r.node_id), proto, dst_ip, int(dst_port))
            if dkey in seen_dnat:
                continue
            cmds = [
                f"iptables -t nat -A PREROUTING -p {proto} -d {router_ip} --dport {dst_port} -j DNAT --to-destination {dst_ip}:{dst_port}",
                f"iptables -I FORWARD 1 -p {proto} -d {dst_ip} --dport {dst_port} -j ACCEPT",
            ]
            script = _write_script(r.node_id, cmds)
            rules_out.append({
                "node_id": r.node_id,
                "service": "Segmentation",
                "rule": {"type": "dnat", "router_ip": router_ip, "dst": dst_ip, "port": dst_port, "proto": proto},
                "script": script,
            })
            seen_dnat.add(dkey)

    # Summary logging before writing
    try:
        nodes_set = {r.get("node_id") for r in rules_out}
        logger.info(
            "Segmentation-DNAT: inserted %d DNAT rules across %d routers (prob=%.2f)",
            len(rules_out), len(nodes_set), float(dnat_prob),
        )
    except Exception:
        pass
    # Append to segmentation_summary.json
    try:
        import json
        summary_path = os.path.join(out_dir, "segmentation_summary.json")
        base = {"rules": []}
        if os.path.exists(summary_path):
            with open(summary_path, "r", encoding="utf-8") as jf:
                base = json.load(jf) or base
            if not isinstance(base, dict):
                base = {"rules": []}
        base.setdefault("rules", [])
        base["rules"].extend(rules_out)
        with open(summary_path, "w", encoding="utf-8") as jf:
            json.dump(base, jf, indent=2)
    except Exception:
        pass

    return {"rules": rules_out}

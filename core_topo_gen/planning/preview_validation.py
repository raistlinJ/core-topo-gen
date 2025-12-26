from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from ..constants import DEFAULT_IPV4_PREFIXLEN


_SUBNET_KEYS: Tuple[str, ...] = (
    "ptp_subnets",
    "router_switch_subnets",
    "lan_subnets",
    "r2r_subnets",
)


def validate_full_preview(preview: Dict[str, Any]) -> List[str]:
    """Validate internal consistency of a full preview payload.

    Returns a list of human-readable issues. Empty list means OK.

    Invariants checked (intentionally minimal and fast):
    - All subnets are valid IPv4 networks and use DEFAULT_IPV4_PREFIXLEN.
        - No duplicate subnet CIDRs across ptp/r2r/router-switch subnet lists.
            (lan_subnets may mirror router_switch_subnets under the single-subnet R2S policy.)
        - Switch details: rsw_subnet and lan_subnet match (single shared subnet);
            router/switch IPs and host_if_ips belong to that shared subnet.
    - R2R link details: per-router interface IPs belong to the declared link subnet.
    """

    issues: List[str] = []
    if not isinstance(preview, dict):
        return ["preview is not a dict"]

    # Only enforce global uniqueness for subnets that should not overlap across lists.
    # Under the single-subnet router-to-switch policy, lan_subnets may intentionally
    # mirror router_switch_subnets.
    all_subnets: List[str] = []
    for key in _SUBNET_KEYS:
        subnets = preview.get(key) or []
        if not isinstance(subnets, list):
            issues.append(f"{key} is not a list")
            continue
        for raw in subnets:
            s = str(raw)
            if key != "lan_subnets":
                all_subnets.append(s)
            try:
                net = ipaddress.ip_network(s, strict=False)
            except Exception as e:
                issues.append(f"{key} invalid subnet {s}: {e}")
                continue
            if getattr(net, "version", None) != 4:
                issues.append(f"{key} non-IPv4 subnet {s}")
            elif net.prefixlen != DEFAULT_IPV4_PREFIXLEN:
                issues.append(f"{key} has non-/{DEFAULT_IPV4_PREFIXLEN}: {s}")

    if len(all_subnets) != len(set(all_subnets)):
        seen: set[str] = set()
        dups: set[str] = set()
        for s in all_subnets:
            if s in seen:
                dups.add(s)
            else:
                seen.add(s)
        issues.append(f"duplicate subnet(s): {sorted(dups)[:20]}")

    # Switch details
    switches_detail = preview.get("switches_detail") or []
    if isinstance(switches_detail, list):
        for detail in switches_detail:
            if not isinstance(detail, dict):
                issues.append("switches_detail contains non-dict")
                continue
            switch_id = detail.get("switch_id")
            rsw = detail.get("rsw_subnet")
            lan = detail.get("lan_subnet")
            if not rsw or not lan:
                issues.append(f"switch {switch_id} missing rsw_subnet/lan_subnet")
                continue
            try:
                rsw_net = ipaddress.ip_network(str(rsw), strict=False)
                lan_net = ipaddress.ip_network(str(lan), strict=False)
            except Exception as e:
                issues.append(f"switch {switch_id} invalid subnet: {e}")
                continue

            if rsw_net.network_address != lan_net.network_address or rsw_net.prefixlen != lan_net.prefixlen:
                issues.append(f"switch {switch_id} subnet mismatch: rsw_subnet={rsw_net} lan_subnet={lan_net}")

            shared_net = rsw_net

            # router_ip is required; switch_ip is optional (switches are L2).
            router_ip_cidr = detail.get("router_ip")
            if not router_ip_cidr:
                issues.append(f"switch {switch_id} missing router_ip")
            else:
                try:
                    iface = ipaddress.ip_interface(str(router_ip_cidr))
                    if iface.ip not in shared_net:
                        issues.append(f"switch {switch_id} router_ip {router_ip_cidr} not in {shared_net}")
                except Exception as e:
                    issues.append(f"switch {switch_id} bad router_ip {router_ip_cidr}: {e}")

            switch_ip_cidr = detail.get("switch_ip")
            if switch_ip_cidr:
                try:
                    iface = ipaddress.ip_interface(str(switch_ip_cidr))
                    if iface.ip not in shared_net:
                        issues.append(f"switch {switch_id} switch_ip {switch_ip_cidr} not in {shared_net}")
                except Exception as e:
                    issues.append(f"switch {switch_id} bad switch_ip {switch_ip_cidr}: {e}")

            host_if_ips = detail.get("host_if_ips") or {}
            if isinstance(host_if_ips, dict):
                for host_id, ip_cidr in host_if_ips.items():
                    if not ip_cidr:
                        continue
                    try:
                        iface = ipaddress.ip_interface(str(ip_cidr))
                    except Exception as e:
                        issues.append(f"switch {switch_id} host {host_id} bad ip {ip_cidr}: {e}")
                        continue
                    if iface.ip not in shared_net:
                        issues.append(f"switch {switch_id} host {host_id} ip {ip_cidr} not in {shared_net}")
            else:
                issues.append(f"switch {switch_id} host_if_ips is not a dict")

    # R2R links
    links = preview.get("r2r_links_preview") or []
    if isinstance(links, list):
        for link in links:
            if not isinstance(link, dict):
                issues.append("r2r_links_preview contains non-dict")
                continue
            subnet = link.get("subnet")
            if not subnet:
                continue
            try:
                net = ipaddress.ip_network(str(subnet), strict=False)
            except Exception as e:
                issues.append(f"r2r invalid subnet {subnet}: {e}")
                continue
            routers = link.get("routers") or []
            if not isinstance(routers, list):
                continue
            for r in routers:
                if not isinstance(r, dict):
                    continue
                ip_cidr = r.get("ip")
                if not ip_cidr:
                    continue
                try:
                    iface = ipaddress.ip_interface(str(ip_cidr))
                except Exception as e:
                    issues.append(f"r2r bad ip {ip_cidr}: {e}")
                    continue
                if iface.ip not in net:
                    issues.append(f"r2r ip {ip_cidr} not in {net}")

    return issues


def assert_full_preview_valid(preview: Dict[str, Any]) -> None:
    issues = validate_full_preview(preview)
    if issues:
        raise ValueError("Full preview validation failed: " + "; ".join(issues))

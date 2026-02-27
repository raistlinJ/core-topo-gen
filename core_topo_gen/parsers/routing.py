from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple
from ..types import RoutingInfo
from .common import find_scenario

logger = logging.getLogger(__name__)


def parse_routing_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[RoutingInfo]]:
    density = 0.0
    items: List[RoutingInfo] = []
    if not os.path.exists(xml_path):
        logger.warning("XML not found for routing parse: %s", xml_path)
        return density, items
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML for routing (%s)", e)
        return density, items
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found for routing parse")
        return density, items
    section = scenario.find(".//section[@name='Routing']")
    if section is None:
        return density, items
    den_raw = (section.get("density") or "").strip()
    if den_raw:
        try:
            density = float(den_raw)
            if density < 0:
                density = 0.0
        except Exception:
            logger.warning("Invalid Routing density '%s'", den_raw)
            density = 0.0
    count_total = 0
    count_items_meta = []  # (proto,count,r2r_mode,edges,r2s_mode,r2s_edges,hmin,hmax)
    weight_items = []      # (proto,factor,r2r_mode,edges,r2s_mode,r2s_edges,hmin,hmax)
    for it in section.findall("./item"):
        proto = (it.get("selected") or "").strip()
        if not proto:
            continue
        vm = (it.get("v_metric") or "").strip()
        r2r_mode = (it.get("r2r_mode") or "").strip()
        r2s_mode = (it.get("r2s_mode") or "").strip()
        edges_raw = (it.get("r2r_edges") or "").strip()
        r2s_edges_raw = (it.get("r2s_edges") or "").strip()
        def _int_attr(raw: str) -> int:
            if not raw: return 0
            try:
                v = int(raw)
                return v if v >= 0 else 0
            except Exception:
                return 0
        edges_val = _int_attr(edges_raw)
        r2s_edges_val = _int_attr(r2s_edges_raw)
        r2s_hmin = _int_attr((it.get("r2s_hosts_min") or "").strip())
        r2s_hmax = _int_attr((it.get("r2s_hosts_max") or "").strip())
        if vm == "Count":
            try:
                vc = int((it.get("v_count") or "0").strip())
            except Exception:
                vc = 0
            if vc > 0:
                count_items_meta.append((proto, vc, r2r_mode, edges_val, r2s_mode, r2s_edges_val, r2s_hmin, r2s_hmax))
                count_total += vc
        else:
            try:
                f = float((it.get("factor") or "0").strip())
            except Exception:
                f = 0.0
            if f > 0:
                weight_items.append((proto, f, r2r_mode, edges_val, r2s_mode, r2s_edges_val, r2s_hmin, r2s_hmax))
    if count_total > 0 and count_items_meta:
        for p,c,rm,re,sm,se,hmin,hmax in count_items_meta:
            items.append(RoutingInfo(protocol=p, factor=0.0, abs_count=c, r2r_mode=rm, r2r_edges=re, r2s_mode=sm, r2s_edges=se, r2s_hosts_min=hmin, r2s_hosts_max=hmax))

    if count_total <= 0 and not weight_items:
        fallback_count = 0
        try:
            total_planned_raw = (section.get("total_planned") or "").strip()
            if total_planned_raw:
                fallback_count = max(0, int(total_planned_raw))
        except Exception:
            fallback_count = 0

        if fallback_count <= 0:
            try:
                min_enabled = str(section.get("node_count_min_enabled") or "").strip().lower() in {"1", "true", "yes", "on"}
                max_enabled = str(section.get("node_count_max_enabled") or "").strip().lower() in {"1", "true", "yes", "on"}
                min_val = int((section.get("node_count_min") or "0").strip() or 0) if min_enabled else 0
                max_val = int((section.get("node_count_max") or "0").strip() or 0) if max_enabled else 0
                min_val = max(0, min_val)
                max_val = max(0, max_val)
                if min_enabled and max_enabled and max_val and max_val < min_val:
                    min_val, max_val = max_val, min_val
                if min_enabled:
                    fallback_count = min_val
                elif max_enabled:
                    fallback_count = max_val
            except Exception:
                fallback_count = 0

        if fallback_count > 0:
            items.append(RoutingInfo(protocol="Routing", factor=0.0, abs_count=fallback_count, r2r_mode="", r2r_edges=0, r2s_mode="", r2s_edges=0, r2s_hosts_min=0, r2s_hosts_max=0))

    if weight_items:
        for p,f,rm,re,sm,se,hmin,hmax in weight_items:
            items.append(RoutingInfo(protocol=p, factor=f, abs_count=0, r2r_mode=rm, r2r_edges=re, r2s_mode=sm, r2s_edges=se, r2s_hosts_min=hmin, r2s_hosts_max=hmax))
    if not items:
        density = 0.0
    logger.debug("Parsed routing: density=%s items=%s", density, [(i.protocol, i.factor) for i in items])
    return density, items

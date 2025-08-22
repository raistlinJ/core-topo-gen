from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
from ..types import ServiceInfo, RoutingInfo, TrafficInfo

logger = logging.getLogger(__name__)


def _find_scenario(root: ET.Element, scenario_name: Optional[str]) -> Optional[ET.Element]:
    scenarios = root.findall(".//Scenario")
    if not scenarios:
        return None
    if scenario_name:
        for s in scenarios:
            if s.get("name") == scenario_name:
                return s
    return scenarios[0]


def parse_services(scenario: ET.Element) -> List[ServiceInfo]:
    services: List[ServiceInfo] = []
    section = scenario.find(".//section[@name='Services']")
    if section is not None:
        den_section_raw = (section.get("density") or "").strip()
        if not den_section_raw:
            logger.warning("'Services' section missing 'density'; no services will be assigned from this section")
        try:
            section_density = float(den_section_raw) if den_section_raw else 0.0
        except Exception:
            logger.warning("'Services' section has invalid 'density' value '%s'", den_section_raw)
            section_density = 0.0
        for it in section.findall("./item"):
            name = (it.get("selected") or "").strip()
            if not name:
                continue
            try:
                factor = float((it.get("factor") or "0").strip())
            except Exception:
                factor = 0.0
            if it.get("density"):
                logger.warning("Ignoring item-level 'density' for service '%s'; using section-level density", name)
            if factor > 0 and section_density > 0:
                services.append(ServiceInfo(name=name, factor=factor, density=section_density))
    return services


def parse_node_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[int, List[Tuple[str, float]], List[ServiceInfo]]:
    default_count = 5
    default_items = [("Workstation", 1.0)]
    if not os.path.exists(xml_path):
        logger.warning("XML file not found: %s; defaulting total_nodes=%s, items=%s", xml_path, default_count, default_items)
        return default_count, default_items, []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML (%s); defaulting values", e)
        return default_count, default_items, []
    scenario = _find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found; defaulting values")
        return default_count, default_items, []
    section = scenario.find(".//section[@name='Node Information']")
    if section is None:
        logger.warning("'Node Information' section not found; defaulting values")
        return default_count, default_items, []
    total_str = section.get("total_nodes", "").strip()
    try:
        total = int(total_str)
        if total <= 0:
            raise ValueError
    except Exception:
        logger.warning("Invalid total_nodes='%s'; defaulting to %s", total_str, default_count)
        total = default_count
    items_el = section.findall("./item")
    parsed: List[Tuple[str, float]] = []
    for it in items_el:
        role = (it.get("selected") or "").strip()
        factor_str = (it.get("factor") or "").strip()
        if not role:
            continue
        try:
            factor = float(factor_str)
        except Exception:
            factor = 0.0
        if factor < 0:
            factor = 0.0
        parsed.append((role, factor))
    if not parsed:
        parsed = default_items
    services = []
    if scenario is not None:
        services = parse_services(scenario)
    return total, parsed, services


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
    scenario = _find_scenario(root, scenario_name)
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
            if density > 1:
                density = 1.0
        except Exception:
            logger.warning("Invalid Routing density '%s'", den_raw)
            density = 0.0
    for it in section.findall("./item"):
        proto = (it.get("selected") or "").strip()
        if not proto:
            continue
        try:
            factor = float((it.get("factor") or "0").strip())
        except Exception:
            factor = 0.0
        if factor > 0:
            items.append(RoutingInfo(protocol=proto, factor=factor))
    logger.debug("Parsed routing: density=%s items=%s", density, [(i.protocol, i.factor) for i in items])
    return density, items


def parse_traffic_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[TrafficInfo]]:
    """Parse the Traffic section density and item factors.

    Returns (density, [TrafficInfo(kind, factor), ...]).
    """
    density = 0.0
    items: List[TrafficInfo] = []
    if not os.path.exists(xml_path):
        logger.warning("XML not found for traffic parse: %s", xml_path)
        return density, items
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML for traffic (%s)", e)
        return density, items
    scenario = _find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found for traffic parse")
        return density, items
    section = scenario.find(".//section[@name='Traffic']")
    if section is None:
        return density, items
    den_raw = (section.get("density") or "").strip()
    if den_raw:
        try:
            density = float(den_raw)
            density = max(0.0, min(1.0, density))
        except Exception:
            logger.warning("Invalid Traffic density '%s'", den_raw)
            density = 0.0
    for it in section.findall("./item"):
        kind = (it.get("selected") or "").strip()
        if not kind:
            continue
        try:
            factor = float((it.get("factor") or "0").strip())
        except Exception:
            factor = 0.0
        # optional attributes for realistic traffic
        pattern = (it.get("pattern") or "").strip()
        # rate is expected in KB/s
        try:
            rate_kbps = float((it.get("rate") or it.get("rate_kbps") or "0").strip())
        except Exception:
            rate_kbps = 0.0
        try:
            period_s = float((it.get("period") or it.get("period_s") or "0").strip())
        except Exception:
            period_s = 0.0
        try:
            jitter_pct = float((it.get("jitter") or it.get("jitter_pct") or "0").strip())
        except Exception:
            jitter_pct = 0.0
        content_type = (it.get("content") or it.get("content_type") or "").strip()
        # clamp / sanitize
        rate_kbps = max(0.0, rate_kbps)
        period_s = max(0.0, period_s)
        jitter_pct = max(0.0, min(100.0, jitter_pct))
        if factor > 0:
            items.append(TrafficInfo(
                kind=kind,
                factor=factor,
                pattern=pattern,
                rate_kbps=rate_kbps,
                period_s=period_s if period_s > 0 else 10.0,
                jitter_pct=jitter_pct,
                content_type=content_type,
            ))
    logger.debug("Parsed traffic: density=%s items=%s", density, [
        (i.kind, i.factor, i.pattern, i.rate_kbps, i.period_s, i.jitter_pct) for i in items
    ])
    return density, items

from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from ..types import ServiceInfo, RoutingInfo, TrafficInfo
from ..types import SegmentationInfo

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
            # Do not clamp upper bound here; density >= 1 will be treated as absolute count downstream
            section_density = float(den_section_raw) if den_section_raw else 0.0
            if section_density < 0:
                section_density = 0.0
        except Exception:
            logger.warning("'Services' section has invalid 'density' value '%s'", den_section_raw)
            section_density = 0.0
        for it in section.findall("./item"):
            name = (it.get("selected") or "").strip()
            # Drop legacy/invalid 'auto' outright (no backward compatibility)
            if name.lower() == "auto":
                logger.warning("Skipping legacy Services item 'auto' (not supported)")
                continue
            if not name:
                continue
            try:
                factor = float((it.get("factor") or "0").strip())
            except Exception:
                factor = 0.0
            # Support per-item Count via v_metric/v_count
            vm = (it.get("v_metric") or "").strip()
            vc_raw = (it.get("v_count") or "").strip()
            count_override: Optional[int] = None
            if vm == "Count" and vc_raw:
                try:
                    vc = int(vc_raw)
                    if vc >= 0:
                        count_override = vc
                except Exception:
                    count_override = None
            if it.get("density"):
                logger.warning("Ignoring item-level 'density' for service '%s'; using section-level density or count override", name)
            # When count_override is provided, encode it in density as an absolute count; otherwise use section density
            item_density = float(count_override) if count_override is not None else section_density
            if factor > 0 and (item_density > 0 or (count_override is not None and count_override == 0)):
                services.append(ServiceInfo(name=name, factor=factor, density=item_density, abs_count=(count_override or 0)))
    return services


def parse_node_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[int, List[Tuple[str, float]], List[Tuple[str, int]], List[ServiceInfo]]:
    """Parse the Node Information section.

    Returns a 4‑tuple:
        (density_base_count, weight_items, count_items, services)

    Where:
    density_base_count: int base host count ("Count for Density") distributed across weight_items.
        weight_items: [(role, factor), ...] un-normalized factors for proportional allocation.
        count_items: [(role, absolute_count), ...] additive explicit host rows.
        services: ServiceInfo list parsed from the Services section (for convenience).
    """
    # Default base host pool (Count for Density) now 10 to match updated UI default.
    default_count = 10
    default_items = [("Workstation", 1.0)]
    if not os.path.exists(xml_path):
        logger.warning("XML file not found: %s; defaulting total_nodes=%s, items=%s", xml_path, default_count, default_items)
        return default_count, default_items, [], []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML (%s); defaulting values", e)
        return default_count, default_items, [], []
    scenario = _find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found; defaulting values")
        return default_count, default_items, [], []
    section = scenario.find(".//section[@name='Node Information']")
    if section is None:
        logger.warning("'Node Information' section not found; defaulting values")
        return default_count, default_items, [], []
    # Determine density base (Count for Density) with compatibility layers.
    # Priority order (first present, even if zero, wins):
    #   1. Scenario-level attribute density_count
    #   2. Section-level attributes: density_count, base_nodes, total_nodes (legacy)
    # If ALL are ABSENT (not present / empty), fall back to default_count (10).
    density_base: Optional[int] = None
    try:
        scen_attr = scenario.get("density_count") if scenario is not None else None
        if scen_attr is not None and str(scen_attr).strip() != "":
            density_base = int(str(scen_attr).strip())
        else:
            for raw in [section.get("density_count"), section.get("base_nodes"), section.get("total_nodes")]:
                if raw is None:
                    continue
                s = str(raw).strip()
                if not s:
                    continue
                try:
                    density_base = int(s)
                    break
                except Exception:
                    continue
    except Exception:
        # Treat parse failures as absence and let fallback apply
        density_base = None
    if density_base is None:
        density_base = default_count
    if density_base < 0:
        density_base = 0
    items_el = section.findall("./item")
    count_map: Dict[str, int] = {}
    weight_items: List[Tuple[str, float]] = []
    for it in items_el:
        role = (it.get("selected") or "").strip() or "Workstation"
        vm = (it.get("v_metric") or "").strip()
        if vm == "Count":
            try:
                vc = int((it.get("v_count") or "0").strip())
            except Exception:
                vc = 0
            if vc > 0:
                count_map[role] = count_map.get(role, 0) + vc
            continue
        try:
            f = float((it.get("factor") or "0").strip())
        except Exception:
            f = 0.0
        if f > 0:
            weight_items.append((role, f))
    # Density model now normalizes weight factors to 1.0 externally; if no explicit base provided keep 0 (base not auto-created here).
    # If no rows at all, nothing to distribute (keep density_base but without weights it will be ignored by callers)
    count_items = [(r, c) for r, c in sorted(count_map.items())]
    services: List[ServiceInfo] = parse_services(scenario)
    return density_base, weight_items, count_items, services


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
        except Exception:
            logger.warning("Invalid Routing density '%s'", den_raw)
            density = 0.0
    # Inspect items; if any Count-based entries exist, use them to set absolute router count
    count_total = 0
    count_items: List[Tuple[str, int]] = []
    weight_items: List[Tuple[str, float]] = []
    for it in section.findall("./item"):
        proto = (it.get("selected") or "").strip()
        if not proto:
            continue
        vm = (it.get("v_metric") or "").strip()
        edges_mode = (it.get("edges_mode") or "").strip()
        # Support legacy attribute name 'edges' for Exact mode
        edges_raw = (it.get("edges") or "").strip()
        edges_val = 0
        if edges_raw:
            try:
                ev = int(edges_raw)
                if ev >= 0:
                    edges_val = ev
            except Exception:
                edges_val = 0
        if vm == "Count":
            try:
                vc = int((it.get("v_count") or "0").strip())
            except Exception:
                vc = 0
            if vc > 0:
                count_items.append((proto, vc))  # edges attributes ignored for count planning
                count_total += vc
        else:
            try:
                f = float((it.get("factor") or "0").strip())
            except Exception:
                f = 0.0
            if f > 0:
                # Temporarily store in weight_items; edges planning handled after consolidated list built
                weight_items.append((proto, f, edges_mode, edges_val))
    if count_total > 0:
        items = [RoutingInfo(protocol=p, factor=0.0, abs_count=c) for p, c in count_items]
    if weight_items:
        for rec in weight_items:
            if len(rec) == 2:  # backward safety
                p, f = rec
                items.append(RoutingInfo(protocol=p, factor=f, abs_count=0))
            else:
                p, f, em, ev = rec
                items.append(RoutingInfo(protocol=p, factor=f, abs_count=0, edges_mode=em, edges=ev))
    # If neither density nor counts nor weight items, result is empty list (0 routers)
    if not items:
        density = 0.0
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
        # Count override per item
        vm = (it.get("v_metric") or "").strip()
        abs_count = 0
        if vm == "Count":
            try:
                vc = int((it.get("v_count") or "0").strip())
                if vc >= 0:
                    abs_count = vc
            except Exception:
                abs_count = 0
        if factor > 0 or abs_count > 0:
            items.append(TrafficInfo(
                kind=kind,
                factor=factor,
                pattern=pattern,
                rate_kbps=rate_kbps,
                period_s=period_s if period_s > 0 else 10.0,
                jitter_pct=jitter_pct,
                content_type=content_type,
                abs_count=abs_count,
            ))
    logger.debug("Parsed traffic: density=%s items=%s", density, [
        (i.kind, i.factor, i.pattern, i.rate_kbps, i.period_s, i.jitter_pct) for i in items
    ])
    return density, items


def parse_segmentation_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[SegmentationInfo]]:
    """Parse the Segmentation section density and item factors.

    Returns (density, [SegmentationInfo(name, factor), ...]).
    """
    density = 0.0
    items: List[SegmentationInfo] = []
    if not os.path.exists(xml_path):
        logger.warning("XML not found for segmentation parse: %s", xml_path)
        return density, items
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML for segmentation (%s)", e)
        return density, items
    scenario = _find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found for segmentation parse")
        return density, items
    section = scenario.find(".//section[@name='Segmentation']")
    if section is None:
        return density, items
    den_raw = (section.get("density") or "").strip()
    if den_raw:
        try:
            density = float(den_raw)
            # Do not clamp upper bound; >=1.0 will be treated as absolute slot count downstream
            if density < 0:
                density = 0.0
        except Exception:
            logger.warning("Invalid Segmentation density '%s'", den_raw)
            density = 0.0
    for it in section.findall("./item"):
        name = (it.get("selected") or "").strip()
        if not name:
            continue
        try:
            factor = float((it.get("factor") or "0").strip())
        except Exception:
            factor = 0.0
        vm = (it.get("v_metric") or "").strip()
        abs_count = 0
        if vm == "Count":
            try:
                vc = int((it.get("v_count") or "0").strip())
                if vc >= 0:
                    abs_count = vc
            except Exception:
                abs_count = 0
        if factor > 0 or abs_count > 0:
            items.append(SegmentationInfo(name=name, factor=factor, abs_count=abs_count))
    logger.debug("Parsed segmentation: density=%s items=%s", density, [(i.name, i.factor) for i in items])
    return density, items


def parse_vulnerabilities_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[dict]]:
    """Parse the Vulnerabilities section.

    Returns (density, items) where items are dictionaries including keys:
        selected, factor, and depending on mode possibly v_type, v_vector, v_name, v_path, v_count
    """
    density = 0.0
    items: List[dict] = []
    if not os.path.exists(xml_path):
        logger.warning("XML not found for vulnerabilities parse: %s", xml_path)
        return density, items
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML for vulnerabilities (%s)", e)
        return density, items
    scenario = _find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found for vulnerabilities parse")
        return density, items
    section = scenario.find(".//section[@name='Vulnerabilities']")
    if section is None:
        return density, items
    den_raw = (section.get("density") or "").strip()
    if den_raw:
        try:
            density = float(den_raw)
            density = max(0.0, min(1.0, density))
        except Exception:
            logger.warning("Invalid Vulnerabilities density '%s'", den_raw)
            density = 0.0
    for it in section.findall("./item"):
        selected = (it.get("selected") or "").strip() or "Random"
        try:
            factor = float((it.get("factor") or "0").strip())
        except Exception:
            factor = 0.0
        rec: dict = {"selected": selected, "factor": factor}
        vm = (it.get("v_metric") or "").strip()
        if vm:
            rec["v_metric"] = vm
        if selected == "Type/Vector":
            vt = (it.get("v_type") or "").strip()
            vv = (it.get("v_vector") or "").strip()
            if vt:
                rec["v_type"] = vt
            if vv:
                rec["v_vector"] = vv
        elif selected == "Specific":
            vn = (it.get("v_name") or "").strip()
            vp = (it.get("v_path") or "").strip()
            vc_raw = (it.get("v_count") or "").strip()
            if vn:
                rec["v_name"] = vn
            if vp:
                rec["v_path"] = vp
            try:
                if vc_raw:
                    rec["v_count"] = int(vc_raw)
            except Exception:
                pass
        # Keep items regardless of factor to reflect UI faithfully
        items.append(rec)
    logger.debug("Parsed vulnerabilities: density=%s items=%s", density, items)
    return density, items


def parse_planning_metadata(xml_path: str, scenario_name: Optional[str]) -> Dict[str, Dict[str, Union[int, float]]]:
    """Parse additive planning metadata attributes written by the web UI.

    The writer (webapp/app_backend.py:_build_scenarios_xml) persists additional
    attributes on sections to allow lossless round‑trip of planning semantics.
    This helper returns a nested dictionary with any discovered metadata. If
    attributes are missing (older XML), it will derive sensible fallback values
    from existing parse_* helpers without attempting to reconstruct values that
    require information not encoded in legacy XML (e.g. derived router count
    without a host pool reference).

    Returned structure (keys optional depending on presence):
        {
          'scenario': {
              'scenario_total_nodes': int,   # scenario-level aggregate if written
          },
          'node_info': {
              'base_nodes': int,
              'additive_nodes': int,
              'combined_nodes': int,
              'weight_rows': int,
              'count_rows': int,
              'weight_sum': float,
          },
          'routing': {
              'explicit_count': int,
              'derived_count': int,
              'total_planned': int,
              'weight_rows': int,
              'count_rows': int,
              'weight_sum': float,
          },
          'vulnerabilities': { ... same fields as routing ... }
        }
    """
    meta: Dict[str, Dict[str, Union[int, float]]] = {}
    if not os.path.exists(xml_path):
        return meta
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return meta
    scenario = _find_scenario(root, scenario_name)
    if scenario is None:
        return meta

    # Scenario level aggregate (new attribute scenario_total_nodes)
    scen_total_raw = scenario.get('scenario_total_nodes')
    scen_total: Optional[int] = None
    if scen_total_raw is not None:
        try:
            scen_total = int(str(scen_total_raw).strip())
        except Exception:
            scen_total = None
    if scen_total is not None:
        meta['scenario'] = {'scenario_total_nodes': scen_total}

    def _int(val: Optional[str]) -> Optional[int]:
        if val is None or val == "":
            return None
        try:
            return int(val)
        except Exception:
            return None

    def _float(val: Optional[str]) -> Optional[float]:
        if val is None or val == "":
            return None
        try:
            return float(val)
        except Exception:
            return None

    # Node Information
    ni = scenario.find(".//section[@name='Node Information']")
    if ni is not None:
        base_nodes = _int(ni.get("base_nodes"))
        additive_nodes = _int(ni.get("additive_nodes"))
        combined_nodes = _int(ni.get("combined_nodes"))
        weight_rows = _int(ni.get("weight_rows"))
        count_rows = _int(ni.get("count_rows"))
        weight_sum = _float(ni.get("weight_sum"))
        # Fallback derivation if any critical values missing
        if base_nodes is None or additive_nodes is None or combined_nodes is None:
            density_base, weight_items, count_items, _ = parse_node_info(xml_path, scenario_name)
            # density_base corresponds to base_nodes (distributed across weight rows)
            if base_nodes is None:
                base_nodes = density_base
            if additive_nodes is None:
                additive_nodes = sum(c for _r, c in count_items)
            if combined_nodes is None:
                combined_nodes = (base_nodes or 0) + (additive_nodes or 0)
            if weight_rows is None:
                weight_rows = len(weight_items)
            if count_rows is None:
                count_rows = len(count_items)
            if weight_sum is None:
                weight_sum = float(sum(f for _r, f in weight_items))
        meta['node_info'] = {
            'base_nodes': base_nodes or 0,
            'additive_nodes': additive_nodes or 0,
            'combined_nodes': combined_nodes or ((base_nodes or 0) + (additive_nodes or 0)),
            'weight_rows': weight_rows or 0,
            'count_rows': count_rows or 0,
            'weight_sum': weight_sum or 0.0,
        }

    # Helper for routing / vulnerabilities sections
    def _parse_section(sec_name: str, key: str):
        sec = scenario.find(f".//section[@name='{sec_name}']")
        if sec is None:
            return
        explicit = _int(sec.get("explicit_count"))
        derived = _int(sec.get("derived_count"))
        total_planned = _int(sec.get("total_planned"))
        weight_rows = _int(sec.get("weight_rows"))
        count_rows = _int(sec.get("count_rows"))
        weight_sum = _float(sec.get("weight_sum"))
        # Fallback if metadata absent
        if explicit is None or total_planned is None:
            if sec_name == 'Routing':
                _density, r_items = parse_routing_info(xml_path, scenario_name)
                explicit = sum(i.abs_count for i in r_items if i.abs_count > 0) if explicit is None else explicit
                if weight_rows is None:
                    weight_rows = sum(1 for i in r_items if i.factor > 0)
                if count_rows is None:
                    count_rows = sum(1 for i in r_items if i.abs_count > 0)
                if weight_sum is None:
                    weight_sum = float(sum(i.factor for i in r_items if i.factor > 0))
            else:  # Vulnerabilities
                _density, v_items = parse_vulnerabilities_info(xml_path, scenario_name)
                # explicit vulns are those with v_count specified
                exp_counts = 0
                weight_items_cnt = 0
                weight_sum_tmp = 0.0
                for rec in v_items:
                    vm = rec.get('v_metric')
                    if rec.get('selected') == 'Specific' and 'v_count' in rec:
                        try:
                            exp_counts += int(rec['v_count'])
                        except Exception:
                            pass
                    else:
                        # treat as weight row if factor>0
                        try:
                            f = float(rec.get('factor', 0) or 0)
                        except Exception:
                            f = 0.0
                        if f > 0:
                            weight_items_cnt += 1
                            weight_sum_tmp += f
                if explicit is None:
                    explicit = exp_counts
                if weight_rows is None:
                    weight_rows = weight_items_cnt
                if count_rows is None:
                    count_rows = 0 if exp_counts == 0 else 1  # legacy XML can't distinguish multiple specific rows reliably
                if weight_sum is None:
                    weight_sum = weight_sum_tmp
        if total_planned is None and (explicit is not None) and (derived is not None):
            total_planned = explicit + derived
        if explicit is None and total_planned is not None and derived is not None:
            explicit = total_planned - derived
        if derived is None:
            derived = 0  # cannot reconstruct without host pool
        if explicit is None:
            explicit = 0
        if total_planned is None:
            total_planned = explicit + derived
        if weight_rows is None:
            weight_rows = 0
        if count_rows is None:
            count_rows = 0
        if weight_sum is None:
            weight_sum = 0.0
        meta[key] = {
            'explicit_count': explicit,
            'derived_count': derived,
            'total_planned': total_planned,
            'weight_rows': weight_rows,
            'count_rows': count_rows,
            'weight_sum': weight_sum,
        }

    _parse_section('Routing', 'routing')
    _parse_section('Vulnerabilities', 'vulnerabilities')
    return meta

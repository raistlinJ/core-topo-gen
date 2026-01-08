from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple, Dict, Union
from .common import find_scenario

logger = logging.getLogger(__name__)


def parse_vulnerabilities_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[dict]]:
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
    scenario = find_scenario(root, scenario_name)
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
        selected_raw = (it.get("selected") or "").strip() or "Random"
        # Accept UI synonym "Category" for schema label "Type/Vector".
        selected = "Type/Vector" if selected_raw == "Category" else selected_raw
        try:
            factor = float((it.get("factor") or "0").strip())
        except Exception:
            factor = 0.0
        rec: dict = {"selected": selected, "factor": factor}
        vm = (it.get("v_metric") or "").strip()
        if vm:
            rec["v_metric"] = vm
        # v_count applies whenever v_metric == Count (not only Specific)
        if vm.strip().lower() == 'count':
            vc_raw = (it.get('v_count') or '').strip()
            try:
                if vc_raw:
                    rec['v_count'] = int(vc_raw)
            except Exception:
                pass
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
            if vn:
                rec["v_name"] = vn
            if vp:
                rec["v_path"] = vp
        items.append(rec)
    logger.debug("Parsed vulnerabilities: density=%s items=%s", density, items)
    return density, items

from __future__ import annotations

from core_topo_gen.validation.xml_scenario import validate_scenario_xml


def test_validate_scenario_xml_flags_duplicate_ips_and_switch_mismatch() -> None:
    # Minimal CORE-like XML showing:
    # - router<->switch subnet 192.168.2.0/24
    # - hosts on 10.0.3.0/24 behind same switch
    # - duplicate switch-side ip4=10.0.3.1 on two links
    xml = b"""<?xml version='1.0' encoding='UTF-8'?>
<scenario>
  <networks>
    <network id=\"16\" name=\"rsw-1-1\" type=\"SWITCH\" />
  </networks>
  <devices>
    <device id=\"1\" name=\"r1\" type=\"router\" />
    <device id=\"6\" name=\"h1\" type=\"PC\" />
    <device id=\"11\" name=\"h6\" type=\"PC\" />
  </devices>
  <links>
    <link node1=\"1\" node2=\"16\">
      <iface1 id=\"0\" name=\"r1-rsw16\" ip4=\"192.168.2.1\" ip4_mask=\"24\" />
      <iface2 id=\"0\" name=\"veth16.0.1\" ip4=\"192.168.2.2\" ip4_mask=\"24\" />
    </link>
    <link node1=\"6\" node2=\"16\">
      <iface1 id=\"0\" name=\"eth0\" ip4=\"10.0.3.3\" ip4_mask=\"24\" />
      <iface2 id=\"1\" name=\"veth16.1.1\" ip4=\"10.0.3.1\" ip4_mask=\"24\" />
    </link>
    <link node1=\"11\" node2=\"16\">
      <iface1 id=\"0\" name=\"eth0\" ip4=\"10.0.3.4\" ip4_mask=\"24\" />
      <iface2 id=\"2\" name=\"veth16.2.1\" ip4=\"10.0.3.1\" ip4_mask=\"24\" />
    </link>
  </links>
</scenario>
"""

    issues = validate_scenario_xml(xml)
    codes = {i.code for i in issues}

    assert "dup_ip4" in codes
    assert "switch_subnet_mismatch" in codes

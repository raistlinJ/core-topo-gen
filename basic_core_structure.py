import xml.etree.ElementTree as ET

###
# CORE XML fixed section / element handlers 
#
# These functions add required metadata and default settings
# to the <scenario> root element for CORE.
####

###
# Adds the <session_origin> element with map location and scale.
# This defines where the scenario is centered.
##
def add_session_origin(scenario):
    ET.SubElement(scenario, "session_origin", {
        "lat": "47.579166412353516",
        "lon": "-122.13232421875",
        "alt": "2.0",
        "scale": "150.0"
    })



##
# Adds the <session_options> section.
# These are simulation settings such as networking behavior,
# control interfaces, and system preferences.
##
def add_session_options(scenario):
    session_options = ET.SubElement(scenario, "session_options")
    config_list = [
        ("controlnet", ""), ("controlnet0", ""), ("controlnet1", ""), ("controlnet2", ""), ("controlnet3", ""),
        ("controlnet_updown_script", ""), ("enablerj45", "1"), ("preservedir", "0"), ("enablesdt", "0"),
        ("sdturl", "tcp://127.0.0.1:50000/"), ("ovs", "0"), ("platform_id_start", "1"), ("nem_id_start", "1"),
        ("link_enabled", "1"), ("loss_threshold", "30"), ("link_interval", "1"), ("link_timeout", "4"),
        ("mtu", "0")
    ]
    for name, value in config_list:
        ET.SubElement(session_options, "configuration", {"name": name, "value": value})

##
# Adds the <session_metadata> element.
# This contains visual layout and canvas metadata for the GUI.
##
def add_session_metadata(scenario):
    session_metadata = ET.SubElement(scenario, "session_metadata")
    metadata = [
        ("shapes", "[]"),
        ("hidden", "[]"),
        ("edges", "[]"),
        ("canvas", "{\"gridlines\": true, \"canvases\": [{\"id\": 1, \"wallpaper\": null, \"wallpaper_style\": 1, \"fit_image\": false, \"dimensions\": [1000, 750]}]}")
    ]
    for name, value in metadata:
        ET.SubElement(session_metadata, "configuration", {"name": name, "value": value})

##
# Adds the <default_services> section that assigns core services 
# to certain types of nodes by default (ex. routers get OSPF, zebra).
##
def add_default_services(scenario):
    default_services = ET.SubElement(scenario, "default_services")

    node_data = {
        "mdr": ["zebra", "OSPFv3MDR", "IPForward"],
        "PC": ["DefaultRoute"],
        "prouter": [],
        "router": ["zebra", "OSPFv2", "OSPFv3", "IPForward"],
        "host": ["DefaultRoute", "SSH"]
    }

    for node_type, services in node_data.items():
        node = ET.SubElement(default_services, "node", {"type": node_type})
        for svc in services:
            ET.SubElement(node, "service", {"name": svc})


            
def add_mobility_configurations(scenario, device_registry):
    # Add mobility_configurations section for WIRELESS_LAN devices
    mobility_configurations = ET.Element("mobility_configurations")
    added_any = False

    for device_id, info in device_registry.items():
        if info["type"] == "WIRELESS_LAN":
            mobility = ET.SubElement(mobility_configurations, "mobility_configuration", {
                "node": str(device_id),
                "model": "basic_range"
            })

            configs = [
                ("range", "275"),
                ("bandwidth", "54000000"),
                ("jitter", "0"),
                ("delay", "5000"),
                ("error", "0.0"),
                ("promiscuous", "0")
            ]

            for name, value in configs:
                ET.SubElement(mobility, "configuration", {
                    "name": name,
                    "value": value
                })

            added_any = True

    if added_any:
        scenario.append(mobility_configurations)

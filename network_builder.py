
import xml.etree.ElementTree as ET
import random
import sys

class NetworkBuilder:

    def __init__(self, start_id=1, ip4_base="10.0.0.0", ip6_base="2001::"):
        #Begin counting devices from this value
        self.current_id = start_id
        self.ip4_base = ip4_base
        self.ip6_base = ip6_base

        # Prefix used for naming different types of networks 
        self.network_prefixes = {
            "SWITCH": "n",
            "HUB": "n",
            "WIRELESS_LAN": "wlan"
        }

        self.MIN_X = 32
        self.MAX_X = 970
        self.MIN_Y = 29
        self.MAX_Y = 719

        self.X_STEP = 160 
        self.Y_STEP = 140  
 
        # Tracks all devices created with their properties
        self.device_registry = {}

    def generate_network_tag(self, name, net_type, x, y, lat, lon):

        # Creates a <network> XML element with a <position> subelement
        network = ET.Element("network", {
            "id": str(self.current_id),
            "name": name,
            "icon": "",
            "canvas": "1",
            "type": net_type
        })
        ET.SubElement(network, "position", {
            "x": str(x),
            "y": str(y),
            "lat": str(lat),
            "lon": str(lon),
            "alt": "2.0"
        })
        return network

    def add_user_networks(self, networks_element, device_counts):

        switches = device_counts.get("SWITCH", 0)
        routers = device_counts.get("router", 0)

        if switches > routers:
            # raise ValueError("Invalid topology: number of switches exceeds number of routers.")
            print("Invalid topology: number of switches exceeds number of routers.")
            sys.exit()

        # Adds network nodes like switches, routers, etc to the scenario
        for net_type in self.network_prefixes:
            count = device_counts.get(net_type, 0)
            prefix = self.network_prefixes[net_type]
            

            for _ in range(count):
                name = f"{prefix}{self.current_id}"

                x, y = self._get_bounded_position(self.current_id)
                
                lat, lon = self.get_lat_lon(self.current_id)

                # Create and append <network> element
                tag = self.generate_network_tag(name, net_type, x, y, lat, lon)
                networks_element.append(tag)

                # Save info to the registry
                self.device_registry[self.current_id] = {
                    "name": name,
                    "type": net_type,
                    "interfaces": 0
                }
                self.current_id += 1

    def add_user_devices(self, devices_element, device_counts):

        # Adds PC and router devices, and assigns services to them
        device_types = {
            "PC": ["DefaultRoute"],
            "router": ["OSPFv3", "OSPFv2", "IPForward", "zebra"],
            "mdr":["zebra", "IPForward", "OSPFv3MDR"]
        }

        for device_type, services in device_types.items():
            count = device_counts.get(device_type, 0)

            for _ in range(count):
                name = f"n{self.current_id}"

                device = ET.Element("device", {
                    "id": str(self.current_id),
                    "name": name,
                    "icon": "",
                    "canvas": "1",
                    "type": device_type,
                    "class": "",
                    "image": ""
                })

                x, y = self._get_bounded_position(self.current_id)
                lat, lon = self.get_lat_lon(self.current_id)

                # Add position info
                ET.SubElement(device, "position", {
                    "x": str(x),
                    "y": str(y),
                    "lat": str(lat),
                    "lon": str(lon),
                    "alt": "2.0"
                })

                # Add config services like routing protocols
                configservices = ET.SubElement(device, "configservices")
                for svc in services:
                    ET.SubElement(configservices, "service", {"name": svc})

                devices_element.append(device)

                # Save info to the registry
                self.device_registry[self.current_id] = {
                    "name": name,
                    "type": device_type,
                    "interfaces": 0
                }

                self.current_id += 1
# ///////////
    def _get_subnet_prefix(self, subnet_counter):
        ip4_parts = self.ip4_base.split(".")
        ip4_prefix = f"{ip4_parts[0]}.{ip4_parts[1]}.{int(ip4_parts[2]) + subnet_counter}."

        ip6_prefix = f"{self.ip6_base.rstrip(':')}:{subnet_counter}"
        return ip4_prefix, ip6_prefix

    def generate_links(self, links_element, connections):
        subnet_counter = 1
        adjacency = {}
        deferred_lans = []  # To retry lans later

        for node1, node2 in connections:
            adjacency.setdefault(node1, []).append(node2)
            adjacency.setdefault(node2, []).append(node1)

        self.adjacency = adjacency
        linked_pairs = set()

        # First pass: Wireless and direct links
        for node1, node2 in connections:
            type1 = self.device_registry[node1]["type"].lower()
            type2 = self.device_registry[node2]["type"].lower()
            pair_key = tuple(sorted((node1, node2)))

            if "wireless_lan" in (type1, type2):
                link = self._create_wireless_link(node1, node2, subnet_counter)
                links_element.append(link)
                linked_pairs.add(pair_key)
                subnet_counter += 1

            elif self._is_direct_link(type1, type2):
                if type2 in {"router", "mdr"} and type1 not in {"router", "mdr"}:
                    node1, node2 = node2, node1
                    type1, type2 = type2, type1
                link = self._create_direct_link(node1, node2, subnet_counter)
                links_element.append(link)
                linked_pairs.add(pair_key)
                subnet_counter += 1

        # First pass: LAN links (switch/hub)
        for device_id, info in self.device_registry.items():
            device_type = info["type"].lower()
            if device_type in {"switch", "hub"} and device_id in adjacency:
                neighbors = adjacency[device_id]
                if neighbors:
                    link_group = self._create_lan_links(device_id, neighbors, subnet_counter)
                    if link_group:
                        for link in link_group:
                            node1 = int(link.attrib["node1"])
                            node2 = int(link.attrib["node2"])
                            pair_key = tuple(sorted((node1, node2)))
                            if pair_key not in linked_pairs:
                                links_element.append(link)
                                linked_pairs.add(pair_key)
                        subnet_counter += 1
                    else:
                        deferred_lans.append((device_id, neighbors))

        # Second pass: Retry deferred LANs
        for center_id, neighbors in deferred_lans:
            link_group = self._create_lan_links(center_id, neighbors, subnet_counter)
            if link_group:
                for link in link_group:
                    node1 = int(link.attrib["node1"])
                    node2 = int(link.attrib["node2"])
                    pair_key = tuple(sorted((node1, node2)))
                    if pair_key not in linked_pairs:
                        links_element.append(link)
                        linked_pairs.add(pair_key)
                subnet_counter += 1
            else:
                print(f"[Notice] Could not link switch/hub {center_id} to {neighbors} — no router or MDR available.")


    def _is_direct_link(self, type1, type2):
        # Checks PCs and routers for direct links
        valid = {"router", "pc", "mdr"}
        return type1 in valid and type2 in valid
    
    def _create_direct_link(self, node1, node2, subnet_counter):
        # Create a link element between two devices, with IP interfaces
        # ip4_prefix = f"10.0.{subnet_counter}." #TODO Change to be dynamic 
        # ip6_prefix = f"2001::{subnet_counter}"

        ip4_prefix, ip6_prefix = self._get_subnet_prefix(subnet_counter)

        iface1_id = self.device_registry[node1]["interfaces"]
        iface2_id = self.device_registry[node2]["interfaces"]

        # Build XML element
        link = ET.Element("link", {
            "node1": str(node1),
            "node2": str(node2)
        })

        iface1 = ET.Element("iface1", {
            "id": str(iface1_id),
            "name": f"eth{iface1_id}",
            "ip4": ip4_prefix + "1",
            "ip4_mask": "24",
            "ip6": ip6_prefix + "1",
            "ip6_mask": "64"
        })

        iface2 = ET.Element("iface2", {
            "id": str(iface2_id),
            "name": f"eth{iface2_id}",
            "ip4": ip4_prefix + "2",
            "ip4_mask": "24",
            "ip6": ip6_prefix + "2",
            "ip6_mask": "64"
        })

        options = ET.Element("options", {
            "delay": "0",
            "bandwidth": "0",
            "loss": "0.0",
            "dup": "0",
            "jitter": "0",
            "unidirectional": "0",
            "buffer": "0"
        })

        link.extend([iface1, iface2, options])

        # Increment interface counters for both devices
        self.device_registry[node1]["interfaces"] += 1
        self.device_registry[node2]["interfaces"] += 1

        return link
    
    def _create_lan_links(self, center_id, neighbors, subnet_counter):
        # Creates links between a switch/hub and all its neighbors using a shared subnet
        links = []
        # ip4_prefix = f"10.0.{subnet_counter}."
        # ip6_prefix = f"2001::{subnet_counter}"
        ip4_prefix, ip6_prefix = self._get_subnet_prefix(subnet_counter)

        ip_host = 1  # Host counter for IP assignments

        # Find the router if any to use as reference
       
        router_id = None
        for neighbor_id in neighbors:
            neighbor_type = self.device_registry[neighbor_id]["type"].lower()
            if neighbor_type in {"router", "mdr"}:
                router_id = neighbor_id
                break

        if not router_id:
            return links  # skip if no router to base IPs on

        # Assign IP to router first
        for node_id in neighbors:
            if node_id == router_id:
                iface_id = self.device_registry[node_id]["interfaces"]
                link = ET.Element("link", {
                    "node1": str(center_id),
                    "node2": str(node_id)
                })

                iface = ET.Element("iface2", {
                    "id": str(iface_id),
                    "name": f"eth{iface_id}",
                    "ip4": ip4_prefix + str(ip_host),
                    "ip4_mask": "24",
                    "ip6": ip6_prefix + f":{ip_host}",
                    "ip6_mask": "64"
                })

                link.append(iface)
                link.append(ET.Element("options", {
                    "delay": "0", "bandwidth": "0", "loss": "0.0",
                    "dup": "0", "jitter": "0", "unidirectional": "0", "buffer": "0"
                }))
                links.append(link)
                self.device_registry[node_id]["interfaces"] += 1
                ip_host += 1

        # Connect remaining devices
        for node_id in neighbors:
            if node_id == router_id:
                continue

            iface_id = self.device_registry[node_id]["interfaces"]
            link = ET.Element("link", {
                "node1": str(center_id),
                "node2": str(node_id)
            })

            iface = ET.Element("iface2", {
                "id": str(iface_id),
                "name": f"eth{iface_id}",
                "ip4": ip4_prefix + str(ip_host),
                "ip4_mask": "24",
                "ip6": ip6_prefix + f":{ip_host}",
                "ip6_mask": "64"
            })

            link.append(iface)
            link.append(ET.Element("options", {
                "delay": "0", "bandwidth": "0", "loss": "0.0",
                "dup": "0", "jitter": "0", "unidirectional": "0", "buffer": "0"
            }))
            links.append(link)
            self.device_registry[node_id]["interfaces"] += 1
            ip_host += 1

        return links
    

    def _create_wireless_link(self, node1, node2, subnet_counter):
        # Ensure node1 is the wireless LAN node
        if self.device_registry[node1]["type"].upper() != "WIRELESS_LAN":
            node1, node2 = node2, node1

        iface_id = self.device_registry[node2]["interfaces"]

        link = ET.Element("link", {
            "node1": str(node1),
            "node2": str(node2)
        })

        # Check if node2 is a switch
        if self.device_registry[node2]["type"].lower() == "switch" or  self.device_registry[node2]["type"].lower() == "hub":
            # iface2 for switch + WLAN connection
            iface2 = ET.Element("iface2", {
                "id": str(iface_id),
                "name": f"veth{node1}.{node2}.1"
            })
        else:
            # iface2 for other connections
            # ip4_prefix = f"10.0.{subnet_counter}."
            # ip6_prefix = f"2001:0:0:{subnet_counter}::"
            ip4_prefix, ip6_prefix = self._get_subnet_prefix(subnet_counter)


            iface2 = ET.Element("iface2", {
                "id": str(iface_id),
                "name": f"eth{iface_id}",
                "ip4": ip4_prefix + "1",
                "ip4_mask": "32",
                "ip6": f"{ip6_prefix}1",
                "ip6_mask": "128"
            })

        link.append(iface2)

        self.device_registry[node2]["interfaces"] += 1

        return link


    def add_configservice_configurations(self, parent_element):
        config_elem = ET.SubElement(parent_element, "configservice_configurations")

        for node_id, info in self.device_registry.items():
            device_type = info["type"].lower()
            
            # Map device types to their services (same as add_user_devices)
            if device_type == "router":
                services = ["OSPFv3", "OSPFv2", "IPForward", "zebra"]
            elif device_type == "mdr":
                services = ["zebra", "IPForward", "OSPFv3MDR"]
            elif device_type == "pc":
                services = ["DefaultRoute"]
            else:
                continue  # skip other types

            for svc in services:
                ET.SubElement(config_elem, "service", {
                    "name": svc,
                    "node": str(node_id)
                })


    def _get_bounded_position(self, idx):
        max_columns = (self.MAX_X - self.MIN_X) // self.X_STEP
        max_rows = (self.MAX_Y - self.MIN_Y) // self.Y_STEP
        total_slots = max_columns * max_rows

        idx = idx % total_slots  # wrap around

        row = idx // max_columns
        col = idx % max_columns

        if row % 2 == 1:
            col = max_columns - 1 - col  # snake pattern

        x = self.MIN_X + col * self.X_STEP
        y = self.MIN_Y + row * self.Y_STEP

        return float(x), float(y)
    
    def get_lat_lon(self, idx):
        max_columns = (self.MAX_X - self.MIN_X) // self.X_STEP
        max_rows = (self.MAX_Y - self.MIN_Y) // self.Y_STEP
        total_slots = max_columns * max_rows

        idx = idx % total_slots  # wrap around 

        row = idx // max_columns
        col = idx % max_columns

        if row % 2 == 1:
            col = max_columns - 1 - col

        LAT_START = 47.57889
        LAT_STEP = 0.00135

        LON_START = -122.13188
        LON_STEP = 0.00265

        latitude = LAT_START - (row * LAT_STEP)
        longitude = LON_START + (col * LON_STEP)

        return f"{latitude:.12f}", f"{longitude:.12f}"
    

    #deterministic
    def generate_random_links(self):
        links = []
        seen_links = []

        # Group devices by type
        routers = []
        switch_and_hubs = []
        pcs = []

        for device_id, info in self.device_registry.items():
            dtype = info["type"].lower()
            if dtype == "router":
                routers.append(device_id)
            elif dtype in {"switch", "hub"}:
                switch_and_hubs.append(device_id)
            elif dtype == "pc":
                pcs.append(device_id)

        # Link routers to each other
        for i in range(len(routers)):
            for j in range(i + 1, len(routers)):
                r1, r2 = routers[i], routers[j]
                link = (min(r1, r2), max(r1, r2))
                if link not in seen_links:
                    links.append(link)
                    seen_links.append(link)

        # Attach each switch to a router (record which switches got a router)
        router_index = 0
        switches_connected_to_routers = set()
        for switch_id in switch_and_hubs:
            if routers:
                router_id = routers[router_index % len(routers)]
                link = (min(switch_id, router_id), max(switch_id, router_id))
                if link not in seen_links:
                    links.append(link)
                    seen_links.append(link)
                    switches_connected_to_routers.add(switch_id)
                    router_index += 1

        # Now connect PCs to a switch that has a router connected
        preferred_parents = list(switches_connected_to_routers) or routers  # fallback to router if no such switch

        parent_index = 0
        for pc in pcs:
            for _ in range(len(preferred_parents)):
                parent = preferred_parents[parent_index % len(preferred_parents)]
                link = (min(pc, parent), max(pc, parent))
                if link not in seen_links:
                    links.append(link)
                    seen_links.append(link)
                    parent_index += 1
                    break
                parent_index += 1

        return links


    def generate_non_deterministic_links(self):
        links = []
        seen_links = set()

        routers = []
        switch_and_hubs = []
        pcs = []

        for device_id, info in self.device_registry.items():
            dtype = info["type"].lower()
            if dtype == "router":
                routers.append(device_id)
            elif dtype in {"switch", "hub"}:
                switch_and_hubs.append(device_id)
            elif dtype == "pc":
                pcs.append(device_id)

        # Shuffle to introduce randomness
        random.shuffle(routers)
        random.shuffle(switch_and_hubs)
        random.shuffle(pcs)

        # Optional: randomly link some routers to each other
        for i in range(len(routers)):
            for j in range(i + 1, len(routers)):
                if random.random() < 0.5:
                    r1, r2 = routers[i], routers[j]
                    link = (min(r1, r2), max(r1, r2))
                    if link not in seen_links:
                        links.append(link)
                        seen_links.add(link)

        # Constraint: No router can have more than one switch
        router_switch_count = {r: 0 for r in routers}

        for switch in switch_and_hubs:
            available_routers = [r for r, count in router_switch_count.items() if count < 1]
            if available_routers:
                chosen_router = random.choice(available_routers)
                link = (min(switch, chosen_router), max(switch, chosen_router))
                if link not in seen_links:
                    links.append(link)
                    seen_links.add(link)
                    router_switch_count[chosen_router] += 1

        # PCs connect to any available switch (or router if no switches)
        preferred_parents = switch_and_hubs or routers
        for pc in pcs:
            if preferred_parents:
                parent = random.choice(preferred_parents)
                link = (min(pc, parent), max(pc, parent))
                if link not in seen_links:
                    links.append(link)
                    seen_links.add(link)

        return links


   
from __future__ import annotations
import ipaddress
from typing import Tuple

class UniqueAllocator:
    def __init__(self, ip4_prefix: str):
        self.net = ipaddress.IPv4Network(ip4_prefix, strict=False)
        self.host_offset = 1
        self.mac_counter = 1

    def next_ip(self) -> Tuple[str, int]:
        if int(self.net.network_address) + self.host_offset >= int(self.net.broadcast_address):
            base = int(self.net.network_address) + self.net.num_addresses
            self.net = ipaddress.IPv4Network((ipaddress.IPv4Address(base), self.net.prefixlen))
            self.host_offset = 1
        ip_int = int(self.net.network_address) + self.host_offset
        self.host_offset += 1
        ip = str(ipaddress.IPv4Address(ip_int))
        return ip, self.net.prefixlen

    def next_mac(self) -> str:
        n = self.mac_counter
        self.mac_counter += 1
        b5 = [
            (n >> 32) & 0xFF,
            (n >> 24) & 0xFF,
            (n >> 16) & 0xFF,
            (n >> 8) & 0xFF,
            n & 0xFF,
        ]
        return "02:" + ":".join(f"{x:02x}" for x in b5)

class SubnetAllocator:
    def __init__(self, ip4_prefix: str):
        self.base = ipaddress.IPv4Network(ip4_prefix, strict=False)
        self.next_addr = int(self.base.network_address)
        self._allocated: set[tuple[int, int]] = set()

    def next_subnet(self, prefixlen: int) -> ipaddress.IPv4Network:
        size = 1 << (32 - prefixlen)
        aligned = (self.next_addr + size - 1) // size * size
        net = ipaddress.IPv4Network((ipaddress.IPv4Address(aligned), prefixlen))
        self.next_addr = aligned + size
        self._allocated.add((int(net.network_address), prefixlen))
        return net

    def next_random_subnet(self, prefixlen: int, attempts: int = 256) -> ipaddress.IPv4Network:
        size = 1 << (32 - prefixlen)
        base_size = self.base.num_addresses
        total_slots = base_size // size if base_size >= size else 0
        if total_slots > 0:
            base_start = int(self.base.network_address)
            if sum(1 for k in self._allocated if k[1] == prefixlen and base_start <= k[0] < base_start + base_size) >= total_slots:
                return self.next_subnet(prefixlen)
            import random
            for _ in range(max(8, attempts)):
                slot = random.randrange(0, total_slots)
                cand = base_start + slot * size
                key = (cand, prefixlen)
                if key in self._allocated:
                    continue
                try:
                    net = ipaddress.IPv4Network((ipaddress.IPv4Address(cand), prefixlen))
                except Exception:
                    continue
                if (int(net.network_address) < base_start) or (int(net.broadcast_address) >= base_start + base_size):
                    continue
                self._allocated.add(key)
                return net
        net = self.next_subnet(prefixlen)
        return net

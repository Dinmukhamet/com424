import logging
from typing import Callable, Dict, Optional, Union
from scapy.all import (
    TCP,
    PcapReader,
    rdpcap,
    IP,
    UDP,
    Packet,
)
from collections import defaultdict


NIL = 0x0
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


class BaseScan:
    def __init__(self, filename: str, layer: Union[TCP, UDP]):
        self.layer = layer
        self.packets: PcapReader = rdpcap(filename=filename)

    def get_packet_ip(self, packet: Packet):
        try:
            return f"{packet[IP].src}:{packet[IP].dport}"
        except (AttributeError, ValueError):
            pass

    def check(self, packet: Packet):
        raise NotImplementedError()

    def check_flags(
        self, packet: Packet, check: Optional[Callable] = None
    ) -> bool:
        perform_check = check or self.check
        if packet.haslayer(self.layer):
            return perform_check(packet.getlayer(self.layer))
        return False

    def search(self):
        intruders: Dict[str, int] = defaultdict(int)

        for packet in self.packets:
            ip = self.get_packet_ip(packet)
            if packet.haslayer(self.layer):
                intruders[ip] += self.check(packet)
        return intruders


class XmasScan(BaseScan):
    def check(self, packet: Packet):
        """
        Sets the FIN, PSH, and URG flags,
        lighting the packet up like a Christmas tree
        """
        return packet.flags == FIN + PSH + URG


class UDPScan(BaseScan):
    def check(self, packet: Packet):
        """
        UDP scan works by sending a UDP packet to every targeted port.
        For most ports, this packet will be empty (no payload).
        """
        return packet.len == 8  # empty payload


class HalfOpenScan(BaseScan):
    def search(self):
        intruders: Dict[str, int] = defaultdict(int)

        for index in range(0, len(self.packets), 2):
            current = self.packets[index]
            if current.haslayer(self.layer):
                ip = self.get_packet_ip(current)
                has_opened = self.check_flags(
                    current, check=lambda p: p.flags == SYN
                )
                is_listening = self.check_flags(
                    self.packets[index + 1],
                    check=lambda p: p.flags == SYN + ACK,
                )

                is_reset = self.check_flags(
                    self.packets[index + 2],
                    check=lambda p: p.flags == RST,
                )
                intruders[ip] += has_opened and is_listening and is_reset
        return intruders

from typing import Callable, Dict, Union
from scapy.all import (
    TCP,
    PcapReader,
    rdpcap,
    IP,
    UDP,
    Packet,
)


NIL = 0x0
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


class PortScan:
    def __init__(self, filename: str):
        self.packets: PcapReader = rdpcap(filename=filename)

    def get_ip(self, packet: Packet):
        return f"{packet[IP].src}:{packet[IP].dport}"

    def search(self):
        raise NotImplementedError()

    def check_flags(
        self, packet: Packet, layer: Union[TCP, UDP], condition: Callable
    ) -> bool:
        if packet.haslayer(layer):
            return packet.getlayer(layer).flags == condition(packet)
        return False


class XmasScan(PortScan):
    def search(self):
        """
        Sets the FIN, PSH, and URG flags,
        lighting the packet up like a Christmas tree
        """
        intruders: Dict[str, int] = dict()

        for packet in self.packets:
            ip = self.get_ip(packet)

            was_attacked = self.check_flags(
                packet, TCP, lambda p: p[TCP].flags == FIN + PSH + URG
            )

            try:
                intruders[ip] += was_attacked
            except KeyError:
                intruders[ip] = was_attacked
        return intruders


class UDPScan(PortScan):
    def search(self):
        """
        UDP scan works by sending a UDP packet to every targeted port.
        For most ports, this packet will be empty (no payload).
        """
        intruders: Dict[str, int] = dict()

        for packet in self.packets:
            if packet.haslayer(UDP):
                ip = self.get_ip(packet)
                is_empty = self.check_flags(
                    packet, UDP, lambda p: p[UDP].len == 8  # empty payload
                )
                try:
                    intruders[ip] += is_empty
                except KeyError:
                    intruders[ip] = is_empty
        return intruders


class HalfOpenScan(PortScan):
    def search(self):
        for index in range(0, len(self.packets), 2):
            current_packet: Packet = self.packets[index]
            if (
                current_packet.haslayer(TCP)
                and current_packet[TCP].flags == SYN
            ):
                # TODO
                if (
                    next_packet := self.packets[index + 1]
                ) and next_packet.haslayer(TCP):
                    self.packets[index + 2]
                    next_packet[TCP].flags == SYN + ACK
        pass

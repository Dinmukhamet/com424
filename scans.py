from enum import Enum
from time import sleep
from typing import Callable, Dict, Optional, Tuple

from peewee import fn
from prettytable import PrettyTable
from scapy.all import ICMP, IP, TCP, UDP, Packet, PcapReader, rdpcap

from db import Intruder


class Colors(str, Enum):
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    RED = "\033[0;31m"
    WARNING = "\033[93m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


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
    layer: Packet = None  # TCP, UDP, ICMP
    scan_type: str = None  # Name of the scan for database records and summary

    def __init__(self, filename: str):
        assert self.layer is not None, "Specify `layer`. Must not be None."
        assert (
            self.scan_type is not None
        ), "Specify `scan_type`. Must not be None."

        self.packets: PcapReader = rdpcap(filename=filename)

    def options(self, packet: Packet) -> bool:
        """
        Used as placeholder for options needed to check
        packet for a scan.

        :param packet: received packet
        :type packet: Packet
        :raises NotImplementedError:
        For each scan this method
        must be implemented individually,
        since each scan has its own options
        :return: True if options are met, False otherwise
        :rtype: bool
        """
        raise NotImplementedError()

    def check(
        self, packet: Packet, options: Optional[Callable] = None
    ) -> bool:
        """
        Performs check on packet with specified options.

        If no options are specified in parameters,
        then it uses method.

        :param packet: received packet
        :type packet: Packet
        :param options: options for checking
        the package for a scan, defaults to None
        :type options: Optional[Callable], optional
        :return: True if scan was detected, False otherwise
        :rtype: bool
        """
        perform_check = options or self.options
        if packet.haslayer(self.layer):
            return perform_check(packet.getlayer(self.layer))
        return False

    def get_packet_ip(self, packet: Packet) -> Tuple[str, int]:
        """
        Retrieves Host and Port from packet.

        :param packet: received packet
        :type packet: Packet
        :return: return tuple of host and port
        :rtype: Tuple[str, int]
        """
        try:
            return packet[IP].src, packet[IP].dport
        except (AttributeError, ValueError):
            pass

    def search(self) -> None:
        """
        Iterates over packets and search
        for scan according to specified options.
        """
        for packet in self.packets:
            if (
                packet.haslayer(IP)
                and (ip := self.get_packet_ip(packet)) is not None
            ):
                host, port = ip
                Intruder.create(
                    scan_type=self.scan_type,
                    host=host,
                    port=port,
                    has_attacked=int(self.check(packet)),
                )

    @property
    def summary(self) -> None:
        """
        Outputs the search summary to the console.

        Aggregation performed via Peewee ORM to
        retrieve data in the fastest way possible.
        """
        print(
            Colors.OKBLUE
            + f"Searching for {self.scan_type} scans."
            + Colors.ENDC
        )

        self.search()
        query = (
            Intruder.select(
                Intruder.host,
                fn.SUM(Intruder.has_attacked).alias("attacks"),
                fn.COUNT(Intruder.port.distinct()).alias("ports_number"),
            )
            .where(Intruder.scan_type == self.scan_type)
            .group_by(Intruder.host)
            .having(fn.SUM(Intruder.has_attacked) > 0)
        )

        if query.exists():
            table = PrettyTable(
                field_names=("host", "number of attacks", "number of ports")
            )
            table.add_rows(query.tuples())
            print(
                f"{Colors.RED}{self.scan_type} scans were detected!{Colors.ENDC}"
            )
            print(f"{Colors.WARNING}{table}{Colors.ENDC}")
        else:
            print(
                Colors.OKGREEN
                + f"{self.scan_type} scans not detected!"
                + Colors.ENDC
            )


class XmasScan(BaseScan):
    """
    Sets the FIN, PSH, and URG flags,
    lighting the packet up like a Christmas tree
    """

    layer: Packet = TCP
    scan_type: str = "XMAS"

    def options(self, packet: Packet) -> bool:
        return packet.flags == FIN + PSH + URG


class UDPScan(BaseScan):
    """
    UDP scan works by sending a UDP packet to every targeted port.
    For most ports, this packet will be empty (no payload).
    """

    layer: Packet = UDP
    scan_type: str = "UDP"

    def options(self, packet: Packet) -> bool:
        return packet.len == 8  # empty payload


class HalfOpenScan(BaseScan):
    """
    Don't open a full TCP connection. 
    Send a SYN packet, as if it is going to open 
    a real connection and then wait for a response. 
    A SYN/ACK indicates the port is listening (open), 
    while a RST (reset) is indicative of a non-listener.
    """

    layer: Packet = TCP
    scan_type: str = "Half Open"

    def search(self) -> Dict[str, int]:
        for index in range(0, len(self.packets), 2):
            current = self.packets[index]
            if current.haslayer(self.layer):
                host, port = self.get_packet_ip(current)
                has_opened = self.check(
                    current, options=lambda p: p.flags == SYN
                )
                is_listening = self.check(
                    self.packets[index + 1],
                    options=lambda p: p.flags == SYN + ACK,
                )

                is_reset = self.check(
                    self.packets[index + 2],
                    options=lambda p: p.flags == RST,
                )
                Intruder.create(
                    scan_type=self.scan_type,
                    host=host,
                    port=port,
                    has_attacked=int(has_opened and is_listening and is_reset),
                )


class NULLScan(BaseScan):
    """
    NULL scan does not set any bits (TCP flag header is 0)
    """

    layer: Packet = TCP
    scan_type: str = "NULL"

    def options(self, packet: Packet) -> bool:
        return packet.flags == NIL


class ICMPEcho(BaseScan):
    """
    An ICMP type 8 (echo request)
    packet is sent to the target IP addresses
    """

    layer: Packet = ICMP
    scan_type: str = "ICMP echo"

    def options(self, packet: Packet) -> bool:
        return packet.type == 8

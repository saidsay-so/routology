from __future__ import annotations

import struct
from asyncio import gather
from dataclasses import dataclass, field
from datetime import datetime
from itertools import product
from random import randint
from socket import (
    AF_INET,
    IP_TTL,
    IPPROTO_ICMP,
    IPPROTO_IP,
    IPPROTO_TCP,
    IPPROTO_UDP,
    SOCK_DGRAM,
    SOCK_RAW,
    socket,
)
from typing import TYPE_CHECKING

import dpkt

from routology.probe import ProbeType
from routology.utils import HostID

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop
    from typing import Callable, Iterable


@dataclass
class SentProbeInfo:
    """Information about a probe."""

    serie: int
    time: datetime
    host: HostID
    probe_type: ProbeType = field(init=False)
    final: bool


@dataclass
class UDPProbeInfo(SentProbeInfo):
    """Information about a UDP probe."""

    dport: int
    sport: int
    length: int
    probe_type = ProbeType.UDP


@dataclass
class TCPProbeInfo(SentProbeInfo):
    """Information about a TCP probe."""

    sport: int
    dport: int
    seq: int
    probe_type = ProbeType.TCP


@dataclass
class ICMPProbeInfo(SentProbeInfo):
    """Information about an ICMP probe."""

    type: int
    code: int
    id: int
    seq: int
    probe_type = ProbeType.ICMP


ProbeInfo = UDPProbeInfo | TCPProbeInfo | ICMPProbeInfo


class HostSender:
    """A sender for a single host."""

    host: HostID
    """The host ID of the host."""

    _probe_info_collector: Callable[[ProbeInfo], None]

    _udp_socket: socket
    _unique_udp_ports: bool

    _tcp_socket: socket
    _tcp_seq_getter: Callable[[], int]

    _icmp_socket: socket
    _icmp_seq_getter: Callable[[], int]

    _ttl: int
    _pkt_size: int
    """Packet size in bytes, including layer 4 headers."""

    def __init__(
        self,
        host: HostID,
        probe_info_collector: Callable[[ProbeInfo], None],
        event_loop: AbstractEventLoop,
        packet_size: int = 20,
        ttl: int = 1,
        port: int = 33434,
        unique_udp_ports: bool = False,
        tcp_seq_getter: Callable[[], int] = lambda: randint(0, 2**32),
        icmp_seq_getter: Callable[[], int] = lambda: randint(0, 2**16),
    ):
        self.host = host
        self._loop = event_loop
        self._unique_udp_ports = unique_udp_ports
        self._probe_info_collector = probe_info_collector
        self._ttl = ttl
        self._pkt_size = packet_size
        self._port = port
        self._udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)

        self._tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
        self._tcp_seq_getter = tcp_seq_getter
        self._tcp_port = self._tcp_socket.getsockname()[1]

        self._icmp_seq_getter = icmp_seq_getter
        self._icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        self._icmp_socket.bind(("0.0.0.0", 0))

    async def _send_probes_serie(self, serie: int, ttl: int) -> None:
        """Send a probes serie."""

        udp_port = self._port + ttl - 1 + serie
        self._udp_socket.sendto(
            b"0" * (self._pkt_size - dpkt.udp.UDP_HDR_LEN),
            (str(self.host), udp_port),
        )

        sport = self._udp_socket.getsockname()[1]

        self._probe_info_collector(
            UDPProbeInfo(
                serie=serie,
                time=datetime.now(),
                host=self.host,
                sport=sport,
                dport=udp_port,
                length=self._pkt_size,
                final=False,
            )
        )

        tcp_data = b"0" * (self._pkt_size - 20)
        tcp = dpkt.tcp.TCP(
            dport=self._port,
            sport=self._tcp_port,
            seq=self._tcp_seq_getter(),
            data=tcp_data,
        )
        self._tcp_socket.sendto(
            bytes(tcp),
            (str(self.host), self._port),
        )

        self._probe_info_collector(
            TCPProbeInfo(
                serie=serie,
                time=datetime.now(),
                host=self.host,
                sport=tcp.sport,  # type: ignore
                dport=tcp.dport,  # type: ignore
                seq=tcp.seq,  # type: ignore
                final=False,
            )
        )

        icmp_data = dpkt.icmp.ICMP.Echo(
            id=self._port, seq=self._icmp_seq_getter, data=b"0" * (self._pkt_size - 8)
        )
        icmp_cksum = dpkt.dpkt.in_cksum_add(
            0, struct.pack("!HH", dpkt.icmp.ICMP_ECHO, 0)
        )
        icmp_cksum = dpkt.dpkt.in_cksum_add(icmp_cksum, bytes(icmp_data))
        icmp_cksum = dpkt.dpkt.in_cksum_done(icmp_cksum)

        icmp = dpkt.icmp.ICMP(
            type=dpkt.icmp.ICMP_ECHO,
            code=0,
            sum=icmp_cksum,
            data=icmp_data,
        )
        self._icmp_socket.sendto(bytes(icmp), (str(self.host), 0))

        self._probe_info_collector(
            ICMPProbeInfo(
                serie=serie,
                time=datetime.now(),
                host=self.host,
                type=dpkt.icmp.ICMP_ECHO,
                code=0,
                id=icmp_data.id,  # type: ignore
                seq=icmp_data.seq,  # type: ignore
                final=False,
            )
        )

    async def send_probes(self, serie: int, ttl: int) -> None:
        """Send a serie of probes."""

        await self._send_probes_serie(serie, ttl)

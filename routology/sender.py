from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from random import randint
from typing import TYPE_CHECKING
from logging import getLogger

from scapy.all import send, PacketList, conf as scapy_conf
from scapy.layers.inet import IP, UDP, TCP, ICMP

from routology.probe import ProbeType
from routology.utils import HostID

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop
    from typing import Callable
    from logging import Logger

scapy_conf.verb = 0


@dataclass
class SentProbeInfo:
    """Information about a probe."""

    ttl: int
    serie: int
    time: datetime
    host: HostID
    probe_type: ProbeType = field(init=False)


@dataclass
class UDPProbeInfo(SentProbeInfo):
    """Information about a UDP probe."""

    dport: int
    sport: int
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

    id: int
    seq: int
    probe_type = ProbeType.ICMP


ProbeInfo = UDPProbeInfo | TCPProbeInfo | ICMPProbeInfo


@dataclass
class SendRequest:
    """A request to send probes."""

    ttl: int
    serie: int
    host: HostID


class Sender:
    """A sender which can send multiple probes."""

    _probe_info_collector: Callable[[ProbeInfo], None]

    _dont_fragment: bool

    _udp_sport: int
    _unified_udp_sport: bool

    _tcp_sport: int
    _tcp_dport: int

    _udp_dport: int
    _unified_udp_dport: bool

    _id: int
    _tcp_seq_getter: Callable[[], int]
    _ip_id_getter: Callable[[], int]
    _icmp_seq_getter: Callable[[], int]

    _logger: Logger

    def __init__(
        self,
        probe_info_collector: Callable[[ProbeInfo], None],
        event_loop: AbstractEventLoop,
        packet_size: int = 20,
        udp_sport: int = randint(2048, 65535),
        unified_udp_sport: bool = False,
        udp_dport: int = 33434,
        unified_udp_dport: bool = False,
        tcp_sport: int = randint(2048, 65535),
        tcp_dport: int = randint(2048, 65535),
        ip_id_getter: Callable[[], int] = lambda: randint(0, 2**16 - 1),
        tcp_seq_getter: Callable[[], int] = lambda: randint(0, 2**32 - 1),
        icmp_seq_getter: Callable[[], int] = lambda: randint(0, 2**16 - 1),
        icmp_id: int = randint(0, 2**16),
        dont_fragment: bool = False,
        logger: Logger | None = None,
    ):
        self._id = icmp_id
        self._loop = event_loop
        self._probe_info_collector = probe_info_collector
        self._pkt_size = packet_size

        self._udp_sport = udp_sport
        self._unified_udp_sport = unified_udp_sport

        self._udp_dport = udp_dport
        self._unified_udp_dport = unified_udp_dport

        self._tcp_sport = tcp_sport
        self._tcp_dport = tcp_dport

        self._tcp_seq_getter = tcp_seq_getter
        self._icmp_seq_getter = icmp_seq_getter
        self._ip_id_getter = ip_id_getter

        self._dont_fragment = dont_fragment

        self._logger = logger or getLogger(__name__)

    def _compute_udp_dport(self) -> int:
        if not self._unified_udp_dport:
            self._udp_dport += 1
        return self._udp_dport

    async def send_probes(
        self, entries: list[SendRequest], pkt_send_time: int = 0
    ) -> None:
        """Send a serie of probes."""
        if not entries:
            return

        probes = []
        data = "0" * (self._pkt_size - 8)
        for entry in entries:
            ttl = entry.ttl
            ip = IP(dst=str(entry.host), ttl=ttl, id=self._ip_id_getter())

            udp_dport = self._compute_udp_dport()

            udp_sport = (
                self._udp_sport if self._unified_udp_sport else randint(2048, 65535)
            )
            probes.append(
                ip
                / UDP(
                    dport=udp_dport,
                    sport=udp_sport,
                )
                / data
            )

            self._probe_info_collector(
                UDPProbeInfo(
                    ttl=entry.ttl,
                    serie=entry.serie,
                    time=datetime.now(),
                    host=entry.host,
                    sport=udp_sport,
                    dport=udp_dport,
                )
            )

            icmp_seq = self._icmp_seq_getter()
            probes.append(
                ip
                / ICMP(
                    type=8,
                    code=0,
                    id=self._id,
                    seq=icmp_seq,
                )
                / data
            )

            self._probe_info_collector(
                ICMPProbeInfo(
                    ttl=entry.ttl,
                    serie=entry.serie,
                    time=datetime.now(),
                    host=entry.host,
                    id=self._id,
                    seq=icmp_seq,
                )
            )

            tcp_seq = self._tcp_seq_getter()
            probes.append(
                ip
                / TCP(
                    dport=self._tcp_dport,
                    sport=self._tcp_sport,
                    seq=tcp_seq,
                    flags="S",
                )
            )

            self._probe_info_collector(
                TCPProbeInfo(
                    ttl=entry.ttl,
                    serie=entry.serie,
                    time=datetime.now(),
                    host=entry.host,
                    sport=self._tcp_sport,
                    dport=self._tcp_dport,
                    seq=tcp_seq,
                )
            )

        self._logger.debug(
            "Sending probes to %s",
            ", ".join((str(probe.host) for probe in entries)),
        )
        await self._loop.run_in_executor(
            None,
            lambda: send(
                PacketList(probes),
                inter=pkt_send_time,
                verbose=False,
            ),
        )

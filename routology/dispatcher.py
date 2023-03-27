from __future__ import annotations

from asyncio import Queue, get_event_loop, create_task
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from ipaddress import ip_address
import dpkt
from datetime import datetime, timedelta
from logging import getLogger

from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, UDP, TCP, ICMP, Ether
from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded, ICMPv6EchoReply

from routology.probe import ProbeType
from routology.sender import ProbeInfo
from routology.utils import HostID

if TYPE_CHECKING:
    from typing import Optional, Callable, AsyncGenerator
    from asyncio import AbstractEventLoop, Task
    from ipaddress import IPv4Address, IPv6Address
    from logging import Logger


@dataclass
class DispatchedProbeReport:
    """A report for a dispatched probe."""

    ttl: int
    probe_type: ProbeType
    series: int
    node_ip: IPv4Address | IPv6Address
    rtt: float
    host_id: HostID
    """The host ID of the probe."""


class Dispatcher:
    """A dispatcher for received ICMP packets, which identifies the
    corresponding host and updates its list of hops."""

    _subscriptions: list[Queue[DispatchedProbeReport | None]]

    _tcp_info_getter: Callable[[TCP], Optional[ProbeInfo]]
    _udp_info_getter: Callable[[UDP], Optional[ProbeInfo]]
    _icmp_info_getter: Callable[[ICMP], Optional[ProbeInfo]]
    _icmp6_info_getter: Callable[[ICMPv6EchoReply], Optional[ProbeInfo]]

    tasks: set[Task]

    _loop: AbstractEventLoop
    _sniffer: AsyncSniffer

    _logger: Logger

    def __init__(
        self,
        tcp_getter: Callable[[TCP], Optional[ProbeInfo]],
        udp_getter: Callable[[UDP], Optional[ProbeInfo]],
        icmp_getter: Callable[[ICMP], Optional[ProbeInfo]],
        icmp6_getter: Callable[
            [ICMPv6EchoReply | ICMPv6TimeExceeded], Optional[ProbeInfo]
        ],
    ):
        self._subscriptions = []
        self.tasks = set()
        self._stop = False

        self._tcp_info_getter = tcp_getter
        self._udp_info_getter = udp_getter
        self._icmp_info_getter = icmp_getter
        self._icmp6_info_getter = icmp6_getter

        self._loop = get_event_loop()
        self._logger = getLogger(__name__)

        self._sniffer = AsyncSniffer(
            store=False,
            prn=self._dispatch_packet,
            quiet=True,
            filter="tcp[tcpflags] == tcp-rst or icmp[icmptype] == icmp-echoreply or icmp[icmptype] == icmp-timxceed or icmp6[icmptype] == icmp6-echoreply or icmp6[icmptype] == icmp6-timeexceeded",
        )
        self._sniffer.start()

    def subscribe(self) -> AsyncGenerator[DispatchedProbeReport, None]:
        """Subscribe to a host's probe reports."""

        q = Queue()

        async def _subscribe() -> AsyncGenerator[DispatchedProbeReport, None]:
            while not self._stop:
                report = await q.get()
                if report is None:
                    return

                yield report

        self._subscriptions.append(q)
        s = _subscribe()
        s.asend(None)
        return s

    def publish(self, report: DispatchedProbeReport) -> None:
        """Publish a report for a host."""
        for subscription in self._subscriptions:
            subscription.put_nowait(report)

    async def run(self) -> None:
        """Run the dispatcher."""
        await self._loop.run_in_executor(None, self._sniffer.join)
        self._logger.debug("Sniffer stopped, closing dispatcher")

    async def close(self) -> None:
        """Close the dispatcher."""
        self._stop = True
        self._sniffer.stop()

        for subscription in self._subscriptions:
            subscription.put_nowait(None)
            self._logger.debug("Closing subscription")

    def _dispatch_packet(self, pkt: Ether) -> None:
        """Dispatch an ICMPv4 packet."""
        if not IP in pkt:
            return

        ip: IP = pkt[IP]
        addr = ip_address(ip.src)
        self._logger.debug("Packet from %s", addr)

        match ip.payload:
            case ICMP() as icmp:
                match icmp.type, icmp.code:
                    case 11, 0:
                        # We've reached a hop
                        previous_ip = cast(IP, icmp.payload)
                        ttl = previous_ip.ttl
                        match previous_ip.payload:
                            case TCP() as tcp:
                                probe_info = self._tcp_info_getter(tcp)
                                if probe_info:
                                    self._add_to_queue(
                                        ttl,
                                        addr,
                                        probe_info,
                                        ProbeType.TCP,
                                    )
                            case UDP() as udp:
                                probe_info = self._udp_info_getter(udp)
                                if probe_info:
                                    self._add_to_queue(
                                        ttl,
                                        addr,
                                        probe_info,
                                        ProbeType.UDP,
                                    )
                            case ICMP() as icmp:
                                probe_info = self._icmp_info_getter(icmp)
                                if probe_info:
                                    self._add_to_queue(
                                        ttl,
                                        addr,
                                        probe_info,
                                        ProbeType.ICMP,
                                    )

    def _add_to_queue(
        self,
        ttl: int,
        addr: IPv4Address | IPv6Address,
        probe_info: ProbeInfo,
        probe_type: ProbeType,
    ) -> None:
        """Add a report to the appropriate queue if available."""
        host_id = probe_info.host
        time_diff = datetime.now() - probe_info.time
        rtt = time_diff / timedelta(milliseconds=1)
        report = DispatchedProbeReport(
            ttl,
            probe_type,
            probe_info.serie,
            addr,
            rtt,
            host_id,
        )

        self._logger.debug(
            "Dispatching report for host %s: %s with TTL %d",
            host_id,
            report,
            ttl,
        )
        self.publish(report)

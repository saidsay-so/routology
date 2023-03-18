from __future__ import annotations

from socket import (
    AF_INET,
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    SOCK_RAW,
    socket,
)
from asyncio import Queue, get_event_loop, create_task
from aiorwlock import RWLock
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from ipaddress import ip_address
import dpkt
from datetime import datetime, timedelta

from routology.probe import ProbeType
from routology.sender import SentProbeInfo
from routology.utils import HostID

if TYPE_CHECKING:
    from typing import Optional, Callable, AsyncGenerator, Coroutine
    from asyncio import AbstractEventLoop, Task
    from ipaddress import IPv4Address, IPv6Address


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

    _subs_lock: RWLock
    _subscriptions: dict[HostID, list[Queue[DispatchedProbeReport | None]]]

    _tcp_info_getter: Callable[[dpkt.tcp.TCP], Optional[SentProbeInfo]]
    _udp_info_getter: Callable[[dpkt.udp.UDP], Optional[SentProbeInfo]]
    _icmp_info_getter: Callable[[dpkt.icmp.ICMP], Optional[SentProbeInfo]]
    _icmp6_info_getter: Callable[[dpkt.icmp6.ICMP6], Optional[SentProbeInfo]]

    tasks: set[Task]

    _sockv4: socket
    _loop: AbstractEventLoop

    def __init__(
        self,
        hosts: list[HostID],
        tcp_getter: Callable[[dpkt.tcp.TCP], Optional[SentProbeInfo]],
        udp_getter: Callable[[dpkt.udp.UDP], Optional[SentProbeInfo]],
        icmp_getter: Callable[[dpkt.icmp.ICMP], Optional[SentProbeInfo]],
        icmp6_getter: Callable[[dpkt.icmp6.ICMP6], Optional[SentProbeInfo]],
    ):
        self._subscriptions = {host: [] for host in hosts}
        self.tasks = set()

        self._tcp_info_getter = tcp_getter
        self._udp_info_getter = udp_getter
        self._icmp_info_getter = icmp_getter
        self._icmp6_info_getter = icmp6_getter

        self._loop = get_event_loop()
        self._sockv4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        self._sockv4.bind(("0.0.0.0", 0))

        self._loop.add_reader(
            self._sockv4,
            lambda: self._fire_background_task(
                self.dispatch_v4(*self._sockv4.recvfrom(1024))
            ),
        )

        self._sockv6 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMPV6)
        self._sockv6.bind(("::", 0))

        self._loop.add_reader(
            self._sockv6,
            lambda: self._fire_background_task(
                self.dispatch_v6(*self._sockv6.recvfrom(1024))
            ),
        )

    def _fire_background_task(self, coro: Coroutine) -> None:
        """Fire-and-forget a coroutine."""
        task = create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.remove)

    async def stop_tracking_host(self, host: HostID) -> None:
        """Stop tracking a host."""
        for subscription in self._subscriptions[host]:
            await subscription.put(None)
            await subscription.join()
        self._subscriptions.pop(host)

    def subscribe(self, host: HostID) -> AsyncGenerator[DispatchedProbeReport, None]:
        """Subscribe to a host's probe reports."""

        q = Queue()

        async def _subscribe(
            host: HostID,
        ) -> AsyncGenerator[DispatchedProbeReport, None]:
            while host in self._subscriptions:
                report = await q.get()
                if report is None:
                    return
                yield report
                q.task_done()

        self._subscriptions[host].append(q)
        return _subscribe(host)

    def publish(self, host: HostID, report: DispatchedProbeReport) -> None:
        """Publish a report for a host."""
        if host in self._subscriptions:
            for subscription in self._subscriptions[host]:
                subscription.put_nowait(report)

    async def dispatch_v4(self, data: bytes, addr_info: tuple[str, int]) -> None:
        """Dispatch an ICMPv4 packet."""
        pkt = cast(dpkt.icmp.ICMP, dpkt.ip.IP(data).data)
        addr, _ = addr_info
        addr = ip_address(addr)
        match pkt.type, pkt.code:  # type: ignore
            case dpkt.icmp.ICMP_TIMEXCEED, dpkt.icmp.ICMP_TIMEXCEED_INTRANS:
                # We've reached a hop
                ip = cast(dpkt.ip.IP, pkt.data)
                ttl = ip.ttl  # type: ignore
                match ip.data:
                    case dpkt.tcp.TCP() as tcp:
                        probe_info = self._tcp_info_getter(tcp)
                        if probe_info:
                            self._add_to_queue(
                                ttl,
                                addr,
                                probe_info,
                                ProbeType.TCP,
                            )
                    case dpkt.udp.UDP() as udp:
                        probe_info = self._udp_info_getter(udp)
                        if probe_info:
                            self._add_to_queue(
                                ttl,
                                addr,
                                probe_info,
                                ProbeType.UDP,
                            )
                    case dpkt.icmp.ICMP() as icmp:
                        probe_info = self._icmp_info_getter(icmp)
                        if probe_info:
                            self._add_to_queue(
                                ttl,
                                addr,
                                probe_info,
                                ProbeType.ICMP,
                            )

    async def dispatch_v6(self, data: bytes, addr_info: tuple[str, int]) -> None:
        """Dispatch an ICMPv6 packet."""
        pkt = cast(dpkt.icmp6.ICMP6, dpkt.ip6.IP6(data).data)
        addr, _ = addr_info
        addr = ip_address(addr)
        match pkt.type, pkt.code:  # type: ignore
            case dpkt.icmp6.ICMP6_TIME_EXCEEDED, 0:
                # We've reached a hop
                ip = cast(dpkt.ip6.IP6, pkt.data)
                ttl = ip.hlim  # type: ignore
                match ip.data:
                    case dpkt.tcp.TCP() as tcp:
                        probe_info = self._tcp_info_getter(tcp)
                        if probe_info:
                            self._add_to_queue(
                                ttl,
                                addr,
                                probe_info,
                                ProbeType.TCP,
                            )
                    case dpkt.udp.UDP() as udp:
                        probe_info = self._udp_info_getter(udp)
                        if probe_info:
                            self._add_to_queue(
                                ttl,
                                addr,
                                probe_info,
                                ProbeType.UDP,
                            )
                    case dpkt.icmp6.ICMP6() as icmp:
                        probe_info = self._icmp6_info_getter(icmp)
                        if probe_info:
                            self._add_to_queue(
                                ttl,
                                addr,
                                probe_info,
                                ProbeType.ICMP6,
                            )

    def _add_to_queue(
        self,
        ttl: int,
        addr: IPv4Address | IPv6Address,
        probe_info: SentProbeInfo,
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

        self.publish(host_id, report)

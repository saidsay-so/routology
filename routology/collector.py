from __future__ import annotations

from dataclasses import dataclass
from math import ceil, floor
from typing import TYPE_CHECKING
from logging import Logger, getLogger
from asyncio import TimeoutError
from datetime import datetime, timedelta

from routology.probe import ProbeType
from routology.utils import HostID, dynamic_timeout

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from routology.dispatcher import DispatchedProbeReport, Dispatcher


@dataclass
class ProbeResponse:
    """A response for a probe."""

    rtt: float
    node_ip: IPv4Address | IPv6Address


@dataclass
class Node:
    """A report for a node, which can contain different addresses for each probe type."""

    udp_probe: Optional[ProbeResponse] = None
    tcp_probe: Optional[ProbeResponse] = None
    icmp_probe: Optional[ProbeResponse] = None


@dataclass
class Hop:
    """A report for a hop, which contains a list of nodes sorted by series."""

    nodes: list[Optional[Node]]


@dataclass
class HostReport:
    """A report for a host."""

    addr: IPv4Address | IPv6Address
    hops: list[Optional[Hop]]


class Collector:
    """A collector for probe reports."""

    _hosts: dict[HostID, HostReport]

    _delay: float
    _here: float
    _near: float

    _series: int

    _logger: Logger

    def __init__(
        self,
        hosts: list[HostID],
        dispatcher: Dispatcher,
        max_hops: int,
        delay: float,
        series: int,
        send_wait: float,
        sim_probes: int,
        logger: Optional[Logger] = None,
    ):
        self._hosts = {host: HostReport(host.addr, [None] * max_hops) for host in hosts}
        self._dispatcher = dispatcher
        self._subscription = dispatcher.subscribe()

        self._delay = delay
        self._max_hops = max_hops
        self._send_wait = send_wait
        self._sim_probes = sim_probes
        self._num_hosts = len(hosts)
        self._timeout = None

        self._series = series

        self._logger = logger or getLogger(__name__)

    def _collect(self, report: DispatchedProbeReport):
        """Collects a probe report."""
        self._logger.debug(
            "Received report for %s (ttl=%d, series=%d, type=%s, rtt=%f, host=%s)",
            report.node_ip,
            report.ttl,
            report.series,
            report.probe_type,
            report.rtt,
            report.host_id,
        )
        host = self._hosts[report.host_id]

        hop = host.hops[report.ttl - 1]
        if hop is None:
            hop = Hop([None] * self._series)
            host.hops[report.ttl - 1] = hop

        node = hop.nodes[report.series]
        if node is None:
            node = Node()
            hop.nodes[report.series] = node

        match report.probe_type:
            case ProbeType.UDP:
                node.udp_probe = ProbeResponse(report.rtt, report.node_ip)
            case ProbeType.TCP:
                node.tcp_probe = ProbeResponse(report.rtt, report.node_ip)
            case ProbeType.ICMP:
                node.icmp_probe = ProbeResponse(report.rtt, report.node_ip)

    def start_timeout(self) -> None:
        """Determines the timeout for the collector."""
        self._timeout = datetime.now() + timedelta(
            seconds=(self._delay),
        )

    def get_report(self) -> dict[HostID, HostReport]:
        """Returns the collected report."""
        return self._hosts

    def get_timeout(self) -> float:
        """Returns the timeout for the collector."""
        if self._timeout is None:
            return 5

        diff = self._timeout - datetime.now()
        return max(diff.total_seconds(), 0)

    def _compute_timeout(self, report: DispatchedProbeReport):
        """Computes the timeout for the collector."""
        if self._timeout is not None:
            self._timeout -= timedelta(
                seconds=self._delay / 3,
            )

    async def run(self) -> dict[HostID, HostReport]:
        """Runs the collector."""
        try:
            async with dynamic_timeout(
                self._subscription, self.get_timeout
            ).stream() as subscription:
                async for report in subscription:
                    self._logger.debug("Next timeout: %.2lf", self.get_timeout())
                    self._logger.debug(
                        "%sNext report: %s", "(Final) " if report.final else "", report
                    )
                    self._collect(report)
                    self._compute_timeout(report)
        except TimeoutError:
            self._logger.warn("Expired timeout for collector")
        finally:
            self._logger.info("Collector finished")
            await self._dispatcher.close()
            return self.get_report()

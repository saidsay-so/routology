from __future__ import annotations

from dataclasses import dataclass
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

    _max: float
    _here: float
    _near: float

    _series: int

    _logger: Logger

    def __init__(
        self,
        hosts: list[HostID],
        dispatcher: Dispatcher,
        max_hops: int,
        max: float,
        here: float,
        near: float,
        series: int,
        send_wait: float,
        sim_probes: int,
        logger: Optional[Logger] = None,
    ):
        self._hosts = {host: HostReport(host.addr, [None] * max_hops) for host in hosts}
        self._dispatcher = dispatcher
        self._subscription = dispatcher.subscribe()

        self._max = max
        self._here = here
        self._near = near
        self._send_wait = send_wait
        self._sim_probes = sim_probes
        self._timeout = datetime.now() + timedelta(
            seconds=(max * max_hops)
            + (max_hops / (here * series - 1))
            + (near * series)
            + (send_wait * (max_hops / sim_probes))
        )

        self._series = series

        self._logger = logger or getLogger(self.__class__.__name__)

    def _collect(self, report: DispatchedProbeReport):
        """Collects a probe report."""
        host = self._hosts[report.host_id]

        hop = host.hops[report.ttl - 1]
        if hop is None:
            hop = Hop([None] * self._series)
            host.hops[report.ttl - 1] = hop

        node = hop.nodes[report.series - 1]
        if node is None:
            node = Node()
            hop.nodes[report.series - 1] = node

        match report.probe_type:
            case ProbeType.UDP:
                node.udp_probe = ProbeResponse(report.rtt, report.node_ip)
            case ProbeType.TCP:
                node.tcp_probe = ProbeResponse(report.rtt, report.node_ip)
            case ProbeType.ICMP:
                node.icmp_probe = ProbeResponse(report.rtt, report.node_ip)

    def get_report(self) -> dict[HostID, HostReport]:
        """Returns the collected report."""
        return self._hosts

    def get_timeout(self) -> float:
        """Returns the timeout for the collector."""
        diff = self._timeout - datetime.now()
        return diff.total_seconds() if diff.total_seconds() > 0 else 1

    def _compute_timeout(self, report: DispatchedProbeReport):
        """Computes the timeout for the collector."""
        self._timeout -= timedelta(
            milliseconds=report.rtt / self._here + report.ttl / self._near,
        )

    async def run(self) -> dict[HostID, HostReport]:
        """Runs the collector."""
        try:
            async with dynamic_timeout(
                self._subscription, self.get_timeout
            ).stream() as subscription:
                async for report in subscription:
                    self._logger.debug("Timeout: %.2lf", self.get_timeout())
                    self._collect(report)
                    self._compute_timeout(report)
        except TimeoutError:
            self._logger.warn("Expired timeout: %.2lf", self.get_timeout())
            pass
        finally:
            self._logger.info("Collector finished")
            await self._dispatcher.close()
            return self.get_report()

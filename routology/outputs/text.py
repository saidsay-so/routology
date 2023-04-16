from __future__ import annotations
import asyncio

from dns.asyncresolver import Resolver
from dns.resolver import LRUCache

from dataclasses import dataclass
from typing import TYPE_CHECKING
from routology.collector import HostReport, ProbeResponse

from routology.utils import HostID

if TYPE_CHECKING:
    from typing import Optional
    from asyncio import AbstractEventLoop

    from routology.collector import Hop


@dataclass
class ProbeOutput:
    """Output for a single probe"""

    rtt: float
    node_ip: str
    node_name: Optional[str]

    def __str__(self) -> str:
        return f"{self.node_name or self.node_ip} ({self.node_ip}) {self.rtt:.3f}ms"


@dataclass
class HopNode:
    """Output for a single hop"""

    udp: Optional[ProbeOutput] = None
    tcp: Optional[ProbeOutput] = None
    icmp: Optional[ProbeOutput] = None

    def __str__(self) -> str:
        udp = str(self.udp) if self.udp else "*"
        tcp = str(self.tcp) if self.tcp else "*"
        icmp = str(self.icmp) if self.icmp else "*"

        return f"{udp} {tcp} {icmp}"


@dataclass
class Line:
    ttl: int
    series: list[HopNode]

    def __str__(self) -> str:
        return f"{self.ttl} {' '.join(str(h) for h in self.series)}"


class HostTextFormatter:
    """Output for a single host"""

    lines: list[Line]
    addr: str

    _loop: AbstractEventLoop
    _collected: list[list[Hop | None]]
    _resolver: Resolver
    _no_dns: bool

    def __init__(
        self,
        addr: str,
        series: int,
        collected: list[list[Hop | None]],
        loop: AbstractEventLoop,
        resolver: Resolver,
        no_dns: bool = False,
    ):
        max_ttl = max(len(s) for s in collected)
        self.lines = [Line(ttl, [HopNode()] * series) for ttl in range(1, max_ttl + 1)]
        self.addr = addr
        self._loop = loop
        self._collected = collected
        self._resolver = resolver
        self._no_dns = no_dns

    async def build(self):
        tasks = []
        for probe_type in ("udp", "tcp", "icmp"):
            for i, serie in enumerate(self._collected):
                for ttl, hop in enumerate(serie):
                    ho = getattr(hop, probe_type + "_probe", None)
                    if ho:
                        tasks.append(
                            self._loop.create_task(
                                self._line_worker(probe_type, i, ttl, ho)
                            )
                        )

        await asyncio.gather(*tasks)

    async def _line_worker(
        self,
        probe_type: str,
        serie_num: int,
        ttl: int,
        hop: ProbeResponse,
    ):
        if self._no_dns:
            node_name = None
        else:
            try:
                res = await self._resolver.resolve_address(
                    str(hop.node_ip), lifetime=10
                )
                node_name = res[0].target.to_unicode(omit_final_dot=True)  # type: ignore
            except Exception:
                node_name = None

        setattr(
            self.lines[ttl].series[serie_num],
            probe_type,
            ProbeOutput(hop.rtt, str(hop.node_ip), node_name),
        )

    def __str__(self) -> str:
        return "traceroute to %s\n%s" % (
            self.addr,
            "\n".join(str(line) for line in self.lines),
        )


class TextOutputFormatter:
    """Output for a single host"""

    formatters: list[HostTextFormatter]
    result: str
    resolver: Resolver

    def __init__(
        self,
        collected: dict[HostID, HostReport],
        series: int,
        resolver: Resolver,
        no_dns: bool = False,
        loop: AbstractEventLoop = asyncio.get_event_loop(),
    ):
        self.resolver = resolver
        self.formatters = [
            HostTextFormatter(
                str(addr),
                series,
                collected[addr].series,
                loop,
                self.resolver,
                no_dns=no_dns,
            )
            for addr in collected
        ]
        self._collected = collected

    async def format(self):
        await asyncio.gather(*[form.build() for form in self.formatters])

        self.result = "\n\n".join(str(host) for host in self.formatters)

    def __str__(self) -> str:
        return self.result

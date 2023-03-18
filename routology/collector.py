from dataclasses import dataclass
from typing import TYPE_CHECKING

from routology.utils import HostID

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from routology.dispatcher import DispatchedProbeReport


@dataclass
class NodeReport:
    """"""

    udp_probe: DispatchedProbeReport
    tcp_probe: DispatchedProbeReport
    icmp_probe: DispatchedProbeReport


@dataclass
class Hop:
    """A report for a hop."""

    ttl: int
    nodes: dict[HostID, list[NodeReport]]


@dataclass
class HostReport:
    """A report for a host."""

    addr: IPv4Address | IPv6Address
    hops: list[Optional[Hop]]

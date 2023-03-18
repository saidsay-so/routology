from asyncio import gather
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from aiostream.stream.time import timeout

from routology.dispatcher import DispatchedProbeReport, Dispatcher
from routology.sender import HostSender
from routology.utils import HostID

if TYPE_CHECKING:
    from typing import AsyncGenerator


@dataclass
class Host:
    """A host to probe."""

    id: HostID
    addr: str
    sender: HostSender
    subscription: AsyncGenerator[DispatchedProbeReport, None]
    last_rtt: float = field(init=False, default=0.0)
    current_rtt: float = field(init=False, default=0.0)
    last_ttl: int = field(init=False, default=0)
    current_ttl: int = field(init=False, default=0)
    last_series: int = field(init=False, default=1)
    current_series: int = field(init=False, default=1)
    last_time: datetime = field(init=False, default=datetime.now())
    current_time: datetime = field(init=False, default=datetime.now())



class Scheduler:
    """Schedules sending probes to hosts
    and receiving responses from hosts with the dispatcher."""

    _dispatcher: Dispatcher
    _hosts: dict[HostID, Host]
    _series: int
    _send_wait: float
    _max: float
    _here: float
    _near: float

    def __init__(
        self,
        hosts: list[HostID],
        dispatcher: Dispatcher,
        series: int = 1,
        send_wait: float = 0.1,
        max: float = 5.0,
        here: float = 3.0,
        near: float = 10.0,
    ):
        self._dispatcher = dispatcher
        self._send_wait = send_wait
        self._series = series
        self._max = max
        self._here = here
        self._near = near
        self._sent_probes = {host: [] for host in hosts}
        self._hosts = {
            host: Host(
                host, str(host), HostSender(host), self._dispatcher.subscribe(host)
            )
            for host in hosts
        }

    async def _host_schedule(self, host: HostID) -> None:
        """Schedules sending probes to a host."""
        host_info = self._hosts[host]
        sender = host_info.sender
        subscription = host_info.subscription

        await sender.send_probes(self._series, range(host_info.last_ttl, host_info.current_ttl))

        timeout(subscription, self._max)

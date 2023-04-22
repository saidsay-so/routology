from __future__ import annotations

from asyncio import gather, sleep
from itertools import product
from logging import Logger, getLogger
from typing import TYPE_CHECKING, Optional

from more_itertools import batched

from routology.dispatcher import DispatchedProbeReport, Dispatcher
from routology.probe import ProbeType
from routology.sender import SendRequest, Sender
from routology.utils import HostID

if TYPE_CHECKING:
    from typing import AsyncGenerator, Callable, TypeVar

    T = TypeVar("T")


class Scheduler:
    """Schedules sending probes to hosts while filtering out hosts that have already responded."""

    _subscription: AsyncGenerator[DispatchedProbeReport, None]
    _sender: Sender
    _hosts: set[HostID]
    _stop_send: dict[ProbeType, set[HostID]]
    _series: int
    _max_hops: int
    _sim_probes: int
    _send_wait: float
    _finished_callback: Callable[[], None]
    _progress_callback: Callable[[int], None]
    _logger: Logger

    def __init__(
        self,
        hosts: list[HostID],
        dispatcher: Dispatcher,
        sender: Sender,
        series: int,
        max_hops: int,
        sim_probes: int,
        send_wait: float,
        first_ttl: int,
        finished_callback: Callable[[], None] = lambda: None,
        progress_callback: Callable[[int], None] = lambda _: None,
        logger: Optional[Logger] = None,
    ):
        self._subscription = dispatcher.subscribe()
        self._sender = sender
        self._send_wait = send_wait
        self._series = series
        self._max_hops = max_hops
        self._first_ttl = first_ttl
        self._sim_probes = sim_probes
        self._hosts = {host for host in hosts}
        self._stop_send = {ptype: set() for ptype in ProbeType}
        self._finished_callback = finished_callback
        self._progress_callback = progress_callback
        self._logger = logger or getLogger(__name__)

    async def run(self):
        """Schedule sending probes to hosts and receiving responses from hosts."""
        await gather(
            self.report_task(),
            self.send_task(),
        )
        self._logger.info("Scheduler finished")

    async def report_task(self):
        """Receive reports from the dispatcher and update the hosts list."""
        async for report in self._subscription:
            if (
                report.final
                and report.series == self._series - 1
                and report.host_id in self._hosts
            ):
                self._stop_send[report.probe_type].add(report.host_id)

    async def send_task(self):
        """Send probes to hosts."""
        reqs = (
            SendRequest(ttl, serie, host, probe_type)
            for ttl, host, serie, probe_type in product(
                range(self._first_ttl, self._max_hops + 1),
                self._hosts,
                range(0, self._series),
                (ProbeType.UDP, ProbeType.TCP, ProbeType.ICMP),
            )
        )

        for probe_batch in batched(
            reqs,
            self._sim_probes,
        ):
            probes = [
                probe
                for probe in probe_batch
                if probe.host not in self._stop_send[probe.probe_type]
            ]
            await self._sender.send_probes(
                probes,
                pkt_send_time=self._send_wait,
            )
            self._progress_callback(len(probes))
            # We need to check if there are any hosts left to probe
            if not self._hosts:
                break

        self._logger.info("Scheduler finished sending probes")
        self._finished_callback()

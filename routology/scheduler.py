from __future__ import annotations

from asyncio import (
    PriorityQueue,
    create_task,
    gather,
    wait,
    get_event_loop,
    Event,
    sleep,
)
from dataclasses import dataclass, field
from datetime import datetime
from itertools import cycle, islice, product, starmap
from logging import Logger, getLogger
from typing import TYPE_CHECKING, Optional

from aiostream.stream.time import timeout
from more_itertools import batched, interleave_longest

from routology.dispatcher import DispatchedProbeReport, Dispatcher
from routology.sender import SendRequest, Sender, ProbeInfo
from routology.utils import HostID

if TYPE_CHECKING:
    from typing import AsyncGenerator, Iterable, Iterator, TypeVar
    from asyncio import Task

    T = TypeVar("T")


class Scheduler:
    """Schedules sending probes to hosts
    and receiving responses from hosts with the dispatcher."""

    _subscription: AsyncGenerator[DispatchedProbeReport, None]
    _sender: Sender
    _hosts: set[HostID]
    _series: int
    _max_hops: int
    _sim_probes: int
    _send_wait: float

    def __init__(
        self,
        hosts: list[HostID],
        dispatcher: Dispatcher,
        sender: Sender,
        series: int = 1,
        max_hops: int = 30,
        sim_probes: int = 32,
        send_wait: float = 1,
        logger: Optional[Logger] = None,
    ):
        self._subscription = dispatcher.subscribe()
        self._sender = sender
        self._send_wait = send_wait
        self._series = series
        self._max_hops = max_hops
        self._sim_probes = sim_probes
        self._hosts = {host for host in hosts}
        self._logger = logger or getLogger(__name__)

    async def run(self):
        """Schedule sending probes to hosts and receiving responses from hosts."""
        await gather(
            self.report_task(),
            self.waker_task(),
        )
        self._logger.info("Scheduler finished")

    async def report_task(self):
        """Schedule sending probes to hosts and receiving responses from hosts."""
        async for report in self._subscription:
            if report.node_ip == report.host_id.addr and report.host_id in self._hosts:
                self._hosts.remove(report.host_id)

    async def waker_task(self):
        """Wake up the sender at the scheduled intervals."""
        for probe_batch in batched(
            (
                SendRequest(ttl, serie, host)
                for ttl, host, serie in product(
                    range(1, self._max_hops),
                    (host for host in self._hosts),
                    range(0, self._series),
                )
            ),
            self._sim_probes,
        ):
            await self._sender.send_probes(
                [probe for probe in probe_batch if probe.host in self._hosts],
            )
            await sleep(self._send_wait)
            # We need to check if there are any hosts left to probe
            if not self._hosts:
                break

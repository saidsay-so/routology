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
from typing import TYPE_CHECKING

from aiostream.stream.time import timeout

from routology.dispatcher import DispatchedProbeReport, Dispatcher
from routology.sender import HostSender, ProbeInfo
from routology.utils import HostID

if TYPE_CHECKING:
    from typing import AsyncGenerator, Callable
    from asyncio import Task


@dataclass
class Host:
    """A host to probe."""

    id: HostID
    addr: str
    sender: HostSender
    probe_sender: ScheduledProbeSend | None = None


class Scheduler:
    """Schedules sending probes to hosts
    and receiving responses from hosts with the dispatcher."""

    _subscription: AsyncGenerator[DispatchedProbeReport, None]
    _hosts: dict[HostID, Host]
    _series: int
    _max_hops: int
    _sim_probes: int
    _send_wait: float
    _max: float
    _here: float
    _near: float
    _tasks: set[Task]
    _waker_queue: PriorityQueue[tuple[datetime, Event, HostID]]

    def __init__(
        self,
        hosts: list[HostID],
        dispatcher: Dispatcher,
        series: int = 1,
        max_hops: int = 30,
        sim_probes: int = 15,
        send_wait: float = 0.1,
        max_time: float = 5.0,
        here: float = 3.0,
        near: float = 10.0,
    ):
        self._subscription = dispatcher.subscribe()
        self._send_wait = send_wait
        self._series = series
        self._max_hops = max_hops
        self._sim_probes = sim_probes
        self._max = max_time
        self._here = here
        self._near = near
        self._sent_probes = {host: [] for host in hosts}
        self._hosts = {
            host: Host(
                host,
                str(host),
                HostSender(host, self._add_probe, get_event_loop()),
            )
            for host in hosts
        }
        self._tasks = set()

    def _add_probe(self, probe: ProbeInfo):
        self._sent_probes[probe.host].append(probe)

    async def run(self):
        """Schedule sending probes to hosts and receiving responses from hosts."""
        for host in self._hosts.values():
            sender = ScheduledProbeSend(
                host.sender,
                self._series,
                self._max_hops,
                self._add_probe,
                self._send_wait,
            )
            host.probe_sender = sender
            task = create_task(sender.run())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.remove)

        await gather(
            self.report_task(),
            self.waker_task(),
        )

    async def report_task(self):
        """Schedule sending probes to hosts and receiving responses from hosts."""
        async for report in self._subscription:
            if report.node_ip == report.host_id.addr and report.host_id in self._hosts:
                self._hosts[report.host_id].probe_sender.stop()
                del self._hosts[report.host_id]

            if report.node_ip in self._hosts:
                self._hosts[report.node_ip].probe_sender.wake()

    async def waker_task(self):
        """Wake up the sender at the scheduled intervals."""
        while True:
            longest_wait = self._send_wait
            for host in self._hosts.values():
                if host.probe_sender is not None:
                    self._waker_queue.put_nowait(
                        (datetime.now(), host.probe_sender._event_flag, host.id)
                    )


class PriorityWaiter:
    """Wait for the next event to wake up."""

    _queue: PriorityQueue[tuple[datetime, Event]]
    _send_wait: float

    def __init__(self, sim_probes: int, send_wait: float):
        self._queue = PriorityQueue(sim_probes)
        self._send_wait = send_wait

    async def wait_probes_count(self, event: Event):
        """Wait for the next event to wake up."""
        await self._queue.put((datetime.now(), event))
        await event.wait()

    async def run(self):
        """Wait for the next event to wake up."""
        while True:
            await sleep(self._send_wait)
            _, event = await self._queue.get()
            event.set()


class ScheduledProbeSend:
    """A sender which sends probes each time it's woken up."""

    _stop: bool

    _sender: HostSender
    _series: int
    _max_hops: int
    _probe_info_collector: Callable[[ProbeInfo], None]
    _send_wait: float
    _sim_probes: int
    _event_flag: Event
    _last_sent: datetime

    def __init__(
        self,
        sender: HostSender,
        series: int,
        max_hops: int,
        probe_info_collector: Callable[[ProbeInfo], None],
        send_wait: float,
        event: Event = Event(),
    ):
        self._sender = sender
        self._series = series
        self._max_hops = max_hops
        self._probe_info_collector = probe_info_collector
        self._send_wait = send_wait
        self._stop = False
        self._event_flag = event
        self._last_sent = datetime.now()
        self._remaining_probes = self._max_hops * self._series

    def wake(self):
        """Wake up the sender."""
        self._event_flag.set()

    def stop(self):
        """Stop sending probes."""
        self.wake()
        self._stop = True

    @property
    def last_sent(self):
        """Get the time the last probe was sent."""
        return self._last_sent

    async def run(self):
        """Send probes at the scheduled intervals."""
        for ttl in range(1, self._max_hops):
            for serie in range(1, self._series):
                # TODO: Send probes in batches of self._sim_probes
                await self._sender.send_probes(serie, ttl)
                self._last_sent = datetime.now()

            if self._stop:
                return

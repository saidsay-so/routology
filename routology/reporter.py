from logging import Logger, getLogger

from rich.progress import (
    Progress,
    TimeElapsedColumn,
    TextColumn,
    SpinnerColumn,
    MofNCompleteColumn,
    TaskProgressColumn,
    BarColumn,
    TimeRemainingColumn,
)
from rich.live import Live
from rich.console import Group

from datetime import datetime
from asyncio import Event


class Reporter:
    """Terminal reporter to show progress of the algorithm."""

    def __init__(
        self,
        max_hops: int,
        num_hosts: int,
        series: int,
        pkt_size: int,
        logger: Logger | None = None,
    ):
        self._logger = logger or getLogger(__name__)
        self._total_probes = max_hops * num_hosts * series * 3
        self._probes_progress = Progress(
            TextColumn("{task.description}"),
            MofNCompleteColumn(),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
        )
        self._probes_task = self._probes_progress.add_task(
            f"Probes of size {pkt_size} bytes, {max_hops} hops, {num_hosts} hosts, {series} series",
            total=self._total_probes,
        )
        self._timeout_progress = Progress(
            TimeElapsedColumn(),
            TextColumn("[bold red]Waiting for responses [/bold red]"),
            SpinnerColumn(style="red"),
        )
        self._timeout_task = self._timeout_progress.add_task("timeout", total=None)
        self._timeout = datetime.now()
        self._stop = Event()

    def update_probes_callback(self, num_sent: int):
        self._probes_progress.update(self._probes_task, advance=num_sent)

    def complete_timeout_callback(self):
        self._stop.set()

    async def run(self):
        with Live(
            Group(self._probes_progress, self._timeout_progress),
            transient=True,
            refresh_per_second=30,
        ):
            await self._stop.wait()

        t = self._probes_progress.tasks[0]
        skipped = t.total - t.completed if t.total else 0
        if skipped:
            print(f"Skipped {skipped} probes")
            print()

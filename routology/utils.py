from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from asyncio import wait_for
from itertools import cycle

from aiostream import streamcontext, operator
from aiostream.aiter_utils import anext

from socket import gethostbyname

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import AsyncIterable, Callable, TypeVar, Any

    T = TypeVar("T")


@operator(pipable=True)
async def dynamic_timeout(
    source: AsyncIterable[T],
    timeout: Callable[[], float],
    should_exit: Callable[[], bool],
) -> AsyncIterable[T]:
    """Yield items from an async iterable with a dynamic timeout.

    The timeout is reset every time an item is yielded.
    """
    async with streamcontext(source) as streamer:
        while True:
            try:
                item = await wait_for(anext(streamer), timeout())
            except StopAsyncIteration:
                break
            except TimeoutError as timeout_error:
                if should_exit():
                    raise timeout_error
            else:
                yield item


class HostID:
    """Host IP address."""

    id: int
    addr: IPv4Address | IPv6Address

    def __init__(self, id: int):
        self.id = id
        self.addr = ip_address(id)
        self.name = None

    @classmethod
    def from_addr(cls, addr: IPv4Address | IPv6Address) -> HostID:
        """Get host ID from an IP address."""
        return cls(int(addr))

    @classmethod
    def from_name(cls, host: str) -> HostID:
        """Get host ID from a hostname (IPv4 only)."""
        return cls(int(ip_address(gethostbyname(host))))

    def __int__(self) -> int:
        return self.id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HostID):
            raise NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"HostID({self.addr})"

    def __str__(self) -> str:
        return str(self.addr)


class Incrementer:
    """A simple incrementer."""

    _min: int
    _max: int
    _it: Any

    def __init__(self, min: int = 0, max: int = 2**16 - 1):
        self._min = min
        self._max = max
        self._it = iter(cycle(range(min, max + 1)))

    def __call__(self) -> int:
        return next(self._it)

    def __repr__(self) -> str:
        return f"Incrementer(min={self._min}, max={self._max})"

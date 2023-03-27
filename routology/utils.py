from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from asyncio import wait_for

from aiostream import streamcontext, operator
from aiostream.aiter_utils import anext

from logging import getLogger

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import AsyncIterable, Callable, TypeVar

    T = TypeVar("T")


@operator(pipable=True)
async def dynamic_timeout(
    source: AsyncIterable[T], timeout: Callable[[], float]
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
            else:
                yield item


class HostID:
    """Host IP address."""

    id: int
    addr: IPv4Address | IPv6Address

    def __init__(self, id: int):
        self.id = id
        self.addr = ip_address(id)

    @classmethod
    def from_addr(cls, addr: IPv4Address | IPv6Address) -> "HostID":
        """Get host ID from an IP address."""
        return cls(int(addr))

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

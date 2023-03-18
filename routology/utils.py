from ipaddress import IPv4Address, IPv6Address, ip_address


class HostID:
    """Host IP address."""

    id: int

    def __init__(self, id: int):
        self.id = id

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
        return f"HostID({str(self.id)})"

    def __str__(self) -> str:
        return str(ip_address(self.id))

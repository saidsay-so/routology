from enum import Enum, auto


class ProbeType(Enum):
    UDP = auto()
    TCP = auto()
    ICMP = auto()

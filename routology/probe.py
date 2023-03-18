from enum import Enum, auto


class ProbeType(Enum):
    TCP = auto()
    ICMP = auto()
    ICMP6 = auto()
    UDP = auto()

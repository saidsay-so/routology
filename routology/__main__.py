from ipaddress import ip_address
import asyncio
from random import randint
import os

from routology.collector import Collector, Hop, Node
from routology.dispatcher import Dispatcher
from routology.scheduler import Scheduler
from routology.sender import (
    ICMPProbeInfo,
    ProbeInfo,
    Sender,
    TCPProbeInfo,
    UDPProbeInfo,
)
from routology.utils import HostID

if os.name == "nt":
    import os.path

    if not os.path.isfile("C:\\Program Files\\Npcap\\NPFInstall.exe"):
        from routology.npcap_helper import install_npcap

        print("Npcap is not installed, installing it now...")
        install_npcap()

import typer
from scapy.layers.inet import TCP, UDP, ICMP
#from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded, ICMPv6EchoReply

app = typer.Typer()


@app.command(help="traceroute, but not better.")
def main(
    ipv4: bool = typer.Option(False, "-4", help="Use IPv4"),
    ipv6: bool = typer.Option(False, "-6", help="Use IPv6"),
    debug: bool = typer.Option(False, "-d", "--debug", help="Debug mode"),
    dont_fragment: bool = typer.Option(
        False, "-F", "--dont-fragment", help="Do not fragment packets"
    ),
    first_ttl: int = typer.Option(
        1, "-f", "--first-ttl", help="Start from the first_ttl hop (instead from 1)"
    ),
    gateway: str = typer.Option(
        None,
        "-g",
        "--gateway",
        help="Route packets through the specified gateway (maximum 8 for IPv4 and 127 for IPv6)",
    ),
    # We already have a default way to send probes
    # icmp: bool = typer.Option(
    #     False, "-I", "--icmp", help="Use ICMP ECHO instead of UDP datagrams"
    # ),
    # tcp: bool = typer.Option(
    #     False, "-T", "--tcp", help="Use TCP SYN instead of UDP datagrams"
    # ),
    # udp: bool = typer.Option(
    #     False,
    #     "--udp",
    #     help="Use UDP datagrams instead of ICMP ECHO or TCP SYN",
    # ),
    # udp_lite: bool = typer.Option(
    #     False,
    #     "-UL",
    #     help="Use UDP-Lite datagrams instead of ICMP ECHO or TCP SYN",
    # ),
    # dccp: bool = typer.Option(
    #     False,
    #     "-D",
    #     "--dccp",
    #     help="Use DCCP datagrams instead of ICMP ECHO or TCP SYN",
    # ),
    # protocol: int = typer.Option(
    #     None,
    #     "-P",
    #     "--protocol",
    #     help="Use the specified protocol instead of ICMP ECHO or TCP SYN",
    # ),
    # We're platform agnostic, so we don't need to worry about this
    # interface: str = typer.Option(
    #     None, "-i", "--interface", help="Use the specified interface"
    # ),
    max_hops: int = typer.Option(
        30, "-m", "--max-hops", help="Set the maximum number of hops"
    ),
    sim_queries: int = typer.Option(
        16, "-N", "--sim-queries", help="Set the number of simultaneous probes"
    ),
    no_dns: bool = typer.Option(
        False, "-n", help="Do not resolve addresses to hostnames"
    ),
    tcp_port: int = typer.Option(
        33434, "-p", "--port", help="Set the destination port for TCP SYN probes"
    ),
    udp_port: int = typer.Option(
        33434, "-p", "--port", help="Set the destination port for UDP probes"
    ),
    tos: int = typer.Option(
        0, "-q", "--tos", help="Set the TOS (IPv4)/TC (IPv6) field in probe packets"
    ),
    flow_label: int = typer.Option(
        0, "-Q", "--flow-label", help="Set the IPv6 flow label in probe packets"
    ),
    wait: tuple[int, int, int] = typer.Option(
        (5, 3, 10),
        "-w",
        "--wait",
        help="""Wait for a probe no more than HERE times longer than a response from the same hop,
        or no more than NEAR times than some next hop,
        or MAX seconds in total.""",
    ),
    queries: int = typer.Option(
        3, "-q", "--queries", help="Set the number of probes per hop"
    ),
    direct: bool = typer.Option(
        False,
        "-r",
        help="Bypass the normal routing and send directly to a host on an attached network",
    ),
    source_address: str = typer.Option(
        None,
        "-s",
        "--source-address",
        help="Use the specified source address for outgoing packets",
    ),
    sendwait: float = typer.Option(
        0.0,
        "-z",
        "--sendwait",
        help="Wait for a specified number of seconds (or in milliseconds if more than 10) between sending probes",
    ),
    extension: bool = typer.Option(
        None,
        "-e",
        "--extensions",
        help="Show ICMP extensions (if present), including MPLS",
    ),
    as_lookup: bool = typer.Option(
        False,
        "-A",
        "--as-path-lookups",
        help="Perform AS path lookups using the RIPE NCC's RIS whois service",
    ),
    # module: str = typer.Option(
    #     None,
    #     "-M",
    #     "--module",
    #     help="Use the specified module to perform the traceroute",
    # ),
    # module_options: str = typer.Option(
    #     None,
    #     "-O",
    #     "--options",
    #     help="Use module-specific options to perform the traceroute",
    # ),
    # source_port: int = typer.Option(
    #     None,
    #     "--sport",
    #     help="Use the specified source port for outgoing packets",
    # ),
    # firewall_mark: int = typer.Option(
    #     None,
    #     "--fwmark",
    #     help="Use the specified firewall mark for outgoing packets",
    # ),
    mtu: bool = typer.Option(
        False,
        "--mtu",
        help="Discover the MTU along the path being traced",
    ),
    back: bool = typer.Option(
        False,
        "--back",
        help="Guess the number of hops in the backward path",
    ),
    hosts_file: str = typer.Argument(
        ...,
        help="The hosts file to use for the traceroute",
    ),
    size: int = typer.Argument(
        60,
        help="The size of the packet to send",
    ),
) -> None:
    import logging
    import sys

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    root.addHandler(handler)

    asyncio.run(
        _main(
            ipv4=ipv4,
            ipv6=ipv6,
            debug=debug,
            dont_fragment=dont_fragment,
            first_ttl=first_ttl,
            gateway=gateway,
            max_hops=max_hops,
            sim_queries=sim_queries,
            no_dns=no_dns,
            tcp_port=tcp_port,
            udp_port=udp_port,
            tos=tos,
            flow_label=flow_label,
            wait=wait,
            queries=queries,
            direct=direct,
            source_address=source_address,
            sendwait=sendwait,
            extension=extension,
            as_lookup=as_lookup,
            mtu=mtu,
            back=back,
            hosts_file=hosts_file,
            size=size,
        )
    )


def get_hosts(hosts_file: str) -> list[HostID]:
    import logging

    hosts = set()
    logger = logging.getLogger(__name__)
    with open(hosts_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                hosts.add(HostID.from_addr(ip_address(line)))
            except ValueError:
                # TODO: IPv6 support?
                hosts.add(HostID.from_name(line))
            except:
                logger.warning(f"Invalid host: {line}")
                raise

    return list(hosts)


def get_tcp_info(infos: list[ProbeInfo], probe: TCP) -> ProbeInfo | None:
    return next(
        (
            info
            for info in infos
            if isinstance(info, TCPProbeInfo)
            and info.sport == probe.sport
            and info.dport == probe.dport
            and info.seq == probe.seq
        ),
        None,
    )


def get_udp_info(infos: list[ProbeInfo], probe: UDP) -> ProbeInfo | None:
    return next(
        (
            info
            for info in infos
            if isinstance(info, UDPProbeInfo)
            and info.sport == probe.sport
            and info.dport == probe.dport
        ),
        None,
    )


def get_icmp_info(infos: list[ProbeInfo], id: int, probe: ICMP) -> ProbeInfo | None:
    return next(
        (
            info
            for info in infos
            if isinstance(info, ICMPProbeInfo)
            and info.id == id
            and info.seq == probe.seq
        ),
        None,
    )


async def _main(
    ipv4: bool,
    ipv6: bool,
    debug: bool,
    dont_fragment: bool,
    first_ttl: int,
    gateway: str,
    max_hops: int,
    sim_queries: int,
    no_dns: bool,
    tcp_port: int,
    udp_port: int,
    tos: int,
    flow_label: int,
    wait: tuple[int, int, int],
    queries: int,
    direct: bool,
    source_address: str,
    sendwait: float,
    extension: bool,
    as_lookup: bool,
    mtu: bool,
    back: bool,
    hosts_file: str,
    size: int,
) -> None:
    loop = asyncio.get_event_loop()
    hosts = get_hosts(hosts_file)
    probes_info: list[ProbeInfo] = []
    icmp_id = randint(0, 2**16 - 1)

    dispatcher = Dispatcher(
        lambda p: get_tcp_info(probes_info, p),
        lambda p: get_udp_info(probes_info, p),
        lambda p: get_icmp_info(probes_info, icmp_id, p),
        lambda x: None,
    )

    collector = Collector(
        hosts=hosts,
        dispatcher=dispatcher,
        max_hops=max_hops,
        delay=wait[0],
        series=queries,
        send_wait=sendwait,
        sim_probes=sim_queries,
    )
    scheduler = Scheduler(
        hosts=hosts,
        dispatcher=dispatcher,
        sender=Sender(probes_info.append, loop, icmp_id=icmp_id),
        send_wait=sendwait,
        series=queries,
        sim_probes=sim_queries,
        max_hops=max_hops,
        finished_callback=collector.start_timeout,
    )

    _, _, collected = await asyncio.gather(
        scheduler.run(), dispatcher.run(), collector.run()
    )
    # loop.run_until_complete(loop.shutdown_asyncgens())


app()

from __future__ import annotations

from ipaddress import ip_address
import asyncio
from random import randint
import os
import csv

from netgraph import InteractiveGraph


from routology.collector import Collector
from routology.dispatcher import Dispatcher
from routology.outputs.graph import draw_graph
from routology.outputs.text import TextOutputFormatter
from routology.reporter import Reporter
from routology.scheduler import Scheduler
from routology.sender import (
    ICMPProbeInfo,
    ProbeInfo,
    Sender,
    TCPProbeInfo,
    UDPProbeInfo,
)
from routology.utils import HostID, Incrementer
from typing import TYPE_CHECKING, Optional

from dns.asyncresolver import Resolver
from dns.resolver import LRUCache
import matplotlib.pyplot as plt
from rich.progress import track
import networkx as nx

if TYPE_CHECKING:
    from typing import AsyncGenerator
    from routology.collector import Hop

if os.name == "nt":
    import os.path

    if not os.path.isfile("C:\\Program Files\\Npcap\\NPFInstall.exe"):
        from routology.npcap_helper import install_npcap

        print("Npcap is not installed, installing it now...")
        install_npcap()

import typer
from scapy.layers.inet import TCP, UDP, ICMP

# from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded, ICMPv6EchoReply

app = typer.Typer()


@app.command(help="traceroute, but not better.")
def main(
    ipv4: bool = typer.Option(False, "-4", help="Use IPv4"),
    # ipv6: bool = typer.Option(False, "-6", help="Use IPv6"),
    debug: bool = typer.Option(False, "-d", "--debug", help="Debug mode"),
    dont_fragment: bool = typer.Option(
        False, "-F", "--dont-fragment", help="Do not fragment packets"
    ),
    first_ttl: int = typer.Option(
        1, "-f", "--first-ttl", help="Start from the first_ttl hop (instead from 1)"
    ),
    # gateway: str = typer.Option(
    #     None,
    #     "-g",
    #     "--gateway",
    #     help="Route packets through the specified gateway (maximum 8 for IPv4 and 127 for IPv6)",
    # ),
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
        33434, "-T", "--tcp-port", help="Set the destination port for TCP SYN probes"
    ),
    udp_port: int = typer.Option(
        33434, "-U", "--udp-port", help="Set the destination port for UDP probes"
    ),
    tos: int = typer.Option(
        0, "-q", "--tos", help="Set the TOS (IPv4)/TC (IPv6) field in probe packets"
    ),
    # flow_label: int = typer.Option(
    #     0, "-Q", "--flow-label", help="Set the IPv6 flow label in probe packets"
    # ),
    wait: float = typer.Option(
        5,
        "-w",
        "--wait",
        help="""Wait responses for WAIT seconds after sending all probes (defaults to 5 seconds).""",
    ),
    queries: int = typer.Option(
        1, "-q", "--queries", help="Set the number of series of probes per hop"
    ),
    # direct: bool = typer.Option(
    #     False,
    #     "-r",
    #     help="Bypass the normal routing and send directly to a host on an attached network",
    # ),
    # source_address: str = typer.Option(
    #     None,
    #     "-s",
    #     "--source-address",
    #     help="Use the specified source address for outgoing packets",
    # ),
    sendwait: float = typer.Option(
        0.0,
        "-z",
        "--sendwait",
        help="Wait for a specified number of seconds between sending probes",
    ),
    extension: bool = typer.Option(
        None,
        "-e",
        "--extensions",
        help="Show ICMP extensions (if present), including MPLS",
    ),
    # as_lookup: bool = typer.Option(
    #     False,
    #     "-A",
    #     "--as-path-lookups",
    #     help="Perform AS path lookups using the RIPE NCC's RIS whois service",
    # ),
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
    source_port: Optional[int] = typer.Option(
        None,
        "--sport",
        help="Use the specified source port for outgoing packets",
    ),
    # firewall_mark: int = typer.Option(
    #     None,
    #     "--fwmark",
    #     help="Use the specified firewall mark for outgoing packets",
    # ),
    # mtu: bool = typer.Option(
    #     False,
    #     "--mtu",
    #     help="Discover the MTU along the path being traced",
    # ),
    # back: bool = typer.Option(
    #     False,
    #     "--back",
    #     help="Guess the number of hops in the backward path",
    # ),
    hosts_file: str = typer.Argument(
        ...,
        help="The hosts file to use for the traceroute",
    ),
    size: int = typer.Argument(
        60,
        help="The size of the packet to send",
    ),
    output_text_file: str = typer.Option(
        "routology.txt",
        help="The output text file to write to",
    ),
    output_image_file: str = typer.Option(
        "routology.png",
        help="The output text file to write to",
    ),
) -> None:
    if first_ttl > max_hops:
        typer.echo("First TTL must be less than or equal to max hops")
        raise typer.Exit(1)

    if size > 65500:
        typer.echo("Packet size must be less than or equal to 65500")
        raise typer.Exit(1)

    if debug:
        import logging
        import sys

        root = logging.getLogger()
        root.handlers = []
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
            # ipv6=ipv6,
            debug=debug,
            dont_fragment=dont_fragment,
            first_ttl=first_ttl,
            # gateway=gateway,
            max_hops=max_hops,
            sim_queries=sim_queries,
            no_dns=no_dns,
            sport=source_port,
            tcp_port=tcp_port,
            udp_port=udp_port,
            tos=tos,
            # flow_label=flow_label,
            wait=wait,
            queries=queries,
            # direct=direct,
            # source_address=source_address,
            sendwait=sendwait,
            extension=extension,
            # as_lookup=as_lookup,
            # mtu=mtu,
            # back=back,
            hosts_file=hosts_file,
            pkt_size=size,
            output_text_file=output_text_file,
            output_image_file=output_image_file,
        )
    )


def get_hosts(hosts_file: str) -> list[HostID]:
    import logging

    hosts = set()
    logger = logging.getLogger(__name__)

    with open(hosts_file) as f:
        if hosts_file.endswith(".csv"):
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                for host in row:
                    try:
                        hosts.add(HostID.from_addr(ip_address(row[0])))
                    except ValueError:
                        # TODO: IPv6 support?
                        hosts.add(HostID.from_name(host))
                    except:
                        logger.warning(f"Invalid host: {host}")
                        raise

        else:
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


def get_icmp_info(
    infos: list[ProbeInfo], icmp_id: int, probe: ICMP
) -> ProbeInfo | None:
    return next(
        (
            info
            for info in infos
            if isinstance(info, ICMPProbeInfo)
            and info.id == icmp_id
            and info.seq == probe.seq
        ),
        None,
    )


def normalize_hops(hops: list[Optional[Hop]], dest: HostID):
    for i, hop in enumerate(hops):
        if hop is None:
            continue

        stop = False
        for probe_type in ("icmp_probe", "tcp_probe", "udp_probe"):
            res = getattr(hop, probe_type, None)
            if res:
                if res.node_ip == dest.addr:
                    del hops[i + 1 :]
                    stop = True
                    break

        if stop:
            break


async def map_hops(
    hops: list[Optional[Hop]], attr: str, resolver: Optional[Resolver]
) -> AsyncGenerator[tuple[str, str, float], None]:
    for i, hop in enumerate(hops):
        response = getattr(hop, attr, None)
        if resolver and response:
            try:
                res = await resolver.resolve_address(str(response.node_ip))
                name = res[0].target.to_unicode(omit_final_dot=True)  # type: ignore
            except Exception:
                name = str(response.node_ip)
        else:
            name = str(response.node_ip) if response else "Unknown node"

        value = (
            (f"Unknown node {i}", name, 1)
            if response is None
            else (
                str(response.node_ip),
                name,
                int(response.rtt),
            )
        )
        yield value


async def _main(
    ipv4: bool,
    # ipv6: bool,
    debug: bool,
    dont_fragment: bool,
    first_ttl: int,
    # gateway: str,
    max_hops: int,
    sim_queries: int,
    no_dns: bool,
    tcp_port: int,
    udp_port: int,
    sport: Optional[int],
    tos: int,
    # flow_label: int,
    wait: float,
    queries: int,
    # direct: bool,
    # source_address: str,
    sendwait: float,
    extension: bool,
    # as_lookup: bool,
    # mtu: bool,
    # back: bool,
    output_text_file: str,
    output_image_file: str,
    hosts_file: str,
    pkt_size: int,
) -> None:
    loop = asyncio.get_running_loop()
    hosts = get_hosts(hosts_file)
    probes_info: list[ProbeInfo] = []
    icmp_id = randint(0, 2**16 - 1)

    dispatcher = Dispatcher(
        lambda p: get_tcp_info(probes_info, p),
        lambda p: get_udp_info(probes_info, p),
        lambda p: get_icmp_info(probes_info, icmp_id, p),
        lambda x: None,
    )

    reporter = Reporter(
        max_hops=max_hops,
        num_hosts=len(hosts),
        series=queries,
        pkt_size=pkt_size,
    )

    collector = Collector(
        hosts=hosts,
        dispatcher=dispatcher,
        max_hops=max_hops,
        delay=wait,
        series=queries,
        send_wait=sendwait,
        sim_probes=sim_queries,
        finished_callback=reporter.complete_timeout_callback,
    )
    ip_id_getter = Incrementer()
    tcp_seq_getter = Incrementer(max=2**32 - 1)
    icmp_seq_getter = Incrementer()

    scheduler = Scheduler(
        hosts=hosts,
        dispatcher=dispatcher,
        sender=Sender(
            probes_info.append,
            loop,
            packet_size=pkt_size,
            icmp_id=icmp_id,
            dont_fragment=dont_fragment,
            tcp_sport=sport or 0,
            udp_sport=sport or 0,
            udp_dport=udp_port,
            tcp_dport=tcp_port,
            ip_id_getter=ip_id_getter,
            tcp_seq_getter=tcp_seq_getter,
            icmp_seq_getter=icmp_seq_getter,
        ),
        send_wait=sendwait,
        series=queries,
        sim_probes=sim_queries,
        max_hops=max_hops,
        first_ttl=first_ttl,
        finished_callback=collector.start_timeout,
        progress_callback=reporter.update_probes_callback,
    )

    _, _, skipped, collected = await asyncio.gather(
        scheduler.run(),
        dispatcher.run(),
        reporter.run(),
        collector.run(),
    )
    # loop.run_until_complete(loop.shutdown_asyncgens())

    typer.echo(f"Skipped {skipped} probes")

    for host in hosts:
        for serie in collected[host].series:
            normalize_hops(serie, host)

    resolver = Resolver()
    resolver.cache = LRUCache(max_hops * queries)
    text_output = TextOutputFormatter(
        collected,
        queries,
        resolver=resolver,
        loop=loop,
        no_dns=no_dns,
    )
    await text_output.format()

    typer.echo(text_output)

    with open(output_text_file, "w") as f:
        f.write(str(text_output))

    inc = Incrementer()

    G = nx.DiGraph()
    base_node = f"Source"
    G.add_node(base_node)

    for host in track(collected):
        for attr, title in (
            ("udp_probe", "UDP"),
            ("tcp_probe", "TCP"),
            ("icmp_probe", "ICMP"),
        ):
            hops = [
                [
                    hop
                    async for hop in map_hops(
                        serie, attr, resolver if not no_dns else None
                    )
                ]
                for serie in collected[host].series
            ]

            draw_graph(G, base_node, hops, title, host, inc)

    lens = nx.get_edge_attributes(G, "length")
    colors = nx.get_edge_attributes(G, "color")
    plot_instance = InteractiveGraph(
        G,
        node_labels=True,
        node_label_offset=0.05,
        arrows=True,
        node_layout="geometric",
        node_layout_kwargs=dict(edge_length=lens),
        edge_color=colors,
    )

    plt.show()
    plt.savefig(output_image_file)


app()

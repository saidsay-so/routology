import typer
import asyncio

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
        (1, 0, 0),
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
    asyncio.run(_main())


async def _main():
    pass


app()

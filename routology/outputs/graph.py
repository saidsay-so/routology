from __future__ import annotations

import networkx as nx

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable

COLORS = {
    "UDP": "blue",
    "TCP": "green",
    "ICMP": "red",
}


def draw_graph(
    G: nx.DiGraph,
    base_node: Any,
    ip_rtt_list: list[list[tuple[str, str, float]]],
    probe_type: str,
    final_dst: Any,
    get_node_id: Callable[[], int],
):
    # Analyser la liste d'adresses IP et de RTT
    for num, serie in enumerate(ip_rtt_list):
        max_rtt = max(rtt for _, _, rtt in serie)
        src_node = base_node
        for ip, node, rtt in serie:
            node = f"{node} ({ip}) - {probe_type}"
            G.add_node(node, ip=ip, serie=num)
            G.add_edge(
                src_node,
                node,
                length=rtt / max_rtt,
                color=COLORS[probe_type],
                serie=num,
            )
            src_node = node

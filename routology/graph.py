# import networkx as nx
# import matplotlib.pyplot as plt
# from matplotlib.offsetbox import OffsetImage, AnnotationBbox
# import numpy as np

# # define the list of IP addresses
# ip_list = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']

# # create the graph and add the nodes
# G = nx.Graph()
# G.add_nodes_from(ip_list)

# # add edges between the nodes
# G.add_edge('192.168.1.1', '192.168.1.2')
# G.add_edge('192.168.1.1', '192.168.1.3')
# G.add_edge('192.168.1.1', '192.168.1.4')
# G.add_edge('192.168.1.2', '192.168.1.3')
# G.add_edge('192.168.1.3', '192.168.1.4')

# # generate the layout of the nodes
# pos = nx.spring_layout(G)

# # create a list to store the positions of the nodes
# node_positions = []

# # add the positions of each node to the list
# for node in G.nodes:
#     xy = pos[node]
#     node_positions.append(xy)

# # define the router image
# router_img = plt.imread('router.png')

# # create the plot
# fig, ax = plt.subplots(figsize=(10, 8))

# # draw the edges
# nx.draw_networkx_edges(G, pos, alpha=0.5)

# # draw the nodes with the router icon
# for node, xy in zip(G.nodes, node_positions):
#     router_node = OffsetImage(router_img, zoom=0.3)
#     router_node.image.axes = ax
#     router_dict = {'192.168.1.1': router_node, '192.168.1.2': router_node, '192.168.1.3': router_node, '192.168.1.4': router_node}
#     ab = AnnotationBbox(router_dict[node], xy, frameon=False)
#     ax.add_artist(ab)

# # show the plot
# plt.show()

from networkx import DiGraph
from ipaddress import IPv4Address
from socket import getnameinfo
from pyvis.network import Network


def draw_graph(collected, queries):
    G = DiGraph()
    root = "host"
    G.add_node(root, size=10)
    for host in collected:
        prev = root
        current = None
        for serie in range(queries):
            for probe_type in ("tcp_probe", "udp_probe", "icmp_probe"):
                for i, node in enumerate(
                    map(
                        lambda hop: getattr(hop.nodes[serie], probe_type, None)
                        if hop
                        else None,
                        collected[host].hops,
                    )
                ):
                    if node is None:
                        g_node = f"Unknown hop {i}"
                    else:
                        addr = (
                            (str(node.node_ip), 0)
                            if isinstance(node.node_ip, IPv4Address)
                            else (str(node.node_ip), 0, 0, 0)
                        )
                        # TODO: could be async
                        hostname = getnameinfo(addr, 0)[0]
                        g_node = f"{hostname or node.node_ip} ({node.node_ip})"

                    G.add_node(
                        g_node,
                        group=probe_type,
                    )

    nt = Network("1080px")
    nt.from_nx(G)
    nt.show("test.html", notebook=False)

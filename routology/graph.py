import networkx as nx
import matplotlib.pyplot as plt


def draw_graph(ip_rtt_list: list[tuple[str, float]]):
    # Analyser la liste d'adresses IP et de RTT
    G = nx.Graph()
    for ip, rtt in ip_rtt_list:
        G.add_node(ip)
        G.nodes[ip]["rtt"] = rtt

    for i in range(len(ip_rtt_list) - 1):
        src_ip, src_rtt = ip_rtt_list[i]
        dst_ip, _ = ip_rtt_list[i + 1]
        edge_weight = src_rtt
        G.add_edge(src_ip, dst_ip, rtt=edge_weight)

    # Dessiner le graphique
    pos = nx.spring_layout(G)
    edge_labels = nx.get_edge_attributes(G, "rtt")
    nx.draw_networkx_edges(
        G,
        pos,
        edgelist=G.edges(),
        arrowsize=[d["rtt"] for (u, v, d) in G.edges(data=True)],
    )
    nx.draw_networkx_edge_labels(G, pos)
    nx.draw(G, pos, with_labels=True)
    plt.show()

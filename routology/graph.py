import networkx as nx
import matplotlib.pyplot as plt
from multiprocessing import Process


list_a=[('192.168.1.1', 78.462), ('80.10.234.177', 126.468), ('193.253.81.150', 167.107), ('193.252.98.177', 199.111), ('193.252.137.74', 239.116), ('74.125.50.250', 64.007), ('108.170.244.225', 112.01), ('142.251.253.33', 120.022), ('Unknown node 8', 1), ('Unknown node 9', 1), ('Unknown node 10', 1), ('Unknown node 11', 1), ('Unknown node 12', 1), ('Unknown node 13', 1), ('Unknown node 14', 1), ('Unknown node 15', 1), ('Unknown node 16', 1), ('Unknown node 17', 1), ('Unknown node 18', 1), ('Unknown node 19', 1)] 
list_b=[('Unknown node 20', 1), ('Unknown node 21', 1), ('Unknown node 22', 1), ('Unknown node 23', 1), ('Unknown node 24', 1), ('Unknown node 25', 1), ('Unknown node 26', 1), ('Unknown node 27', 1), ('Unknown node 28', 1), ('Unknown node 29', 1)]

import socket

def ip_to_dns(ip_list):
    dns_list = []
    for ip, rtt in ip_list:
        try:
            # Résoudre le nom DNS à partir de l'adresse IP
            dns = socket.gethostbyaddr(ip)[0]
            print(dns)
        except (socket.herror,socket.gaierror):
            dns = ip
        dns_list.append((dns,rtt))
    return dns_list


def draw_graph(ip_rtt_list):
#def draw_graph(ip_rtt_list: list[tuple[str, float]]):
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

if __name__ == '__main__':
    list_b=ip_to_dns(list_b)
    list_a=ip_to_dns(list_a)
    p1 = Process(target=draw_graph,args=(list_a,))
    p1.start()
    p2 = Process(target=draw_graph,args=(list_b,))
    p2.start()
    p1.join()
    p2.join()
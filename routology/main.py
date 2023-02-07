from scapy.all import *
import networkx as nx
import matplotlib.pyplot as plt


def traceroute(hostname):
    hops = []
    for i in range(1, 28):
        pkt = IP(dst=hostname, ttl=i) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=1)
        if reply is None:
            break
        else:
            hops.append(reply.src)
    return hops


hostname = "www.google.com"
result = traceroute(hostname)
print(result)

G = nx.DiGraph()

for i in range(len(result) - 1):
    G.add_edge(result[i], result[i + 1], weight=1.0 / (i + 1))
    src_name = result[i]
    dst_name = result[i + 1]
    G.nodes[result[i]]["name"] = src_name
    G.nodes[result[i + 1]]["name"] = dst_name

nx.draw(G, with_labels=True)
plt.savefig("topology.png")

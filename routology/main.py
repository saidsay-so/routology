import socket
import networkx as nx
import matplotlib.pyplot as plt


def traceroute(hostname):
    hops = []
    ttl = 1
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.settimeout(1)
        sock.sendto(b'', (hostname, 0))
        try:
            _, (host, _) = sock.recvfrom(512)
            host = host
        except socket.timeout:
            break
        hops.append(host)
        ttl += 1
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

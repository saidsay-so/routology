import socket
import networkx as nx
import matplotlib.pyplot as plt
import sys
import time


def traceroute(hostname):
    hops = []
    max_hops = 30
    dest_addr = socket.gethostbyname(hostname)
    port = 33434
    icmp = socket.getprotobyname("icmp")
    udp = socket.getprotobyname("udp")
    ttl = 1
    while True:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        recv_socket.settimeout(2)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        start_time = time.time()
        send_socket.sendto("".encode(), (hostname, port))
        curr_addr = None
        curr_name = None
        try:
            _, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]
            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_name = curr_addr
        except socket.error:
            pass
        finally:
            send_socket.close()
            recv_socket.close()

        rtt = time.time() - start_time
        hops.append((curr_addr, curr_name, rtt))

        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break

    return hops


hostname = sys.argv[1]
result = traceroute(hostname)
for i, hop in enumerate(result):
    print("{:2d} {:15s} ({:s}) {:.2f} ms".format(i + 1, hop[1], hop[0], hop[2] * 1000))

G = nx.DiGraph()

for i in range(len(result) - 1):
    G.add_edge(result[i], result[i + 1], weight=1.0 / (i + 1))
    src_name = result[i]
    dst_name = result[i + 1]
    G.nodes[result[i]]["name"] = src_name
    G.nodes[result[i + 1]]["name"] = dst_name

nx.draw(G, with_labels=True)
plt.savefig("topology.png")

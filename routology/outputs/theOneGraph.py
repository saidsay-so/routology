import networkx as nx
import matplotlib.pyplot as plt
from multiprocessing import Process


list_a=[('192.168.1.1', 78.462), ('80.10.234.177', 126.468), ('193.253.81.150', 167.107), ('193.252.98.177', 199.111), ('193.252.137.74', 239.116), ('74.125.50.250', 64.007), ('108.170.244.225', 112.01), ('142.251.253.33', 120.022), ('Unknown node 8', 1), ('Unknown node 9', 1), ('Unknown node 10', 1), ('Unknown node 11', 1), ('Unknown node 12', 1), ('Unknown node 13', 1), ('Unknown node 14', 1), ('Unknown node 15', 1), ('Unknown node 16', 1), ('Unknown node 17', 1), ('Unknown node 18', 1), ('Unknown node 19', 1)] 
list_b=[('Unknown node 20', 1), ('Unknown node 21', 1), ('Unknown node 22', 1), ('Unknown node 23', 1), ('Unknown node 24', 1), ('Unknown node 25', 1), ('Unknown node 26', 1), ('Unknown node 27', 1), ('Unknown node 28', 1), ('Unknown node 29', 1)]

import socket
s=1
def unknownhost(l):
    global s
    l.append(("Uknown"+str(s),2))
    s+=1
udp_list = []
tcp_list = []
icmp_list = []

def read_trc_result(result):
    

    with open('routology.txt', 'r') as f:
        for line in f:
            parts = line.split()
            # cas vide ***
            if len(parts)==4 :
                unknownhost(udp_list)
                unknownhost(tcp_list)
                unknownhost(icmp_list)
            if(len(parts)<10) :
                ind = [i for i in range(0,len(parts)) if parts[i]=='*']
                if len(ind)==1:
                    # le cas de * x x
                    if ind[0]==1:
                        unknownhost(udp_list)
                        tcp_list.append((parts[2],int(float(parts[4]))))
                        icmp_list.append((parts[5],int(float(parts[7]))))
                    # le cas de x * x
                    if ind[0]==4:
                        udp_list.append((parts[1],int(float(parts[3]))))
                        unknownhost(tcp_list)
                        icmp_list.append((parts[5],int(float(parts[7])))) 
                    # le cas de x x *
                    if ind[0]==7:
                        udp_list.append((parts[1],int(float(parts[3]))))
                        tcp_list.append((parts[4],int(float(parts[6]))))
                        unknownhost(icmp_list)
                if len(ind)==2:
                    if ind[0]==1 and ind[1]==2:
                        unknownhost(udp_list)
                        unknownhost(tcp_list)
                        icmp_list.append((parts[3],int(float(parts[5]))))
                    if ind[0]==1 and ind[1]==len(parts)-1:
                        unknownhost(udp_list)
                        tcp_list.append((parts[2],int(float(parts[4]))))
                        unknownhost(icmp_list)
                    if ind[0]==4 and ind[1]==5:
                        udp_list.append((parts[1],int(float(parts[3]))))
                        unknownhost(tcp_list)
                        unknownhost(icmp_list)                                
            #cas normale
            if len(parts)==10 and len(parts)>0 and parts[0]!="traceroute":                
                udp_list.append((parts[1],int(float(parts[3]))))
                tcp_list.append((parts[4],int(float(parts[6]))))
                icmp_list.append((parts[7],int(float(parts[9]))))
    print("UDP results:", udp_list)
    print("TCP results:", tcp_list)
    print("ICMP results:", icmp_list)


def ip_to_dns(ip_list):
    dns_list = []
    for ip, rtt in ip_list:
        try:
            # Résoudre le nom DNS à partir de l'adresse IP
            dns = socket.gethostbyaddr(ip)[0]
        except (socket.herror,socket.gaierror):
            dns = ip
        dns_list.append((dns,rtt))
    return dns_list


def draw_graph(ip_rtt_list, ax):
    # Analyser la liste d'adresses IP et de RTT
    G = nx.Graph()
    for ip, rtt in ip_rtt_list:
        G.add_node(ip)
        #G.nodes[ip]["rtt"] = rtt

    for i in range(len(ip_rtt_list) - 1):
        src_ip, src_rtt = ip_rtt_list[i]
        dst_ip, _ = ip_rtt_list[i + 1]
        edge_weight = src_rtt
        G.add_edge(src_ip, dst_ip, rtt=edge_weight)
    _, rtt_list=zip(*ip_rtt_list)
    print(rtt_list)
    # Dessiner le graphique
    pos = nx.spring_layout(G)
    nx.draw_networkx_edges(
        G,
        pos,
        #arrowsize=rtt_list,
        edgelist=G.edges(),
        ax=ax,arrows=True,
    )
    nx.draw_networkx_edge_labels(G, pos, ax=ax)
    nx.draw(G, pos, with_labels=True, ax=ax)
    print("!! " + str(len(G.edges())) + " " + str(len(rtt_list)) + " " + str(len(ip_rtt_list)))

"""
#read_trc_result("routology.txt")

#if __name__ == '__main__':
list_b=ip_to_dns(list_b)
list_a=ip_to_dns(list_a)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))
#draw_graph(udp_list, ax1)
ax1.set_title('Graph A')
plt.show()
"""
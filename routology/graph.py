import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
import numpy as np

# define the list of IP addresses
ip_list = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']

# create the graph and add the nodes
G = nx.Graph()
G.add_nodes_from(ip_list)

# add edges between the nodes
G.add_edge('192.168.1.1', '192.168.1.2')
G.add_edge('192.168.1.1', '192.168.1.3')
G.add_edge('192.168.1.1', '192.168.1.4')
G.add_edge('192.168.1.2', '192.168.1.3')
G.add_edge('192.168.1.3', '192.168.1.4')

# generate the layout of the nodes
pos = nx.spring_layout(G)

# create a list to store the positions of the nodes
node_positions = []

# add the positions of each node to the list
for node in G.nodes:
    xy = pos[node]
    node_positions.append(xy)

# define the router image
router_img = plt.imread('router.png')

# create the plot
fig, ax = plt.subplots(figsize=(10, 8))

# draw the edges
nx.draw_networkx_edges(G, pos, alpha=0.5)

# draw the nodes with the router icon
for node, xy in zip(G.nodes, node_positions):
    router_node = OffsetImage(router_img, zoom=0.3)
    router_node.image.axes = ax
    router_dict = {'192.168.1.1': router_node, '192.168.1.2': router_node, '192.168.1.3': router_node, '192.168.1.4': router_node}
    ab = AnnotationBbox(router_dict[node], xy, frameon=False)
    ax.add_artist(ab)

# show the plot
plt.show()

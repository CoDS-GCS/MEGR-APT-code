import networkx as nx
from networkx.readwrite import json_graph
import json
import pickle
import glob
import time 


def main():
    graph_file = "./dataset/darpa_trace/provenance_graphs/attack_Linux_3_provenance_graph_part1.pt"
    with open(graph_file, 'rb') as f:
        provenance_graph = pickle.load(f)
    print("First Graph Size: ",provenance_graph.number_of_nodes(),provenance_graph.number_of_edges())
    for i in range(2,9):
        start_time = time.time()
        graph_file_temp = './dataset/darpa_trace/provenance_graphs/attack_Linux_3_provenance_graph_part' + str(i)+'.pt'
        print("Joining", graph_file_temp)
        with open(graph_file_temp, 'rb') as f:
            provenance_graph_temp = pickle.load(f)
        print("The current Graph Size: ",provenance_graph_temp.number_of_nodes(),provenance_graph_temp.number_of_edges())
        provenance_graph = nx.compose(provenance_graph_temp,provenance_graph)
        print("Joining time: --- %s seconds ---" % (time.time() - start_time))
        provenance_graph_temp.clear()
        print("Composed Graph Size: ",provenance_graph.number_of_nodes(),provenance_graph.number_of_edges())
        graph_file_temp = "./dataset/darpa_trace/provenance_graphs/attack_Linux_3_provenance_graph_temp.pt"
        with open(graph_file_temp, 'wb') as f:
             pickle.dump(provenance_graph,f)
        print("Graph in",graph_file_temp)
        print("Graph joined & stored in time: --- %s seconds ---" % (time.time() - start_time))
    print("Linux 3 has constructed, joining completed")
if __name__ == "__main__":
    main()
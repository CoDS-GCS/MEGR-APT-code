import networkx as nx
from networkx.readwrite import json_graph
import json
import pickle
import glob
import time 
import networkx as nx 
from networkx.readwrite import json_graph
import os
import sys
import json
import matplotlib.pyplot as plt
import pickle
import time
import numpy as np
from rdflib import Graph, Namespace, URIRef , Literal , Bag , BNode
from rdflib.namespace import RDF
import os, psutil
process = psutil.Process(os.getpid())
def read_json_graph(filename):
    with open(filename) as f:
        js_graph = json.load(f)
    return json_graph.node_link_graph(js_graph)

def convert_provenanceGraph_to_rdf_star(provenance_graph,GRAPH_IRI):
    GRAPH_NAME = str(GRAPH_IRI.split("/")[-2])
    print("The provenance graph ",GRAPH_NAME," Number of nodes ",provenance_graph.number_of_nodes()," Number of edges ",provenance_graph.number_of_edges(),"\n\n")    
    turtle_graph_file = "@prefix " + GRAPH_NAME +': <' + GRAPH_IRI +'> .'
    turtle_graph_file += '\n@prefix ' + 'process: <' + GRAPH_IRI+'process/> .'
    turtle_graph_file += '\n@prefix ' + "file: <" + GRAPH_IRI+'file/> .'
    turtle_graph_file += '\n@prefix ' + 'flow: <' + GRAPH_IRI+'flow/> .'
    turtle_graph_file += '\n@prefix ' + 'pipe: <' + GRAPH_IRI+'pipe/> .'
    turtle_graph_file += '\n@prefix ' + 'event: <' + GRAPH_IRI+'event/> .'
    turtle_graph_file += '\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n'
    x = 5
    for node_id, node_attribute in list(provenance_graph.nodes(data=True)):
        subject_type = node_attribute["type"].lower()
        Subject = subject_type + ':' + node_id
        turtle_graph_file += ('\n' + Subject +' '+ GRAPH_NAME + ':uuid "' + str(node_id) + '" .')
        turtle_graph_file += ('\n' + Subject + ' a "' + subject_type.lower() + '" .')
        #Add attributes
        first_attribute = True
        attribute_found = False
        for attr_key,attr_value in node_attribute.items():
            if attr_value and str(attr_value).lower() not in ["na","none"," "] and attr_key != 'type':
                if first_attribute:
                    turtle_graph_file += ('\n' + Subject +' '+ GRAPH_NAME + ':attributes [ ')
                    first_attribute = False
                    attribute_found = True
                else:
                    turtle_graph_file += ';\n'
                turtle_graph_file += (GRAPH_NAME + ':' + attr_key + ' "' + str(attr_value) + '" ')
        if attribute_found:
            turtle_graph_file += "] ."

        for _, nextNode_id,edge_attr in provenance_graph.out_edges(node_id,data=True):
            object_type = provenance_graph.nodes[nextNode_id]['type'].lower()
            Object = object_type + ':' + nextNode_id   
            Predicate = 'event:' + edge_attr['type'].lower()
            turtle_graph_file += ('\n<< ' +  Subject + ' '+ Predicate + ' ' + Object + ' >> ' + GRAPH_NAME + ':timestamp "' + str(edge_attr['timestamp']) + '" .' )
    print("\nMemory usage to constract the provenance graph: ",process.memory_info().rss / (1024 ** 2),"MB")
    return turtle_graph_file

def process_a_graph(GRAPH_IRI,graph_file): 
    start_time = time.time()
    print("Converting", graph_file)
    print("Graph_IRI is",GRAPH_IRI)
    provenance_graph = read_json_graph(graph_file)
    for node_id, node_attrs in list(provenance_graph.nodes.data()):
        try:
            node_type = node_attrs["type"]
        except:
            provenance_graph.remove_node(node_id)
            continue
        if node_type == "FILE":    
            pg_object_paths = [path.lower() for path in node_attrs["object_paths"].split("=>")]
            pg_object_path_names = [path.lower().split("/")[-1].split(".")[0] for path in pg_object_paths]
            pg_object_path_names = [name for name in pg_object_path_names if name] 
            pg_object_path_names = '=>'.join(pg_object_path_names)
            provenance_graph.nodes[node_id]["object_paths"] = pg_object_path_names
    print("Converting",graph_file)
    print("Graph Size: ",provenance_graph.number_of_nodes()," nodes ",provenance_graph.number_of_edges()," edges")
    provenance_graph_rdf = convert_provenanceGraph_to_rdf_star(provenance_graph,GRAPH_IRI)
    provenance_graph.clear()
    rdf_graph_file = graph_file.replace(".json",".ttl") 
    with open(rdf_graph_file, "w") as turtle_file:
        turtle_file.write(provenance_graph_rdf)
    provenance_graph_rdf = None
    print("---Total Running Time : %s seconds ---" % (time.time() - start_time))
    return


def main():
    GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_1/"
    graph_file = "./dataset/darpa_tc3/provenance_graphs/attack_BSD_1_provenance_graph.json"
    process_a_graph(GRAPH_IRI,graph_file)
    
    GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_2/"
    graph_file = "./dataset/darpa_tc3/provenance_graphs/attack_BSD_2_provenance_graph.json"
    process_a_graph(GRAPH_IRI,graph_file)
    
    GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_3_4/"
    graph_file = "./dataset/darpa_tc3/provenance_graphs/attack_BSD_3&4_provenance_graph.json"
    process_a_graph(GRAPH_IRI,graph_file)
    
    GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/benign_BSD/"
    graph_file = "./dataset/darpa_tc3/provenance_graphs/benign_BSD_provenance_graph.json"
    process_a_graph(GRAPH_IRI,graph_file)
    
    print("Completed Converting CADETS host")

if __name__ == "__main__":
    main()
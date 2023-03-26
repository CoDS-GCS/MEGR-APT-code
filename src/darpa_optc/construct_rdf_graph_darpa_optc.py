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
import os, psutil

process = psutil.Process(os.getpid())


def read_json_graph(filename):
    with open(filename) as f:
        js_graph = json.load(f)
    return json_graph.node_link_graph(js_graph)


def convert_provenanceGraph_to_rdf_star(provenance_graph, GRAPH_IRI):
    start_time = time.time()
    GRAPH_NAME = str(GRAPH_IRI.split("/")[-2])
    print("The provenance graph ", GRAPH_NAME, " Number of nodes ", provenance_graph.number_of_nodes(),
          " Number of edges ", provenance_graph.number_of_edges())

    turtle_graph_file = "@prefix " + GRAPH_NAME + ': <' + GRAPH_IRI + '> .'
    turtle_graph_file += '\n@prefix ' + 'process: <' + GRAPH_IRI + 'process/> .'
    turtle_graph_file += '\n@prefix ' + "file: <" + GRAPH_IRI + 'file/> .'
    turtle_graph_file += '\n@prefix ' + 'flow: <' + GRAPH_IRI + 'flow/> .'
    turtle_graph_file += '\n@prefix ' + 'pipe: <' + GRAPH_IRI + 'pipe/> .'
    turtle_graph_file += '\n@prefix ' + 'shell: <' + GRAPH_IRI + 'shell/> .'
    turtle_graph_file += '\n@prefix ' + 'memory: <' + GRAPH_IRI + 'memory/> .'
    turtle_graph_file += '\n@prefix ' + 'event: <' + GRAPH_IRI + 'event/> .'
    turtle_graph_file += '\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n'
    for node_id, node_attribute in list(provenance_graph.nodes(data=True)):
        try:
            subject_type = node_attribute["type"].lower()
        except:
            continue
        Subject = subject_type + ':' + node_id
        turtle_graph_file += ('\n' + Subject + ' ' + GRAPH_NAME + ':uuid "' + str(node_id) + '" .')
        turtle_graph_file += ('\n' + Subject + ' a "' + subject_type.lower() + '" .')
        # Add attributes
        first_attribute = True
        attribute_found = False
        for attr_key, attr_value in node_attribute.items():
            if attr_value and str(attr_value).lower() not in ["na", "none", " "] and attr_key != 'type':
                if first_attribute:
                    turtle_graph_file += ('\n' + Subject + ' ' + GRAPH_NAME + ':attributes [ ')
                    first_attribute = False
                    attribute_found = True
                else:
                    turtle_graph_file += ';\n'
                turtle_graph_file += (GRAPH_NAME + ':' + attr_key + ' "' + str(attr_value) + '" ')
        if attribute_found:
            turtle_graph_file += "] ."

        for _, nextNode_id, edge_attr in provenance_graph.out_edges(node_id, data=True):
            object_type = provenance_graph.nodes[nextNode_id]['type'].lower()
            Object = object_type + ':' + nextNode_id
            Predicate = 'event:' + edge_attr['type'].lower().replace("event_", "")
            turtle_graph_file += (
                        '\n<< ' + Subject + ' ' + Predicate + ' ' + Object + ' >> ' + GRAPH_NAME + ':timestamp "' + str(
                    edge_attr['timestamp']) + '" .')
    print("---Running Time : %s seconds ---" % (time.time() - start_time))
    print("\nMemory usage : ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
    return turtle_graph_file


def process_a_graph(GRAPH_IRI, graph_file):
    start_time = time.time()
    print("Graph_IRI is", GRAPH_IRI)
    print("Converting", graph_file)
    provenance_graph = read_json_graph(graph_file)
    for node_id, node_attrs in list(provenance_graph.nodes.data()):
        try:
            node_type = node_attrs["type"]
        except:
            provenance_graph.remove_node(node_id)
            continue
        if node_type == "FILE":
            try:
                file_paths = node_attrs["file_paths"]
            except:
                file_paths = None
            if file_paths:
                pg_object_paths = [path.lower() for path in file_paths.split("=>")]
                pg_object_path_names = [path.lower().split("\\")[-1].split(".")[0] for path in pg_object_paths]
                pg_object_path_names = [name for name in pg_object_path_names if name]
                pg_object_path_names = '=>'.join(pg_object_path_names)
                provenance_graph.nodes[node_id]["file_paths"] = pg_object_path_names
        if node_type == "PROCESS":
            # handle image_path
            try:
                image_paths = node_attrs["image_paths"]
            except:
                image_paths = None
            if image_paths:
                pg_object_paths = [path.lower() for path in image_paths.split("=>")]
                pg_object_path_names = [path.lower().split("\\")[-1].split(".")[0] for path in pg_object_paths]
                pg_object_path_names = [name for name in pg_object_path_names if name]
                pg_object_path_names = '=>'.join(pg_object_path_names)
                provenance_graph.nodes[node_id]["image_paths"] = pg_object_path_names
            # handle commands
            try:
                command_lines = node_attrs["command_lines"]
            except:
                command_lines = None
            if command_lines:
                pg_object_paths = [path.lower() for path in command_lines.replace("\"","").split("=>")]
                pg_object_path_names = [path.lower().split(" ")[0].split("\\")[-1].split(".")[0] for path in pg_object_paths]
                pg_object_path_names = [name for name in pg_object_path_names if name]
                pg_object_path_names = '=>'.join(pg_object_path_names)
                provenance_graph.nodes[node_id]["command_lines"] = pg_object_path_names
    print("Graph Size: ", provenance_graph.number_of_nodes(), " nodes ", provenance_graph.number_of_edges(), " edges")
    provenance_graph_rdf = convert_provenanceGraph_to_rdf_star(provenance_graph, GRAPH_IRI)
    provenance_graph.clear()
    rdf_graph_file = graph_file.replace(".json", ".ttl").replace("provenance_graphs_v2","provenance_graphs_v2/rdf")
    with open(rdf_graph_file, "w") as turtle_file:
        turtle_file.write(provenance_graph_rdf)
    provenance_graph_rdf = None
    print("---Total Running Time : %s seconds ---" % (time.time() - start_time))
    print("Done Converting", graph_file)
    print("***************************")
    return


def main():
    for graph_file in glob.glob('./dataset/darpa_optc/provenance_graphs_v2/benign_*'):
        GRAPH_IRI = "http://grapt.org/darpa_optc/" + graph_file.split("/")[-1].replace(".json","/")
        process_a_graph(GRAPH_IRI, graph_file)
    for graph_file in glob.glob('./dataset/darpa_optc/provenance_graphs_v2/attack_*'):
        GRAPH_IRI = "http://grapt.org/darpa_optc/" + graph_file.split("/")[-1].replace(".json","/")
        process_a_graph(GRAPH_IRI, graph_file)


if __name__ == "__main__":
    main()
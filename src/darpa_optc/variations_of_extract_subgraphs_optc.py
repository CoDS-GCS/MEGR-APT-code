import networkx as nx
from networkx.readwrite import json_graph
import json
from statistics import mean
import random
import time
import dgl
import pickle
import glob
import argparse
import os
import torch
import torch.nn.functional as F
from torch_geometric.data import Data
import resource
import copy
import dask
from dask.distributed import Client, LocalCluster
import dask.bag as db
import psutil
process = psutil.Process(os.getpid())
from resource import *

parser = argparse.ArgumentParser()
parser.add_argument('--min-nodes', type=int, help='Minimum number of nodes for subgraphs', default=3)
parser.add_argument('--max-nodes-mult-qg', type=int, help='Maximum number of nodes for subgraphs', default=10)
parser.add_argument('--max-nodes-training', type=int, help='Maximum number of nodes for subgraphs', default=200)
parser.add_argument('--max-edges-mult-qg', type=int, help='Maximum number of edges for subgraphs', default=25)
parser.add_argument('--max-edges-training', type=int, help='Maximum number of edges for subgraphs', default=1000)
parser.add_argument("--test-a-qg",type=str,default=None,help="The name of the tested query graph.")
parser.add_argument("--pg-name",type=str,default=None,help="The nae of the tested provenance graph.")
parser.add_argument('--min-iocs', type=int, help='Minimum number of Query Graph IOCs to accept subgraph', default=1)
parser.add_argument('--output-prx', type=str, help='output file prefix ', default=None)
parser.add_argument('--explore', help='Explore The Provenance Graph ',action="store_true", default=False)
parser.add_argument('--abstract-edges', help='Keep abstracted subgraphs',action="store_true", default=False)
parser.add_argument('--benign', help='Process Benign graphs',action="store_true", default=False)
parser.add_argument('--attack', help='Process attack graphs',action="store_true", default=False)
parser.add_argument('--parallel', help='Encode Subgraphs in parallel',action="store_true", default=False)
parser.add_argument('--training', help='Prepare training set',action="store_true", default=False)
parser.add_argument('--ioc-file', nargs="?", help='Path of Query Graph IOCs file', default="./dataset/darpa_optc/query_graphs_allQgNodes.json")
parser.add_argument('--n-subgraphs', type=int, help='Number of Subgraph', default=200)
parser.add_argument('--IFS-extract', help='Use Influence Score in subgraph extraction',action="store_true", default=False)
parser.add_argument('--influence-score', type=int, help='Influence score while traversing', default=3)
parser.add_argument('--QG-all', help='Label all matched Query Graph Nodes',action="store_true", default=False)
parser.add_argument('--deephunter-extract', help='Use DeepHunter subgraph extraction method',action="store_true", default=False)
parser.add_argument('--depth', type=int, help='Maximum depth to traverse while generating subgraphs', default=4)



args = parser.parse_args()
print(args)
def print_memory_cpu_usage(message=None):
    print(message)
    print("Memory usage (ru_maxrss) : ",getrusage(RUSAGE_SELF).ru_maxrss/1024," MB")
    print("Memory usage (psutil) : ", psutil.Process(os.getpid()).memory_info().rss / (1024 ** 2), "MB")
    print('The CPU usage is (per process): ', psutil.Process(os.getpid()).cpu_percent(4))
    load1, load5, load15 = psutil.getloadavg()
    cpu_usage = (load15 / os.cpu_count()) * 100
    print("The CPU usage is : ", cpu_usage)
    print('used virtual memory GB:', psutil.virtual_memory().used / (1024.0 ** 3), " percent",
          psutil.virtual_memory().percent)
    return
def read_json_graph(filename):
    with open(filename) as f:
        js_graph = json.load(f)
    return json_graph.node_link_graph(js_graph)


def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
    return


def checkpoint(data, file_path):
    ensure_dir(file_path)
    torch.save(data,file_path)
    return


def explore_graph(g):
    print("Number of nodes: ", g.number_of_nodes())
    print("Number of edges: ", g.number_of_edges())
    x = list(g.nodes.data("type"))
    unique_nodes_types = list(set([y[1] for y in x]))
    print("\nUnique nodes type:", unique_nodes_types)
    for i in unique_nodes_types:
        print(i, ": ", len([node_id for node_id, node_type in g.nodes.data("type") if node_type == i]))
    x = list(g.edges.data("type"))
    unique_edges_types = list(set([y[2] for y in x]))
    print("\nUnique edges type:", unique_edges_types)
    for i in unique_edges_types:
        print(i, ": ", len([node_id for node_id, _, node_type in g.edges.data("type") if node_type == i]))


def label_candidate_nodes_QG_IOC(provenance_graph,query_graphs,query_graph_name):
    print("labelling matched query graph IOCs nodes")
    start_time = time.time()
    with open(args.ioc_file) as f:
        query_graphs_IOCs = json.load(f)

    if query_graph_name == "all":
        corresponding_query_IOCs_ips = [ioc.lower() for query_graph in query_graphs_IOCs for ioc in query_graphs_IOCs[query_graph]["ip"]]
        corresponding_query_IOCs_files = [ioc.lower() for query_graph in query_graphs_IOCs for ioc in
                                    query_graphs_IOCs[query_graph]["file"]]
    else:    
        corresponding_query_IOCs_ips = [ioc.lower() for ioc in query_graphs_IOCs[query_graph_name]["ip"]]
        corresponding_query_IOCs_files = [ioc.lower() for ioc in query_graphs_IOCs[query_graph_name]["file"]]
        query_graphs = {query_graph_name:query_graphs[query_graph_name]}
    query_ips = set()
    query_names = set()
    for query_graph in query_graphs.values():
        for node , node_attrs in list(query_graph.nodes.data()): 
            try:
                node_type = node_attrs["type"]
            except:
                query_graph.remove_node(node)
                continue
            if node_type == "FLOW":
                try:
                    if node_attrs["src_ip"].lower() in corresponding_query_IOCs_ips:
                        query_ips.add(node_attrs["src_ip"].lower())
                except:
                    continue
                try:
                    if node_attrs["dest_ip"].lower() in corresponding_query_IOCs_ips:
                        query_ips.add(node_attrs["dest_ip"].lower())
                except:
                    continue    
            elif node_type == "FILE":
                try:
                    name = node_attrs["file_path"].lower().split("\\")[-1].split(".")[0]
                    if name in corresponding_query_IOCs_files:
                        query_names.add(name)
                except:
                    continue
            elif node_type == "PROCESS" or node_type == "SHELL":
                try:
                    name = node_attrs["image_path"].lower().split("\\")[-1].split(".")[0]
                    if name in corresponding_query_IOCs_files:
                        query_names.add(name)
                except:
                    continue
    print("\nQuery Ids",query_ips)
    print("\nQuery Names",query_names)

    matched_nodes = {}
    for node_id, node_attrs in list(provenance_graph.nodes.data()):
        provenance_graph.nodes[node_id]["candidate"] = False
        ioc = ''
        try:
            node_type = node_attrs["type"]
        except:
            provenance_graph.remove_node(node_id)
            continue
        if node_type == "FLOW":
            try:
                pg_src_ip = node_attrs["src_ip"].lower()
            except:
                continue
            try:
                pg_dest_ip = node_attrs["dest_ip"].lower()
            except:
                continue    
            if pg_src_ip or pg_dest_ip:
                for q_ip in query_ips:
                    if q_ip == pg_src_ip or q_ip == pg_dest_ip:
                        provenance_graph.nodes[node_id]["candidate"] = True 
                        provenance_graph.nodes[node_id]["ioc"] = q_ip
                        if q_ip in matched_nodes:
                            matched_nodes[q_ip].append(node_id)
                        else:
                            matched_nodes[q_ip] = []
                            matched_nodes[q_ip].append(node_id)
        elif node_type == "FILE":
            try:
                pg_file_paths = [path.lower() for path in node_attrs["file_paths"].split("=>")]
                pg_file_names = [path.lower().split("\\")[-1].split(".")[0] for path in pg_file_paths]
                pg_file_names = [name for name in pg_file_names if name]
            except:
                continue
            if pg_file_names:
                for q_name in query_names:
                    if q_name in pg_file_names:
                        provenance_graph.nodes[node_id]["candidate"] = True 
                        provenance_graph.nodes[node_id]["ioc"] = q_name
                        if q_name in matched_nodes: 
                            matched_nodes[q_name].append(node_id)
                        else:
                            matched_nodes[q_name] = []
                            matched_nodes[q_name].append(node_id)

        elif node_type == "PROCESS" or node_type == "SHELL":
            try:
                pg_image_paths = [path.lower() for path in node_attrs["image_paths"].split("=>")]
                pg_image_names = [path.lower().split("\\")[-1].split(".")[0] for path in pg_image_paths]
                pg_image_names = [name for name in pg_image_names if name]                
            except:
                continue
            if pg_image_names:
                for q_name in query_names:
                    if q_name in pg_image_names:
                        provenance_graph.nodes[node_id]["candidate"] = True 
                        provenance_graph.nodes[node_id]["ioc"] = q_name
                        if q_name in matched_nodes: 
                            matched_nodes[q_name].append(node_id)
                        else:
                            matched_nodes[q_name] = []
                            matched_nodes[q_name].append(node_id) 
    count_matched_candidates = {}
    for n in matched_nodes:
        count_matched_candidates[n] = len(matched_nodes[n])
    all_matchedNodes = set([item for sublist in matched_nodes.values() for item in sublist])
    TraverseNodes = set([node_id for node_id, node_type in provenance_graph.nodes.data("type") if node_type == 'PROCESS'])
#      or node_type == 'SHELL'
    print("\nTotal number of process nodes:",len(TraverseNodes))
    print("\nTotal number of matched nodes:", len(all_matchedNodes))
    print(count_matched_candidates) 
    print("labelling Suspicious nodes in: --- %s seconds ---" % (time.time() - start_time))
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
    return matched_nodes , all_matchedNodes , TraverseNodes


def label_candidate_nodes_QG_all(provenance_graph,query_graph):
    print("labelling all matched query graph nodes")
    start_time = time.time()
    query_ips = set()
    query_names = set()
    query_paths = set()
    query_commands = set()
    for node , node_attrs in list(query_graph.nodes.data()): 
        try:
            node_type = node_attrs["type"]
        except:
            query_graph.remove_node(node)
            continue
        if node_type == "FLOW":
            try:
                query_ips.add(node_attrs["src_ip"].lower())
            except:
                continue
            try:
                query_ips.add(node_attrs["dest_ip"].lower())
            except:
                continue    
        elif node_type == "FILE":
            try:
                path = node_attrs["file_path"].lower()
                if "\\" in path:
                    query_paths.add(path)   
                query_names.add(path.split("\\")[-1].split(".")[0])
            except:
                continue
        elif node_type == "PROCESS" or node_type == "SHELL":
            try:
                path = node_attrs["image_path"].lower()
                if "\\" in path:
                    query_paths.add(path)   
                query_names.add(path.split("\\")[-1].split(".")[0])
            except:
                continue
            try:
                query_commands.add(node_attrs["command_line"].lower())
            except:
                continue
    print("\nQuery IPs",query_ips)
    print("\nQuery Names",query_names)
    print("\nQuery Paths",query_paths)
    print("\nQuery Commands",query_commands)
    

    matched_nodes = {}
    for node_id, node_attrs in list(provenance_graph.nodes.data()):
        provenance_graph.nodes[node_id]["candidate"] = False
        ioc = ''
        try:
            node_type = node_attrs["type"]
        except:
            provenance_graph.remove_node(node_id)
            continue
        if node_type == "FLOW":
            try:
                pg_src_ip = node_attrs["src_ip"].lower()
            except:
                continue
            try:
                pg_dest_ip = node_attrs["dest_ip"].lower()
            except:
                continue    
            if pg_src_ip or pg_dest_ip:
                for q_ip in query_ips:
                    if q_ip == pg_src_ip or q_ip == pg_dest_ip:
                        provenance_graph.nodes[node_id]["candidate"] = True 
                        provenance_graph.nodes[node_id]["ioc"] = q_ip
                        if q_ip in matched_nodes:
                            matched_nodes[q_ip].append(node_id)
                        else:
                            matched_nodes[q_ip] = []
                            matched_nodes[q_ip].append(node_id)
        elif node_type == "FILE":
            try:
                pg_file_paths = [path.lower() for path in node_attrs["file_paths"].split("=>")]
                pg_file_names = [path.lower().split("\\")[-1].split(".")[0] for path in pg_file_paths]
                pg_file_names = [name for name in pg_file_names if name]
            except:
                continue
            if pg_file_names:
                for q_name in query_names:
                    if q_name in pg_file_names:
                        provenance_graph.nodes[node_id]["candidate"] = True 
                        provenance_graph.nodes[node_id]["ioc"] = q_name
                        if q_name in matched_nodes: 
                            matched_nodes[q_name].append(node_id)
                        else:
                            matched_nodes[q_name] = []
                            matched_nodes[q_name].append(node_id)
            if pg_file_paths:                
                for q_path in query_paths:
                    if q_path in pg_file_paths:
                        provenance_graph.nodes[node_id]["candidate"] = True 
                        provenance_graph.nodes[node_id]["ioc"] = q_path
                        if q_path in matched_nodes: 
                            matched_nodes[q_path].append(node_id)
                        else:
                            matched_nodes[q_path] = []
                            matched_nodes[q_path].append(node_id)
        elif node_type == "PROCESS" or node_type == "SHELL":
            try:
                pg_image_paths = [path.lower() for path in node_attrs["image_paths"].split("=>")]
                pg_image_names = [path.lower().split("\\")[-1].split(".")[0] for path in pg_image_paths]
                pg_image_names = [name for name in pg_image_names if name]      

                pg_commands = [command.lower() for command in node_attrs["command_line"].split("=>")]
            except:
                continue
            if pg_image_names:
                for q_name in query_names:
                    if q_name in pg_image_names:
                        provenance_graph.nodes[node_id]["candidate"] = True 
                        provenance_graph.nodes[node_id]["ioc"] = q_name
                        if q_name in matched_nodes: 
                            matched_nodes[q_name].append(node_id)
                        else:
                            matched_nodes[q_name] = []
                            matched_nodes[q_name].append(node_id) 
            if pg_image_paths:
                for q_path in query_paths:
                    if q_path in pg_image_paths:
                        provenance_graph.nodes[node_id]["candidate"] = True 
                        provenance_graph.nodes[node_id]["ioc"] = q_path
                        if q_path in matched_nodes: 
                            matched_nodes[q_path].append(node_id)
                        else:
                            matched_nodes[q_path] = []
                            matched_nodes[q_path].append(node_id) 
            if pg_commands:
                for q_command in query_commands:
                    if q_command in pg_commands:
                        provenance_graph.nodes[node_id]["candidate"] = True 
                        provenance_graph.nodes[node_id]["ioc"] = q_command
                        if q_command in matched_nodes: 
                            matched_nodes[q_command].append(node_id)
                        else:
                            matched_nodes[q_command] = []
                            matched_nodes[q_command].append(node_id) 
    count_matched_candidates = {}
    for n in matched_nodes:
        count_matched_candidates[n] = len(matched_nodes[n])
    all_matchedNodes = set([item for sublist in matched_nodes.values() for item in sublist])
    processNodes = set([node_id for node_id, node_type in provenance_graph.nodes.data("type") if node_type == 'PROCESS'])
    print("\nTotal number of process nodes:",len(processNodes))
    print("\nTotal number of matched nodes:", len(all_matchedNodes))
    print(count_matched_candidates) 
    print("labelling Suspicious nodes in: --- %s seconds ---" % (time.time() - start_time))
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
    return matched_nodes , all_matchedNodes , processNodes

# extract suspicious subgraph from provenance graph 
def extract_suspGraphs_depth(networkx_graph,matched_ioc,matchedNodes,processNodes,min_nodes = None,max_nodes = None,depth = 4,max_edges=1000):
    print("Using Depth-based algorithm to extract subgraphs")
    start_time = time.time()
    suspGraphs = []    
    suspGraphs_iterations = {}
    matched_ioc_mask = copy.deepcopy(matched_ioc)
    sorted_IOCs = {k:n  for k,n in sorted(matched_ioc_mask.items(), key=lambda item: len(item[1]))}
    considered_per_ioc = {}
    
    #Traverse Forward & Backward 
    def AdaptiveBFS(root):
        level = 1
        visited = set()
        currentLevel = [root]
        subgraphEdges = []
        while currentLevel:
            nextLevel = set()
            for node in currentLevel:
                for next_node in networkx_graph.neighbors(node):
                    if (next_node not in visited) and (next_node in matchedNodes or  next_node in processNodes):
                        if args.abstract_edges:
                            # Keep only edges with distinct types to keep the abstract nature 
                            edge_data = networkx_graph.get_edge_data(node, next_node)
                            distinct_edges_keys = []
                            distinct_edges_types = set()
                            for key,edge_attr in edge_data.items():
                                if edge_attr['type'] not in distinct_edges_types:
                                    distinct_edges_types.add(edge_attr['type'])
                                    distinct_edges_keys.append(key)
                            subgraphEdges_temp = [(node , next_node , key) for key in distinct_edges_keys]
                        else:    
                            edge_attr = networkx_graph.get_edge_data(node, next_node).keys()
                            subgraphEdges_temp = [(node , next_node , key) for key in edge_attr]
                        subgraphEdges.extend(subgraphEdges_temp)
                        subgraphEdges_temp = None
                        nextLevel.add(next_node)
            if len(subgraphEdges) > max_edges:
                return None
            if depth:
                if level >= depth:
                    break
                else:
                    level += 1    
            for node in currentLevel:
                for previous_node in networkx_graph.predecessors(node):    
                    if (previous_node not in visited) and (previous_node in matchedNodes or  previous_node in processNodes):
                        if args.abstract_edges:
                            # Keep only edges with distinct types to keep the abstract nature
                            edge_data = networkx_graph.get_edge_data(previous_node, node)
                            distinct_edges_keys = []
                            distinct_edges_types = set()
                            for key,edge_attr in edge_data.items():
                                if edge_attr['type'] not in distinct_edges_types:
                                    distinct_edges_types.add(edge_attr['type'])
                                    distinct_edges_keys.append(key)
                            subgraphEdges_temp = [(previous_node, node , key) for key in distinct_edges_keys]      
                        else:
                            edge_attr = networkx_graph.get_edge_data(previous_node, node).keys()
                            subgraphEdges_temp = [(previous_node, node, key) for key in edge_attr]
                        subgraphEdges.extend(subgraphEdges_temp)
                        subgraphEdges_temp = None
                        nextLevel.add(previous_node)
                visited.add(node)
            if (len(visited)+len(nextLevel)) > max_nodes:
                return None
            if len(subgraphEdges) > max_edges:
                return None
            if depth:
                if level >= depth:
                    break
                else:
                    currentLevel = nextLevel
                    level += 1
            else:
                currentLevel = nextLevel
        return subgraphEdges
    for ioc, nodes in sorted_IOCs.items():
        considered_per_ioc[ioc] = 0
        for node in nodes:
            subgraphEdges = AdaptiveBFS(node)
            if subgraphEdges:
                subgraph = networkx_graph.edge_subgraph(subgraphEdges).copy()
                subgraphEdges = None
                if subgraph.number_of_nodes() >= min_nodes and subgraph.number_of_nodes() <= max_nodes and subgraph.number_of_edges() <= max_edges:
                    suspGraphs.append(subgraph.copy())
                    sorted_IOCs[ioc].remove(node)
                    considered_per_ioc[ioc] += 1
                subgraph.clear()
        
    print("Number of subgraphs:", len(suspGraphs))
    print("Number of subgraph per IOC:\n", considered_per_ioc)
    if len(suspGraphs) > 0:
        print("Average number of nodes in subgraphs:",round(mean([supgraph.number_of_nodes() for supgraph in suspGraphs])))
        print("Average number of edges in subgraphs:",round(mean([supgraph.number_of_edges() for supgraph in suspGraphs])))    
    print("Extract suspicious subgraphs in --- %s seconds ---" % (time.time() - start_time))
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
    return suspGraphs

def extract_suspGraphs_influence_score(networkx_graph,matched_ioc,processNodes,min_nodes = None,max_nodes = None,influence_score = 3,max_edges=1000):
    print("Using Influence-Score-based algorithm to extract subgraphs")
    start_time = time.time()
    suspGraphs = []    
    suspGraphs_iterations = {}
    matched_ioc_mask = copy.deepcopy(matched_ioc)
    sorted_IOCs = {k:n  for k,n in sorted(matched_ioc_mask.items(), key=lambda item: len(item[1]))}
    considered_per_ioc = {}
    
    #Traverse Forward & Backward with DFS and Influence score 
    def dfs(visited,ancestor_chain,subgraphEdges, node): 
        if len(visited) > max_nodes:
            return None
        if node not in visited:
            visited.add(node)
            for next_node in networkx_graph.neighbors(node):
                if next_node not in visited:
                    next_node_ancestors = set(ancestor for ancestor in networkx_graph.predecessors(next_node) if ancestor not in visited and ancestor in processNodes)
                    if (len(ancestor_chain)+len(next_node_ancestors)) >= influence_score:
                        continue
                    else: 
                        temp_ancestor_chain = ancestor_chain
                        ancestor_chain = ancestor_chain.union(next_node_ancestors)
                        edge_data = networkx_graph.get_edge_data(node, next_node)
                        subgraphEdges_temp = [(node , next_node , key) for key in edge_data]
                        subgraphEdges.extend(subgraphEdges_temp)
                        subgraphEdges_temp = None
                        dfs(visited,ancestor_chain,subgraphEdges, next_node)
                        ancestor_chain = temp_ancestor_chain
            for previous_node in networkx_graph.predecessors(node):
                if previous_node not in visited:
                    previous_node_ancestors = set(ancestor for ancestor in networkx_graph.predecessors(previous_node) if ancestor not in visited and ancestor in processNodes)
                    if (len(ancestor_chain)+len(previous_node_ancestors)) >= influence_score:
                        continue
                    else: 
                        temp_ancestor_chain = ancestor_chain
                        ancestor_chain = ancestor_chain.union(previous_node_ancestors)
                        edge_data = networkx_graph.get_edge_data(previous_node, node)
                        # Keep only edges with distinct types to keep the abstract nature 
                        distinct_edges_keys = []
                        distinct_edges_types = set()
                        for key,edge_attr in edge_data.items():
                            if edge_attr['type'] not in distinct_edges_types:
                                distinct_edges_types.add(edge_attr['type'])
                                distinct_edges_keys.append(key)
                        subgraphEdges_temp = [(previous_node, node , key) for key in distinct_edges_keys]
                        subgraphEdges.extend(subgraphEdges_temp)
                        subgraphEdges_temp = None
                        dfs(visited,ancestor_chain,subgraphEdges, previous_node)  
                        ancestor_chain = temp_ancestor_chain
        return subgraphEdges
    for ioc, nodes in sorted_IOCs.items():
        considered_per_ioc[ioc] = 0
        for node in nodes:
            subgraphEdges = []
            visited = set()
            ancestor_chain = set(node) if node in processNodes else set()
            subgraphEdges = dfs(visited,ancestor_chain,subgraphEdges,node)
            if subgraphEdges:
                subgraph = networkx_graph.edge_subgraph(subgraphEdges).copy()
                subgraphEdges = None
                if subgraph.number_of_nodes() >= min_nodes and subgraph.number_of_nodes() <= max_nodes and subgraph.number_of_edges() <= max_edges:
                    print("Extracted a suspicious subgraph from IOC", ioc, " with", subgraph.number_of_nodes(), "nodes, and ",
                          subgraph.number_of_edges(), "edges")
                    suspGraphs.append(subgraph.copy())
                    sorted_IOCs[ioc].remove(node)
                    considered_per_ioc[ioc] += 1
                subgraph.clear()
        
    print("Number of subgraphs:", len(suspGraphs))
    print("Number of subgraph per IOC:\n", considered_per_ioc)
    if len(suspGraphs) > 0:
        print("Average number of nodes in subgraphs:",round(mean([supgraph.number_of_nodes() for supgraph in suspGraphs])))
        print("Average number of edges in subgraphs:",round(mean([supgraph.number_of_edges() for supgraph in suspGraphs])))
    print("Extract suspicious subgraphs in --- %s seconds ---" % (time.time() - start_time))
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
    return suspGraphs


def extract_suspGraphs_with_deepHunter_method(networkx_graph, matched_ioc, matchedNodes, processNodes, depth=4):
    print("summarize provenance graph to get suspicious subgraphs ")
    start_time = time.time()
    seeds = [(k, n) for k, n in sorted(matched_ioc.items(), key=lambda item: len(item[1]))]
    seed = seeds[0][0]
    covered = set()
    covered.add(seed)
    print("seed node: ", seed)
    susp = nx.MultiDiGraph()
    suspGraphs = []

    # Traverse Forward & Backward
    def AdaptiveBFS(root, depth=None):
        level = 0
        visited = set()
        currentLevel = [root]
        while currentLevel:
            nextLevel = set()
            for node in currentLevel:
                for _, nEdge in networkx_graph.out_edges(node):
                    if (nEdge not in visited) and (nEdge in matchedNodes or nEdge in processNodes):
                        edge_attr = networkx_graph.get_edge_data(node, nEdge).keys()
                        for key in edge_attr:
                            yield node, nEdge, key
                        nextLevel.add(nEdge)
                for pEdge, _ in networkx_graph.in_edges(node):
                    if (pEdge not in visited) and (pEdge in matchedNodes or pEdge in processNodes):
                        edge_attr = networkx_graph.get_edge_data(pEdge, node).keys()
                        for key in edge_attr:
                            yield pEdge, node, key
                        nextLevel.add(pEdge)
                visited.add(node)
            if depth:
                if (depth - level) > 0:
                    level += 1
                elif (depth - level) == 0:
                    break
                else:
                    break
            else:
                currentLevel = nextLevel

    # AdaptiveBFSS return one traversed subgraph
    # susp contain the aggregation of subgraphs, it start with empty graphs, stops when it covers all IoCs
    def ExpandSearch(seedNodes, susp, depth=None):
        x = 0
        for node in seedNodes:
            x += 1
            startNode = node
            travNodes = []
            travNodes = AdaptiveBFS(startNode, depth)
            subgraphEdges = []
            for edge in iter(travNodes):
                subgraphEdges.append(edge)
            subgraph = networkx_graph.edge_subgraph(subgraphEdges).copy()
            subgraphEdges = None
            susp = nx.compose(susp, subgraph)
            subgraph = None
            # print("Traversed",x,"node of ")
            for ioc, nodes in seeds:
                if ioc not in covered:
                    for node in nodes:
                        if susp.has_node(node):
                            covered.add(ioc)
                            continue
            remain_nodes = [(ioc, nodes) for ioc, nodes in seeds if ioc not in covered]
            if not remain_nodes:
                suspGraphs.append(susp)
                # print("Done ", x ,"node")
            else:
                covered.add(remain_nodes[0][0])
                # print("next remain node: ", remain_nodes[0][0])
                ExpandSearch(remain_nodes[0][1], susp, depth)
        susp = None
        return suspGraphs

    suspGraphs = ExpandSearch(matched_ioc[seed], susp, depth)

    print("Number of subgraphs:", len(suspGraphs))
    if len(suspGraphs) > 0:
        print("Average number of nodes in subgraphs:",
              round(mean([supgraph.number_of_nodes() for supgraph in suspGraphs])))
        print("Average number of edges in subgraphs:",
              round(mean([supgraph.number_of_edges() for supgraph in suspGraphs])))
    print("Extraction Memory:", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
    print("--- Extraction time %s seconds ---" % (time.time() - start_time))
    return suspGraphs

def Extract_Random_Benign_Subgraphs(processGraph,n_subgraphs,min_nodes,max_nodes,max_edges,depth = 4):
    start_time = time.time()
    benignSubGraphs = []   
    benign_nodes = list(set([node_id for node_id, is_suspicious in processGraph.nodes.data("candidate") if is_suspicious == False]))
    suspicious_nodes = set([node_id for node_id, is_suspicious in processGraph.nodes.data("candidate") if is_suspicious == True])
    random.shuffle(benign_nodes) 
    print("Number of Benign Nodes:",len(benign_nodes))
    print("Number of Suspicious Nodes:",len(suspicious_nodes))
    
    def AdaptiveBFS(root):
        level = 1
        visited = set()
        currentLevel = [root]
        subgraphEdges = []
        while currentLevel:
            nextLevel = set()
            for node in currentLevel:
                for next_node in processGraph.neighbors(node):
                    if (next_node not in visited) and (next_node not in suspicious_nodes):
                        edge_attr = processGraph.get_edge_data(node, next_node).keys()
                        subgraphEdges_temp = [(node , next_node , key) for key in edge_attr]
                        subgraphEdges.extend(subgraphEdges_temp)
                        subgraphEdges_temp = None
            
                        nextLevel.add(next_node)
            if len(subgraphEdges) > max_edges:
                return None
            if depth:
                if level >= depth:
                    break
                else:
                    level += 1    
            for node in currentLevel:
                for previous_node in processGraph.predecessors(node):    
                    if (previous_node not in visited) and (previous_node not in suspicious_nodes):
                        edge_attr = processGraph.get_edge_data(previous_node, node).keys()
                        subgraphEdges_temp = [(previous_node, node, key) for key in edge_attr]
                        subgraphEdges.extend(subgraphEdges_temp)
                        subgraphEdges_temp = None
                        nextLevel.add(previous_node)
                visited.add(node)
            if len(subgraphEdges) > max_edges:
                return None
            if (len(visited)+len(nextLevel)) > max_nodes:
                return None
            if depth:
                if level >= depth:
                    break
                else:
                    currentLevel = nextLevel
                    level += 1
            else:
                currentLevel = nextLevel
        return subgraphEdges
    for node in benign_nodes:
        subgraphEdges = AdaptiveBFS(node)
        if subgraphEdges:
            subgraph = processGraph.edge_subgraph(subgraphEdges).copy()
            subgraphEdges = None
            if subgraph.number_of_nodes() >= min_nodes and subgraph.number_of_nodes() <= max_nodes and subgraph.number_of_edges() <= max_edges:
                benignSubGraphs.append(subgraph.copy())
            subgraph.clear()
        if len(benignSubGraphs) >= n_subgraphs:
            break
    print("Number of benign subgraphs:", len(benignSubGraphs))
    print("Max number of nodes in benign subgraphs:",max([supgraph.number_of_nodes() for supgraph in benignSubGraphs]))
    print("Min number of nodes in benign subgraphs:",min([supgraph.number_of_nodes() for supgraph in benignSubGraphs]))
    print("Average number of nodes in benign subgraphs:",round(mean([supgraph.number_of_nodes() for supgraph in benignSubGraphs])))
    print("Max number of edges in benign subgraphs:",max([supgraph.number_of_edges() for supgraph in benignSubGraphs]))
    print("Min number of edges in benign subgraphs:",min([supgraph.number_of_edges() for supgraph in benignSubGraphs]))
    print("Average number of edges in benign subgraphs:",round(mean([supgraph.number_of_edges() for supgraph in benignSubGraphs])))
    print("--- %s seconds ---" % (time.time() - start_time))
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
    processGraph,benign_nodes = None,None
    return benignSubGraphs



def subgraph_quality_check_per_query(subgraphs,matched_nodes,min_iocs=1):
    covered_attacks = {}
    # with open(args.ioc_file) as f:
    #     query_graphs_IOCs = json.load(f)
        
    # q_g_iocs = query_graphs_IOCs[query]
    accepted_subgraphs = []
    for i,g in enumerate(subgraphs):
        covered_ioc = set([nodes[1]["ioc"] for nodes in g.nodes.data() if nodes[1]["candidate"]])
        covered_ioc_per_query = []
        accepted = False
        for ioc in matched_nodes:
            if ioc.lower() in covered_ioc:
                covered_ioc_per_query.append(ioc.lower())
        if len(set(covered_ioc_per_query)) >= min_iocs:
            if min_iocs == args.min_iocs:
                print("This subgraph contains:",set(covered_ioc_per_query))
            accepted = True
        if accepted: 
            accepted_subgraphs.append(g)
    if len(subgraphs) == 0:
        print("No Subgraphs")
    else:
        print("Accepted",len(accepted_subgraphs)," out of ",len(subgraphs))
        print("Acceptance rate is: ",len(accepted_subgraphs)/len(subgraphs))
    if min_iocs == args.min_iocs:
        return accepted_subgraphs
    else:
        return

def encode_for_RGCN(g):
#     print("Encoding a subgraph with",g.number_of_nodes(),g.number_of_edges())
    types = ['PROCESS', 'SHELL', 'FILE', 'FLOW']
    mapping = {name: j for j, name in enumerate(g.nodes())}
    g = nx.relabel_nodes(g, mapping)
    x = torch.zeros(g.number_of_nodes(), dtype=torch.long)
    for node, info in g.nodes(data=True):
        x[int(node)] = types.index(info['type'])
    x = F.one_hot(x, num_classes=len(types)).to(torch.float)
    for node in g.nodes():
        g.nodes[node]["label"] = x[node]
    edge_types = ['RENAME', 'READ', 'DELETE', 'CREATE', 'OPEN', 'MESSAGE', 'COMMAND', 'WRITE', 'TERMINATE', 'MODIFY']
    for n1, n2, info in g.edges(data=True):
        for k, info in g.get_edge_data(n1, n2).items():
            g.edges[n1, n2, k]["edge_label"] = edge_types.index(info['type'])
    dgl_graph = dgl.from_networkx(g, node_attrs=["label"], edge_attrs=["edge_label"])
    g.clear()
    x = None
    return dgl_graph


def convert_prediction_to_torch_data(prediction_graphs_dgl,g_name):
    prediction_data_list = []
    for i,g in enumerate(prediction_graphs_dgl):
        edge_index = torch.tensor([g.edges()[0].tolist(),g.edges()[1].tolist()])    
        data = Data(edge_index= edge_index,g_name = g_name, i= str(i))
        data.num_nodes = g.number_of_nodes()
        data.nlabel = g.ndata['label']
        data.elabel = g.edata['edge_label']
        prediction_data_list.append(data)        
    return prediction_data_list


def convert_query_to_torch_data(query_graphs_dgl): 
    query_data_list = []
    for g_name,g in query_graphs_dgl.items():
        edge_index = torch.tensor([g.edges()[0].tolist(),g.edges()[1].tolist()])
        data = Data(edge_index=edge_index, g_name= g_name)
        data.num_nodes = g.number_of_nodes()
        data.nlabel = g.ndata['label']
        data.elabel = g.edata['edge_label']
        query_data_list.append(data)
    return query_data_list

def convert_to_torch_data(training_graphs, testing_graphs):
    training_data_list = []
    testing_data_list = []
    ids = 0
    for g in training_graphs:
        edge_index = torch.tensor([g.edges()[0].tolist(), g.edges()[1].tolist()])
        data = Data(edge_index=edge_index, i=ids)
        data.num_nodes = g.number_of_nodes()
        data.nlabel = g.ndata['label']
        data.elabel = g.edata['edge_label']
        training_data_list.append(data)
        ids += 1
    for g in testing_graphs:
        edge_index = torch.tensor([g.edges()[0].tolist(), g.edges()[1].tolist()])
        data = Data(edge_index=edge_index, i=ids)
        data.num_nodes = g.number_of_nodes()
        data.nlabel = g.ndata['label']
        data.elabel = g.edata['edge_label']
        testing_data_list.append(data)
        ids += 1
    return training_data_list, testing_data_list

def process_one_graph(graph_file, query_graphs,query_name,depth, min_nodes, max_nodes,max_edges):
    graph_name = graph_file.split("/")[-1].replace(".json", "")
    print("\nprocessing ", graph_name,"with",query_name)
    one_graph_time = time.time()
    current_mem = getrusage(RUSAGE_SELF).ru_maxrss
    provenance_graph = read_json_graph(graph_file)
    print("Loading the graph consume:", getrusage(RUSAGE_SELF).ru_maxrss - current_mem, "KB")
    print_memory_cpu_usage("Loading the graph")
    if args.QG_all:
        matched_nodes , all_matchedNodes , processNodes = label_candidate_nodes_QG_all(provenance_graph,query_graphs[query_name])
    else:    
        matched_nodes , all_matchedNodes , processNodes = label_candidate_nodes_QG_IOC(provenance_graph,query_graphs,query_name)
    if args.explore:
        explore_graph(provenance_graph)
    if len(all_matchedNodes) == 0:
        print("No suspicious nodes for",graph_name,"with",query_name)
        print("\nprocessed", graph_name, "with",query_name," in: --- %s seconds ---" % (time.time() - one_graph_time))
        print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
        return
    if args.IFS_extract:
        suspSubGraphs = extract_suspGraphs_influence_score(provenance_graph,matched_nodes , processNodes,min_nodes =min_nodes,max_nodes = max_nodes,influence_score =args.influence_score,max_edges=max_edges)
    elif args.deephunter_extract:
        suspSubGraphs = extract_suspGraphs_with_deepHunter_method(provenance_graph, matched_nodes, all_matchedNodes, processNodes, depth=depth)
    else:
        suspSubGraphs = extract_suspGraphs_depth(provenance_graph,matched_nodes , all_matchedNodes , processNodes,depth = depth,min_nodes = min_nodes,max_nodes = max_nodes,max_edges=max_edges)
    
    if len(suspSubGraphs) == 0:
        print("No subgraphs for",graph_name,"with",query_name)
        print("\nprocessed", graph_name, "with",query_name," in: --- %s seconds ---" % (time.time() - one_graph_time))
        print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
        return
    checkpoint(suspSubGraphs,
                      ("./dataset/darpa_optc/experiments/"+args.output_prx+"/predict/nx_suspicious_"+query_name+"_in_"+graph_name +  ".pt"))

    # delete the graph to free memory space
    provenance_graph.clear()

    for i in range(1,4):
        print("\nCheck Quality for",i," IOCs of corresponding query graph")
        if i == args.min_iocs:
            accepted_suspSubGraphs = subgraph_quality_check_per_query(suspSubGraphs,matched_nodes,min_iocs=i)
            print("\nAccepted Subgraphs with ",args.min_iocs," IOCs of corresponding query graph")
            print("Number of accepted subgraph:", len(accepted_suspSubGraphs))
            if accepted_suspSubGraphs == 0:
                print("No accepted subgraphs for",graph_name,"with",query_name)
                return
            checkpoint(accepted_suspSubGraphs,("./dataset/darpa_optc/experiments/"+args.output_prx+"/predict/nx_accepted_suspSubGraphs_"+query_name+"_in_"+graph_name +  ".pt"))
            suspSubGraphs = accepted_suspSubGraphs
        else: 
            subgraph_quality_check_per_query(suspSubGraphs,matched_nodes,min_iocs=i)
            
    if len(suspSubGraphs) == 0:
        print("No subgraphs for",graph_name,"with",query_name)
        print("\nprocessed", graph_name, "with", query_name, " in: --- %s seconds ---" % (time.time() - one_graph_time))
        print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
        return
    
    
    print("Encoding prediction subgraphs")
    
    if args.parallel:
        suspSubGraphs_dask = db.from_sequence(suspSubGraphs, npartitions=26)
        prediction_graphs_dgl = suspSubGraphs_dask.map(lambda g: encode_for_RGCN(g)).compute() 
    else:
        prediction_graphs_dgl = [encode_for_RGCN(g) for g in suspSubGraphs]
    checkpoint(prediction_graphs_dgl,
                      ("./dataset/darpa_optc/experiments/"+args.output_prx+"/predict/dgl_prediction_graphs_"+query_name+"_in_"+ graph_name + ".pt"))

    suspSubGraphs = None
    
    prediction_data_list_host = convert_prediction_to_torch_data(prediction_graphs_dgl,graph_name)
    prediction_graphs_dgl = None
    

    checkpoint(prediction_data_list_host,("./dataset/darpa_optc/experiments/"+args.output_prx+"/raw/torch_prediction/"+query_name+"_in_"+graph_name+".pt"))

    print("\nprocessed", graph_name, "with", query_name, " in: --- %s seconds ---" % (time.time() - one_graph_time))
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
    print("Number of prediction samples from host", graph_name, len(prediction_data_list_host))
    prediction_data_list_host = None
    return 

def process_one_graph_training(graph_file, query_graphs,query_name):
    graph_name = graph_file.split("/")[-1].replace(".json", "")
    print("\nprocessing ", graph_name,"with",query_name)
    one_graph_time = time.time()
    current_mem = getrusage(RUSAGE_SELF).ru_maxrss
    provenance_graph = read_json_graph(graph_file)
    print("Loading the graph consume:", getrusage(resource.RUSAGE_SELF).ru_maxrss - current_mem, "KB")
    print_memory_cpu_usage("Loading the graph")
    matched_nodes , all_matchedNodes , processNodes = label_candidate_nodes_QG_IOC(provenance_graph,query_graphs,query_name)
    if args.explore:
        explore_graph(provenance_graph)
        
    benignSubGraphs = Extract_Random_Benign_Subgraphs(provenance_graph,args.n_subgraphs,args.min_nodes,args.max_nodes_training,args.max_edges_training)
    
    # delete the graph to free memory space
    provenance_graph.clear()
    
    print("Encoding the random benign subgraphs")
    benignSubGraphs_dgl = [encode_for_RGCN(g) for g in benignSubGraphs]
    benignSubGraphs = None
    
    print("\nprocessed", graph_name, "with",query_name," in: --- %s seconds ---" % (time.time() - one_graph_time))
    return benignSubGraphs_dgl


def main():
    start_running_time = time.time()
    print_memory_cpu_usage("Initial memory")
    random.seed(123)
    if args.parallel:
        cluster = LocalCluster(n_workers=26)
        client = Client(cluster)
    print("processing query graphs")
    query_graphs = {}
    for graph_name in glob.glob('./dataset/darpa_optc/query_graphs/*'):
        query_graphs[graph_name.replace(".json","").split("/")[-1]] = read_json_graph(graph_name)
        
    query_graphs_dgl = {g_name:encode_for_RGCN(query_graphs[g_name]) for g_name in query_graphs}     
    
    query_data_list = convert_query_to_torch_data(query_graphs_dgl)
    print("processed",len(query_data_list),"query graphs")
    checkpoint(query_data_list,
                      ("./dataset/darpa_optc/experiments/"+args.output_prx+"/raw/torch_query_dataset.pt"))

    path = "./dataset/darpa_optc/provenance_graphs/"
    if args.training:
        training_dataset = []
        testing_dataset = []
        graph_file = path + "attack_SysClient0201.json"
        benignSubGraphs_dgl = process_one_graph_training(graph_file, query_graphs,"all")
        print("Add ", graph_file.split("/")[-1].replace(".json", ""), " to training set.\n\n")
        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None

        graph_file = path + "attack_SysClient0051.json"
        benignSubGraphs_dgl = process_one_graph_training(graph_file, query_graphs,"all")
        print("Add ", graph_file.split("/")[-1].replace(".json", ""), " to training set.\n\n")
        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
        
        graph_file = path + "attack_SysClient0501.json"
        benignSubGraphs_dgl = process_one_graph_training(graph_file, query_graphs,"all")
        print("Add ", graph_file.split("/")[-1].replace(".json", ""), " to training set.\n\n")
        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
        
        graph_file = path + "attack_SysClient0358.json"
        benignSubGraphs_dgl = process_one_graph_training(graph_file, query_graphs,"all")
        print("Add ", graph_file.split("/")[-1].replace(".json", ""), " to testing set.\n\n")
        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
        
        
        #Train with three PG and test with the forth one 
        #Don't use any of the testing (prediction) samples in training
        graph_file = path + "benign_SysClient0358.json"
        benignSubGraphs_dgl = process_one_graph_training(graph_file, query_graphs,"all")
        print("Add ", graph_file.split("/")[-1].replace(".json", ""), " to testing set.\n\n")
        testing_dataset = testing_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
            
            
        print("Training Samples", len(training_dataset))
        print("Testing Samples", len(testing_dataset))
        checkpoint(training_dataset,
                          ("./dataset/darpa_optc/experiments/"+args.output_prx+"/raw/dgl_training_dataset.pt"))
        checkpoint(testing_dataset,
                          ("./dataset/darpa_optc/experiments/"+args.output_prx+"/raw/dgl_testing_dataset.pt"))
        
        torch_training_set, torch_testing_set = convert_to_torch_data(training_dataset, testing_dataset)
        checkpoint(torch_training_set,
                          ("./dataset/darpa_optc/experiments/"+args.output_prx+"/raw/torch_training_dataset.pt"))
        checkpoint(torch_testing_set,
                          ("./dataset/darpa_optc/experiments/"+args.output_prx+"/raw/torch_testing_dataset.pt"))
    elif (args.test_a_qg):
        print("Extract suspicious supgraphs for the QG "+args.test_a_qg+ " from " +args.pg_name+ " PG")
        graph_file = path + args.pg_name + ".json"
        max_nodes = query_graphs[args.test_a_qg].number_of_nodes() * args.max_nodes_mult_qg
        print("Max Nodes", max_nodes)
        max_edges = query_graphs[args.test_a_qg].number_of_edges() * args.max_edges_mult_qg
        print("Max Edges", max_edges)
        process_one_graph(graph_file, query_graphs, args.test_a_qg, args.depth, args.min_nodes, max_nodes, max_edges)

    else:
        print("processing Provenance Graphs prediction samples")
        if args.attack:   
            graph_file = path + "attack_SysClient0201.json"
            query_graph_name = "Plain_PowerShell_Empire"
            max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
            print("Max Nodes", max_nodes)
            max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
            print("Max Edges", max_edges)
            process_one_graph(graph_file, query_graphs,query_graph_name,args.depth, args.min_nodes, max_nodes,max_edges)

            graph_file = path + "attack_SysClient0051.json"
            query_graph_name = "Malicious_Upgrade"
            max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
            print("Max Nodes", max_nodes)
            max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
            print("Max Edges", max_edges)
            process_one_graph(graph_file, query_graphs,query_graph_name,args.depth, args.min_nodes, max_nodes,max_edges)

            graph_file = path + "attack_SysClient0501.json"
            query_graph_name = "Custom_PowerShell_Empire"
            max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
            print("Max Nodes", max_nodes)
            max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
            print("Max Edges", max_edges)
            process_one_graph(graph_file, query_graphs,query_graph_name,args.depth, args.min_nodes, max_nodes,max_edges)

            graph_file = path + "attack_SysClient0358.json"
            query_graph_name = "Custom_PowerShell_Empire"
            max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
            print("Max Nodes", max_nodes)
            max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
            print("Max Edges", max_edges)
            process_one_graph(graph_file, query_graphs, query_graph_name, args.depth, args.min_nodes, max_nodes,max_edges)
    
        if args.benign:
            for graph_file in glob.glob('./dataset/darpa_optc/provenance_graphs_v2/benign_SysClient*'):
                if "0358" in graph_file:
                    continue
                for query_graph_name in query_graphs:
                    max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
                    print("Max Nodes", max_nodes)
                    max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
                    print("Max Edges", max_edges)
                    process_one_graph(graph_file, query_graphs, query_graph_name, args.depth, args.min_nodes, max_nodes,max_edges)

    print("---Total Running Time : %s seconds ---" % (time.time() - start_running_time))
    print_memory_cpu_usage("Final memory")
    io_counters = process.io_counters()
    print("IOPS (over total time): ", (io_counters[0] + io_counters[1]) / (time.time() - start_running_time))
    print("Disk I/O", io_counters[0]+io_counters[1])
    print("I/O counters", io_counters)


if __name__ == "__main__":
    main()
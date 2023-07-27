import networkx as nx 
from networkx.readwrite import json_graph
import json
import re
from statistics import mean
import random
import time
import dgl 
from nltk.tokenize import word_tokenize
import gensim
import numpy as np
import pickle
import glob
import argparse
import os, psutil
import resource
process = psutil.Process(os.getpid())
import logging
from dataset_config import get_subgraphs_label
from insert_benign_subgraphs import mutate_attack


def read_json_graph(filename):
    with open(filename) as f:
        js_graph = json.load(f)
    return json_graph.node_link_graph(js_graph)

def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=str, help='output folder',default="TEMP")
parser.add_argument('--dataset', nargs="?", help='Dataset name',required=True)
parser.add_argument("--test-a-qg", type=str,required=True, help="The name of the tested query graph.")
parser.add_argument("--pg-name", type=str, default=None, help="The nae of the tested provenance graph.")
parser.add_argument("--load-path",type=str, default=None, help="Load a preprocessed subgraphs")
parser.add_argument('--query-graphs-folder', nargs="?", help='Path of Query Graph folder', default=None)
parser.add_argument('--ioc-file', nargs="?", help='Path of Query Graph IOCs file',
                    default=None)
parser.add_argument("--generate-training", default=False, action='store_true', help="generate training dataset")
parser.add_argument("--lt", default=False, action='store_true', help="train word2vec with last token")
parser.add_argument("--noise-free", default=False, action='store_true', help="train word2vec without noise attributes")
parser.add_argument("--evade-detection", default=False, action='store_true', help="Evade detection by inserting benign subgraphs")
parser.add_argument('--n-subgraphs', type=int, help='Number of benign Subgraph to be inserted', default=1)
parser.add_argument('--insertion-node', type=str, help='The node UUID of insertion point', default=None)
parser.add_argument('--database-name', type=str, help='Stardog database name', default='tc3_cadets_mimicry')
parser.add_argument('--min-nodes', type=int, help='Minimum number of nodes for subgraphs', default=3)
parser.add_argument('--max-nodes', type=int, help='Maximum number of nodes for subgraphs', default=200)
parser.add_argument('--max-edges', type=int, help='Maximum number of edges for subgraphs', default=1000)
parser.add_argument('--parallel', help='Encode Subgraphs in parallel', action="store_true", default=False)
parser.add_argument('--traverse-with-time', help='Consider timestamp while traversing', action="store_false", default=True)
args = parser.parse_args()
if not args.query_graphs_folder:
    args.query_graphs_folder = "./dataset/" + args.dataset + "/query_graphs/"
if not args.ioc_file:
    args.ioc_file = "./dataset/" + args.dataset + "/query_graphs_IOCs.json"


Global_attrs_sentences = []
if args.noise_free:
    wor2vec_model = gensim.models.Word2Vec.load("model/base/word2vec_attrs_noise_free.model")
else:
    wor2vec_model = gensim.models.Word2Vec.load("model/base/word2vec_attrs_ws.model")




#labelling suspicious nodes
def label_susp_nodes(processGraph,iocs_ips,iocs_fname,iocs_fpath):
    networkx_graph = processGraph.copy()
    for node_id, node_attribute in list(processGraph.nodes(data=True)):
        if "type" not in node_attribute:
            networkx_graph.remove_node(node_id)
        elif not node_attribute["type"]:
            networkx_graph.remove_node(node_id)
    processGraph.clear()
    labels = get_subgraphs_label(args.dataset)
    matched_ioc = {}
    for node_id, node_attribute in list(networkx_graph.nodes(data=True)):
        networkx_graph.nodes[node_id]["suspicous"] = False
        if node_attribute['type'].lower() == 'flow':
            ioc = ''
            for ioc in iocs_ips:
                if labels[node_attribute['type'].lower()] in node_attribute:
                    if ioc == node_attribute[labels[node_attribute['type'].lower()]]:
                        #label as suspicious node
                        networkx_graph.nodes[node_id]["suspicous"] = True
                        #count matched nodes for each ioc
                        if ioc in matched_ioc:
                            matched_ioc[ioc].append(node_id)
                        else:
                            matched_ioc[ioc] = []
                            matched_ioc[ioc].append(node_id)
        elif node_attribute['type'].lower() == 'file':
            ioc = ''
            if labels[node_attribute['type'].lower()] in node_attribute and node_attribute[labels[node_attribute['type'].lower()]]:
                for ioc in iocs_fname:
                    re_ioc = ".*" + ioc.replace('.','\.').lower() + ".*"
                    x = re.search(re_ioc, node_attribute[labels[node_attribute['type'].lower()]])
                    if x:
                        networkx_graph.nodes[node_id]["suspicous"] = True
                        if ioc in matched_ioc: 
                            matched_ioc[ioc].append(node_id)
                        else:
                            matched_ioc[ioc] = []
                            matched_ioc[ioc].append(node_id)
            if labels[node_attribute['type'].lower()] in node_attribute and node_attribute[labels[node_attribute['type'].lower()]]:
                for ioc in iocs_fpath:
                    re_ioc = ""
                    re_ioc = ".*" + ioc.replace('\\','\\\\').lower() + ".*"
                    x = re.search( re_ioc, node_attribute[labels[node_attribute['type'].lower()]])
                    if x:
                        networkx_graph.nodes[node_id]["suspicous"] = True
                        if ioc in matched_ioc: 
                            matched_ioc[ioc].append(node_id)
                        else:
                            matched_ioc[ioc] = []
                            matched_ioc[ioc].append(node_id)
        elif node_attribute['type'].lower() == 'process':
            ioc = ''
            if labels[node_attribute['type'].lower()] in node_attribute and node_attribute[labels[node_attribute['type'].lower()]]:
                for ioc in iocs_fname:
                    re_ioc = ".*" + ioc.replace('.','\.').lower() + ".*"
                    x = re.search(re_ioc, node_attribute[labels[node_attribute['type'].lower()]])
                    if x:
                        networkx_graph.nodes[node_id]["suspicous"] = True
                        if ioc in matched_ioc:
                            matched_ioc[ioc].append(node_id)
                        else:
                            matched_ioc[ioc] = []
                            matched_ioc[ioc].append(node_id)
    count_matched_ioc = {}
    for n in matched_ioc:
        count_matched_ioc[n] = len(matched_ioc[n])
    print("IoCs and number of matched nodes:\n",count_matched_ioc)
    matchedNodes = set([item for sublist in matched_ioc.values() for item in sublist])
    processNodes = set([node_id for node_id, node_type in networkx_graph.nodes.data("type") if node_type.lower() == 'process'])
    print("Total number of matched nodes:", len(matchedNodes))
    print("Total number of processes nodes:", len(processNodes))
    
    return networkx_graph, matched_ioc , matchedNodes , processNodes




# summarize provenance graph 
def summarize_prov_graph(networkx_graph,matched_ioc,matchedNodes,processNodes,depth = 4):
    print("summarize provenance graph to get suspicious subgraphs ")
    start_time = time.time()
    seeds = [(k,n)  for k,n in sorted(matched_ioc.items(), key=lambda item: len(item[1]))]
    seed = seeds[0][0]
    covered = set()
    covered.add(seed)
    print("seed node: ",seed)
    susp = nx.MultiDiGraph()
    suspGraphs = []

    #Traverse Forward & Backward 
    def AdaptiveBFS(root,depth = None):
        level = 0
        visited = set()
        currentLevel = [root]
        while currentLevel:
            nextLevel = set()
            for node in currentLevel:
                for _, nEdge in networkx_graph.out_edges(node):
                    if (nEdge not in visited) and (nEdge in matchedNodes or  nEdge in processNodes) :
                        edge_attr = networkx_graph.get_edge_data(node, nEdge).keys()
                        for key in edge_attr:
                            yield node , nEdge , key
                        nextLevel.add(nEdge)
                for pEdge,_ in networkx_graph.in_edges(node):
                    if (pEdge not in visited) and (pEdge in matchedNodes or  pEdge in processNodes) :
                        edge_attr = networkx_graph.get_edge_data( pEdge, node).keys()
                        for key in edge_attr:
                            yield pEdge, node , key
                        nextLevel.add(pEdge)
                visited.add(node)
            if depth:
                if (depth-level) > 0:
                    level += 1
                elif (depth-level) == 0:
                    break
                else:
                    break
            else:
                currentLevel = nextLevel

    #AdaptiveBFSS return one traversed subgraph
    #susp contain the aggregation of subgraphs, it start with empty graphs, stops when it covers all IoCs 
    def ExpandSearch(seedNodes,susp,depth = None):
        x = 0
        for node in seedNodes:
            x += 1
            startNode = node
            travNodes = []
            travNodes = AdaptiveBFS(startNode,depth)
            subgraphEdges = []
            for edge in iter(travNodes):
                subgraphEdges.append(edge)
            subgraph = networkx_graph.edge_subgraph(subgraphEdges).copy()
            subgraphEdges = None
            susp = nx.compose(susp,subgraph)
            subgraph = None
            # print("Traversed",x,"node of ")
            for ioc , nodes in seeds:
                if ioc not in covered:
                    for node in nodes:
                        if susp.has_node(node):
                            covered.add(ioc)
                            continue
            remain_nodes = [ (ioc,nodes) for ioc,nodes in seeds if ioc not in covered ]  
            if not remain_nodes:
                suspGraphs.append(susp)
                # print("Done ", x ,"node")
            else:
                covered.add(remain_nodes[0][0])
                # print("next remain node: ", remain_nodes[0][0])
                ExpandSearch(remain_nodes[0][1],susp,depth)
        susp = None
        return suspGraphs  
    
    suspGraphs = ExpandSearch(matched_ioc[seed],susp,depth)

    print("Number of subgraphs:", len(suspGraphs))
    if len(suspGraphs) > 0:
        print("Average number of nodes in subgraphs:",round(mean([supgraph.number_of_nodes() for supgraph in suspGraphs])))
        print("Average number of edges in subgraphs:",round(mean([supgraph.number_of_edges() for supgraph in suspGraphs])))
    print("Extraction Memory:", process.memory_info().rss / (1024 ** 2),"MB (based on psutil Lib)")
    print("--- Extraction time %s seconds ---" % (time.time() - start_time))
    return suspGraphs



def summarize_subgraph(g):
    labels = get_subgraphs_label(args.dataset)
    processNodes = [node_id for node_id, node_type in g.nodes.data("type") if node_type.lower() == 'process']
    seeds = random.choices(processNodes, k=15)
    traversedEdges = [ (n,u,k) for n,u,k in nx.edge_dfs(g,source=seeds)]
    gen_subgraph = g.edge_subgraph(traversedEdges).copy()
    labeldict = { node_id:labels[node_attribute["type"].lower()] for node_id,node_attribute in list(gen_subgraph.nodes(data=True))}
    gen_subgraph = nx.relabel.relabel_nodes(gen_subgraph,labeldict)
    n = random.randrange(2)
    gen_subgraph.remove_edges_from(random.choices(list(gen_subgraph.edges()),k=n))
    n = random.randrange(2)
    gen_subgraph.remove_nodes_from(random.choices(list(gen_subgraph.nodes()),k=n))
    for node_id,_ in gen_subgraph.nodes.data():
        del gen_subgraph.nodes[node_id]['_color']
        del gen_subgraph.nodes[node_id]['_node_class']   
        del gen_subgraph.nodes[node_id]['suspicous']
    g,processNodes,traversedEdges,labeldict = None,None,None,None
    return gen_subgraph

def translate_attr_to_string_ws(processGraph,Global_attrs = False, for_query_graph=False):
    labels = get_subgraphs_label(args.dataset,for_query_graph)
    for node_id, node_attribute in list(processGraph.nodes(data=True)):
        trans_str = []
        for _, nextNode_id,edge_attr in processGraph.out_edges(node_id,data=True):
            for attr_key,attr_value in node_attribute.items():
                if node_attribute[attr_key] and "type" in node_attribute and isinstance(attr_key, str) and isinstance(attr_value, str):
                    node_label = node_attribute['type'].lower()
                    if labels[node_label] in node_attribute:
                        try:
                            n_label = node_attribute[labels[node_label]]
                            node_label += (" "+ n_label)
                        except Exception as e:
                            print("exception",e)
                            print(node_attribute)
                    next_node_attribute = processGraph.nodes(data=True)[nextNode_id]
                    next_node_label = next_node_attribute['type'].lower()
                    if labels[next_node_label] in next_node_attribute:
                        try:
                            nn_label = next_node_attribute[labels[next_node_label]]
                            next_node_label += (" " + nn_label)
                        except Exception as e:
                            print("exception",e)
                            print(next_node_attribute)
                    e_type = edge_attr["type"].lower().replace(" ","_")
                    try:
                        sentence = (node_label + " with " + attr_key + " "+ attr_value +" "+e_type+" " + next_node_label)
                        trans_str.append(sentence)
                        if Global_attrs:
                            Global_attrs_sentences.append(sentence)
                    except Exception as e:
                        print("Error in translate_attr_to_string_ws function",e)
        for prevNode_id,_ ,edge_attr in processGraph.in_edges(node_id,data=True):
            for attr_key,attr_value in node_attribute.items():
                attr_key = str(attr_key).lower()
                attr_value = str(attr_value).lower()
                if node_attribute[attr_key] and "type" in node_attribute and isinstance(attr_key, str) and isinstance(attr_value, str):
                    node_label = node_attribute['type'].lower()
                    if labels[node_label] in node_attribute:
                        try:
                            n_label = node_attribute[labels[node_label]]
                            node_label += (" "+ n_label)
                        except Exception as e:
                            print("exception",e)
                            print(node_attribute)
                    previous_node_attribute = processGraph.nodes(data=True)[prevNode_id]
                    previous_node_label = previous_node_attribute['type'].lower()
                    if labels[previous_node_label] in previous_node_attribute:
                        try:
                            pn_label = previous_node_attribute[labels[previous_node_label]]
                            previous_node_label += (" " + pn_label)
                        except Exception as e:
                            print("exception",e)
                            print(previous_node_attribute)
                    e_type = edge_attr["type"].lower().replace(" ","_")
                    try:
                        sentence = (previous_node_label +" "+e_type +" " + node_label +" with " + attr_key + " "+ attr_value)
                        trans_str.append(sentence)
                        if Global_attrs:
                            Global_attrs_sentences.append(sentence)
                    except Exception as e:
                        print("Error in translate_attr_to_string_ws function",e)
        processGraph.nodes[node_id]["attribute_string"] = trans_str
    trans_str = None
    sentence = None
    return processGraph


def noise_free_translate_attr_to_string(processGraph,Global_attrs = False):
    chosen_attributes = ["command_line","process_path","file_path","file_name","ip_address","process_image"]
    for node_id, node_attribute in list(processGraph.nodes(data=True)):
        trans_str = []
        for _, nextNode_id,edge_attr in processGraph.out_edges(node_id,data=True):
            for attr_key,attr_value in node_attribute['properties'].items():
                attr_key = str(attr_key).lower()
                attr_value = str(attr_value).lower()
                if attr_key in chosen_attributes and node_attribute['properties'][attr_key] and node_attribute['properties'][attr_key] not in ["na","none"]:
                    n_type = node_attribute['_node_type'].lower().replace(" ","_")
                    n_label = node_attribute['_display'].lower().replace(" ","_")
                    nn_type = processGraph.nodes('_node_type')[nextNode_id].lower().replace(" ","_")
                    nn_label = processGraph.nodes('_display')[nextNode_id].lower()
                    e_type = edge_attr["type"].lower().replace(" ","_")
                    sentence = (n_type+" "+ n_label +" "+ attr_key + " "+ attr_value +" "+e_type+" "+nn_type+" "+nn_label)
                    trans_str.append(sentence)
                    if Global_attrs:
                        Global_attrs_sentences.append(sentence)
        for prevNode_id,_ ,edge_attr in processGraph.in_edges(node_id,data=True):
            for attr_key,attr_value in node_attribute['properties'].items():
                attr_key = str(attr_key).lower()
                attr_value = str(attr_value).lower()
                if attr_key in chosen_attributes and node_attribute['properties'][attr_key] and node_attribute['properties'][attr_key] not in ["na","none"]:
                    n_type = node_attribute['_node_type'].lower().replace(" ","_")
                    n_label = node_attribute['_display'].lower().replace(" ","_")
                    pn_type = processGraph.nodes('_node_type')[prevNode_id].lower().replace(" ","_")
                    pn_label = processGraph.nodes('_display')[prevNode_id].lower()
                    e_type = edge_attr["type"].lower().replace(" ","_")
                    sentence = (pn_type + " " +pn_label+" "+e_type +" " + n_type+" "+ n_label +" "+ attr_key + " "+ attr_value)
                    trans_str.append(sentence)
                    if Global_attrs:
                        Global_attrs_sentences.append(sentence)
        processGraph.nodes[node_id]["attribute_string"] = trans_str
    trans_str = None
    sentence = None
    return processGraph




def translate_attr_to_string(g,Global_attrs = False,for_query_graph=False):
    if args.noise_free:
        g = noise_free_translate_attr_to_string(g,Global_attrs,for_query_graph)
    else:
        g = translate_attr_to_string_ws(g,Global_attrs,for_query_graph)
    return g

# 2 - Get embedding vector for each attribute in each node (word2vec)
def get_embedding_word2vec_ws(g):
    for node_id, sentences in g.nodes.data("attribute_string"):
        trans_vec = []
        for s in sentences:
            temp = []
            for token in word_tokenize(s):
                try:
                    temp.append(wor2vec_model.wv[token.lower()])
                except:
                    continue
            trans_vec.append(np.mean(temp,0))
        g.nodes[node_id]["attributes_embedding"] = trans_vec 
    return g



def get_embedding_word2vec_lt(g):
    for node_id, sentences in g.nodes.data("attribute_string"):
        trans_vec = []
        for s in sentences:
            temp = []
            for token in word_tokenize(s):
                temp.append(token.lower())
            try:
                trans_vec.append(wor2vec_model.wv[token])
            except:
                continue
        g.nodes[node_id]["attributes_embedding"] = trans_vec 
    return g

def get_embedding_word2vec(g):
    if args.lt:
        g = get_embedding_word2vec_lt(g)
    else:
        g = get_embedding_word2vec_ws(g)
    return g

# 3 - Aggregate Attribute Embedding for each node 
def aggr_attrs_embbedding(g):
    for node_id, vectors in g.nodes.data("attributes_embedding"):
        temp = np.zeros([1,32])
        for vector in vectors:
            temp = temp + vector
        temp = temp/np.linalg.norm(temp)
        temp = np.around(temp,4) 
        temp = [item for sublist in temp for item in sublist]
        g.nodes[node_id]["attribute_embedding_aggr"] = temp
    temp = None
    return g

def Clear_graph(g):
    for node_id, _ in g.nodes.data():
        del g.nodes[node_id]["attributes_embedding"]
        del g.nodes[node_id]["attribute_string"]
    return g



def preprocess_graph(g):
    processed_graph = g.copy()
    for node_id, node_type in g.nodes.data("type"):
        if node_type.lower() == "process":
            processed_graph.nodes[node_id]["label"] = 0
        elif node_type.lower() == "file":
            processed_graph.nodes[node_id]["label"] = 1
        elif node_type.lower() == "flow":
            processed_graph.nodes[node_id]["label"] = 2
        else:
            processed_graph.remove_node(node_id)
    dgl_graph = dgl.from_networkx(processed_graph,node_attrs=["label","attribute_embedding_aggr"])
    processed_graph.clear()
    g.clear()
    return dgl_graph

def write_graph_instance(G1,G2, file_label, target=None):
    data ={}
    temp_l_1 = []
    a,b = G1.edges()
    for i in range(len(a)):
        temp_l_1.append([a[i].tolist(),b[i].tolist()])
    temp_l_2 = []
    a,b = G2.edges()
    for i in range(len(a)):
        temp_l_2.append([a[i].tolist(),b[i].tolist()])
    data['title'] = file_label
    data['graph_1'] = temp_l_1
    data['graph_2'] = temp_l_2
    data['labels_1'] = G1.ndata['label'].tolist()
    data['labels_2'] = G2.ndata['label'].tolist()   
    data['attrsEmbedding_1'] = G1.ndata["attribute_embedding_aggr"].tolist()
    data['attrsEmbedding_2'] = G2.ndata["attribute_embedding_aggr"].tolist()
    if target != None:
        data['target'] = target
    if args.lt:
        graph_file = "./dataset/"+args.dataset+"/Last_Token/" +args.output + "/"+ str(file_label) + ".json"
    elif args.noise_free:
        graph_file = "./dataset/"+args.dataset+"/Noise_Free/" +args.output + "/"+ str(file_label) + ".json"
    else:
        graph_file = "./dataset/"+args.dataset+"/Whole_Sentence/" +args.output + "/"+ str(file_label) + ".json"
    
    ensure_dir(graph_file)
    with open(graph_file, 'w') as f:
        json.dump(data, f)
    G1,G2,data = None,None,None
    return


def main():
    print(args)
    start_running_time = time.time()
    start_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if args.load_path:
        print("load subgraphs ")
        if args.lt:
            suspGraphs_file = "./dataset/" + args.dataset+ "/Last_Token/" +args.output+ "/suspGraphs/" + args.load_path +".pkl"
        elif args.noise_free:
            suspGraphs_file = "./dataset/" + args.dataset+ "/Noise_Free/" +args.output+ "/suspGraphs/" + args.load_path +".pkl"
        else:
            suspGraphs_file = "./dataset/" + args.dataset+ "/Whole_Sentence/" +args.output+ "/suspGraphs/" + args.load_path +".pkl"
        suspGraphs = pickle.load(open(suspGraphs_file,"rb"))
    else:
        with open(args.ioc_file) as f:
            query_graphs_IOCs = json.load(f)
        ioc_ips = query_graphs_IOCs[args.test_a_qg]["ip"]
        ioc_files = query_graphs_IOCs[args.test_a_qg]["file"]
        if args.dataset == "darpa_trace" and args.pg_name == "attack_linux_3":
            graph_json_paths = glob.glob(("./dataset/" + args.dataset +"/provenance_graphs/" + args.pg_name + "_provenance_graph*.pt"))
            print("loading parts of Linux_3")
            provenance_graph = nx.MultiDiGraph()
            for graph_json in graph_json_paths:
                print("Loading",graph_json)
                with open(graph_json, 'rb') as f:
                    temp_provenance_graph = pickle.load(f)
                provenance_graph = nx.compose(provenance_graph,temp_provenance_graph)
                print("Number of nodes",provenance_graph.number_of_nodes())
                print("Number of edges", provenance_graph.number_of_edges())
                print("Occupied Memory:", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
                temp_provenance_graph.clear()
        else:
            graph_json = "./dataset/" + args.dataset +"/provenance_graphs/" + args.pg_name + "_provenance_graph.json"
            provenance_graph = read_json_graph(graph_json)

        if args.evade_detection:
            provenance_graph = mutate_attack(args,provenance_graph)
            print("The mutated provenance graph has",provenance_graph.number_of_nodes(),"nodes and ",provenance_graph.number_of_edges(),"edges")
         
        for node_id in provenance_graph.nodes():
            provenance_graph.nodes[node_id]["networkx_id"] = node_id
        print("label suspicious nodes (matched IOCs)")
        provenance_graph,matched_ioc,matchedNodes,processNodes = label_susp_nodes(provenance_graph,ioc_ips,ioc_files,ioc_files)
        if len(matchedNodes) == 0:
            print("No suspicious nodes matches IOCs")
            print("Memory:", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
            print("---Total Running Time : %s seconds ---" % (time.time() - start_running_time))
            exit()
        print("summarize provenance graph")
        suspGraphs = summarize_prov_graph(provenance_graph,matched_ioc,matchedNodes,processNodes)
        if len(suspGraphs) == 0:
            print("Couldn't extract any suspicious subgraphs")
            print("Memory:", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
            print("---Total Running Time : %s seconds ---" % (time.time() - start_running_time))
            exit()
        if args.lt:
            suspGraphs_file = "./dataset/" + args.dataset+ "/Last_Token/" +args.output+ "/suspGraphs/suspGraphs_" + args.pg_name +".pkl"
        elif args.noise_free:
            suspGraphs_file = "./dataset/" + args.dataset+ "/Noise_Free/" +args.output+ "/suspGraphs/suspGraphs_" + args.pg_name +".pkl"
        else:
            suspGraphs_file = "./dataset/" + args.dataset+ "/Whole_Sentence/" +args.output+ "/suspGraphs/suspGraphs_" + args.pg_name +".pkl"
        ensure_dir(suspGraphs_file)
        pickle.dump(suspGraphs, open(suspGraphs_file, 'wb'))
    query_graphs = {}
    for graph_name in glob.glob((args.query_graphs_folder + "*")):
        query_graphs[graph_name.replace(".json", "").split("/")[-1]] = read_json_graph(graph_name)
    query_graphs[args.test_a_qg] = translate_attr_to_string(query_graphs[args.test_a_qg],for_query_graph=True)
    query_graphs[args.test_a_qg] = get_embedding_word2vec(query_graphs[args.test_a_qg])
    query_graphs[args.test_a_qg] = aggr_attrs_embbedding(query_graphs[args.test_a_qg])
    query_graphs[args.test_a_qg] = preprocess_graph(query_graphs[args.test_a_qg])
    if args.generate_training:
        print("summarize subgraphs to get training set")
        start_time = time.time()
        query_subg = []
        for i in range(len(suspGraphs)):
            query_subg.append(summarize_subgraph(suspGraphs[i]))
        print("--- %s seconds ---" % (time.time() - start_time))
        
        print("prepare training set")
        start_time = time.time()
        # get attrs embedding for each graph 
        for i in range(len(suspGraphs)):
            if query_subg[i].number_of_nodes() > 2:
                suspGraphs[i] = translate_attr_to_string(suspGraphs[i])
                suspGraphs[i] = get_embedding_word2vec(suspGraphs[i])
                suspGraphs[i] = aggr_attrs_embbedding(suspGraphs[i])
                suspGraphs[i] = preprocess_graph(suspGraphs[i])
                temp_graph_2 = translate_attr_to_string(query_subg[i])
                temp_graph_2 = get_embedding_word2vec(temp_graph_2)
                temp_graph_2 = aggr_attrs_embbedding(temp_graph_2)
                temp_graph_2 = preprocess_graph(temp_graph_2)
                write_graph_instance(suspGraphs[i],temp_graph_2,str("positive/" +"po_"+ str(i)),1)
                temp_graph_2 = None
            j = (len(suspGraphs)-1) - i
            if query_subg[j].number_of_nodes() > 2:
                temp_graph_2 = translate_attr_to_string(query_subg[j])
                temp_graph_2 = get_embedding_word2vec(temp_graph_2)
                temp_graph_2 = aggr_attrs_embbedding(temp_graph_2)
                temp_graph_2 = preprocess_graph(temp_graph_2)
                write_graph_instance(suspGraphs[i],temp_graph_2,str("negative/" + "ne_p" +str(i) + "_q"+ str(j)),0)
                temp_graph_2 = None
            print("Done Training sample:",i)
        print("--- %s seconds ---" % (time.time() - start_time))
        print("Done training set preperation")
        if args.lt:
            suspGraphs_f = "./dataset/" + args.dataset+ "/Last_Token/" +args.output+ "/suspGraphs/suspGraphs_f_" + args.pg_name +".pkl"
        elif args.noise_free:
            suspGraphs_f = "./dataset/" + args.dataset+ "/Noise_Free/" +args.output+ "/suspGraphs/suspGraphs_f_" + args.pg_name +".pkl"
        else:
            suspGraphs_f = "./dataset/" + args.dataset+ "/Whole_Sentence/" +args.output+ "/suspGraphs/suspGraphs_f_" + args.pg_name +".pkl"
        ensure_dir(suspGraphs_f)
        pickle.dump(suspGraphs, open(suspGraphs_f, 'wb'))
        fisrt_loop = False
    else:
        fisrt_loop = True

    print("prepare prediction set")
    start_time = time.time()
    for i in range(len(suspGraphs)):
        suspGraphs[i] = translate_attr_to_string(suspGraphs[i])
        suspGraphs[i] = get_embedding_word2vec(suspGraphs[i])
        suspGraphs[i] = aggr_attrs_embbedding(suspGraphs[i])
        suspGraphs[i] = preprocess_graph(suspGraphs[i])
    for i in range(len(suspGraphs)):
        write_graph_instance(suspGraphs[i],query_graphs[args.test_a_qg],str(args.test_a_qg + "_in_"+args.pg_name+ "/" + "pr_p" +str(i)+"_" + args.test_a_qg))
    print("--- %s seconds ---" % (time.time() - start_time))
    print("Done prediction set preperation")
    
    if not args.generate_training:
        if args.lt:
            suspGraphs_f = "./dataset/" + args.dataset+ "/Last_Token/" +args.output+ "/suspGraphs/suspGraphs_f_" + args.pg_name +".pkl"
        elif args.noise_free:
            suspGraphs_f = "./dataset/" + args.dataset+ "/Noise_Free/" +args.output+ "/suspGraphs/suspGraphs_f_" + args.pg_name +".pkl"
        else:
            suspGraphs_f = "./dataset/" + args.dataset+ "/Whole_Sentence/" +args.output+ "/suspGraphs/suspGraphs_f_" + args.pg_name +".pkl"
        ensure_dir(suspGraphs_f)
        pickle.dump(suspGraphs, open(suspGraphs_f, 'wb'))
    max_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - start_mem
    print("Maximum Memory usage :", max_mem / 1024,"MB")
    print("Occupied Memory:", process.memory_info().rss / (1024 ** 2),"MB (based on psutil Lib)")
    print("---Total Running Time : %s seconds ---" % (time.time() - start_running_time))


if __name__ == "__main__":
    main()

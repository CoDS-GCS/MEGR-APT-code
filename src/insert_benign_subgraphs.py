import time
import pickle
import torch
import pickle
import argparse
import matplotlib.pyplot as plt
import os, psutil
import dask.bag as db
import argparse
import glob
import io
from dask.distributed import Client, LocalCluster
import dask
import json
from networkx.readwrite import json_graph
import networkx as nx
import torch.nn.functional as F
import dgl
import stardog
import pandas as pd
import numpy as np
import pytz
import copy
from datetime import datetime
import multiprocessing
import random
from statistics import mean
from dataset_config import get_stardog_cred

process = psutil.Process(os.getpid())

parser = argparse.ArgumentParser()
parser.add_argument('--n-subgraphs', type=int, help='Number of benign Subgraph', default=1)
parser.add_argument('--insertion-node', type=str, help='The node UUID of insertion point', required=True)
parser.add_argument('--min-nodes', type=int, help='Minimum number of nodes for subgraphs', default=3)
parser.add_argument('--max-nodes', type=int, help='Maximum number of nodes for subgraphs', default=200)
parser.add_argument('--max-edges', type=int, help='Maximum number of edges for subgraphs', default=1000)
parser.add_argument('--parallel', help='Encode Subgraphs in parallel', action="store_true", default=False)
parser.add_argument('--output-prx', type=str, help='output file prefix ', default=None)
parser.add_argument('--query-graphs-folder', nargs="?", help='Path of Query Graph folder', default=None)
parser.add_argument('--ioc-file', nargs="?", help='Path of Query Graph IOCs file', default=None)
parser.add_argument('--dataset', nargs="?", help='Dataset name', default="darpa_cadets")
parser.add_argument('--traverse-with-time', help='Consider timestamp while traversing', action="store_false", default=True)
parser.add_argument("--qg-name",type=str,default=None,help="The name of the tested query graph.")
parser.add_argument("--pg-name",type=str,default=None,help="The nae of the tested provenance graph.")
parser.add_argument('--database-name', type=str, help='Stardog database name', default='tc3_cadets_mimicry')
args = parser.parse_args()

database_name, connection_details = get_stardog_cred(args.database_name)
conn = stardog.Connection(database_name, **connection_details)
if not args.ioc_file:
    args.ioc_file = "./dataset/"+ args.dataset +"/query_graphs_IOCs.json"
if not args.query_graphs_folder:
    args.query_graphs_folder = "./dataset/"+ args.dataset +"/query_graphs/"   
benign_pg_map = {"darpa_cadets":"benign_BSD","darpa_theia":"benign_theia","darpa_trace":"benign_trace","darpa_optc":"benign_SysClient0201"}
GRAPT_IRI_map = {"darpa_cadets":"darpa_tc3/cadets","darpa_theia":"darpa_tc3/theia","darpa_trace":"darpa_tc3/trace","darpa_optc":"darpa_optc"}

    
def read_json_graph(filename):
    with open(filename) as f:
        js_graph = json.load(f)
    return json_graph.node_link_graph(js_graph)
def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        
sparql_queries = {
    'Random_Benign_Nodes': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/<DATASET>/<GRAPH_NAME>/>
    SELECT DISTINCT ?uuid
    WHERE{
    ?s <GRAPH_NAME>:uuid ?uuid.
    filter(rand()<0.5) .
    FILTER NOT EXISTS {?s <GRAPH_NAME>:suspicious ?susp}.
    } 
""",
                  'Extract_Benign_Subgraph_NoTime': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/<DATASET>/<GRAPH_NAME>/> 
    PREFIX event: <http://grapt.org/<DATASET>/<GRAPH_NAME>/event/> 
    SELECT  DISTINCT ?subject ?predicate ?object {
        {
            # 1- forward
            SELECT DISTINCT ?subject ?predicate ?object 
            WHERE {
                ?subject ?predicate ?object .
                ?subject <GRAPH_NAME>:uuid ?IOC_node .
                FILTER NOT EXISTS {?object <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?predicate),str(event:)).
            }   LIMIT <MAX_EDGES> 
        } 
        UNION 
        {
            #2- backward
            SELECT DISTINCT ?subject ?predicate ?object 
            WHERE {
                ?subject ?predicate ?object .
                ?object <GRAPH_NAME>:uuid ?IOC_node .
                FILTER NOT EXISTS {?subject <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?predicate),str(event:)).
            } LIMIT <MAX_EDGES> 
        } 
        UNION 
        {
            # 3-a forward from all first neighbours  
            SELECT (?first_object as ?subject) (?next_predicate as ?predicate) (?next_object as ?object) 
            WHERE {
                ?first_object ?next_predicate ?next_object .
                {
                    SELECT DISTINCT ?first_object 
                    WHERE {
                        ?first_subject ?first_predicate ?first_object .
                        ?first_subject <GRAPH_NAME>:uuid ?IOC_node .
                        FILTER NOT EXISTS {?first_object <GRAPH_NAME>:suspicious ?susp}.
                        FILTER strstarts(str(?first_predicate),str(event:)).
                    }
                }
                FILTER NOT EXISTS {?next_object <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?next_predicate),str(event:)).
            }    LIMIT <MAX_EDGES>
        } 
        UNION {
        #     # 3-b forward from all first neighbours  
            SELECT DISTINCT (?first_subject as ?subject) (?next_predicate as ?predicate) (?next_object as ?object)  
            WHERE {
                ?first_subject ?next_predicate ?next_object
                { 
                    SELECT DISTINCT ?first_subject
                    WHERE {
                        ?first_subject ?first_predicate ?first_object .
                        ?first_object <GRAPH_NAME>:uuid ?IOC_node .
                        FILTER NOT EXISTS {?first_subject <GRAPH_NAME>:suspicious ?susp}.
                        FILTER strstarts(str(?first_predicate),str(event:)).
                    }
                }
                FILTER NOT EXISTS {?next_object <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?next_predicate),str(event:)).
            } LIMIT <MAX_EDGES>
        } 
        UNION {
            #4-a Backward from all first neighbours  
            SELECT DISTINCT (?next_subject as ?subject) (?next_predicate as ?predicate) (?first_object as ?object) 
            WHERE {
                ?next_subject ?next_predicate ?first_object
                {
                    SELECT DISTINCT ?first_object
                    WHERE{
                        ?first_subject ?first_predicate ?first_object .
                        ?first_subject <GRAPH_NAME>:uuid ?IOC_node . 
                        FILTER NOT EXISTS {?first_object <GRAPH_NAME>:suspicious ?susp}.
                        FILTER strstarts(str(?first_predicate),str(event:)).
                    }
                }
                FILTER NOT EXISTS {?next_subject <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?next_predicate),str(event:)).
            }    LIMIT <MAX_EDGES> 
        } 
        UNION {
        #     #4-b Backward from all first neighbours  
            SELECT DISTINCT (?next_subject as ?subject) (?next_predicate as ?predicate) (?first_subject as ?object) 
            WHERE {
                ?next_subject ?next_predicate ?first_subject .
                {
                    SELECT DISTINCT  ?first_subject  
                    WHERE {
                        ?first_subject ?first_predicate ?first_object .
                        ?first_object <GRAPH_NAME>:uuid ?IOC_node .
                        FILTER NOT EXISTS {?first_subject <GRAPH_NAME>:suspicious ?susp}.
                        FILTER strstarts(str(?first_predicate),str(event:)).
                    }
                }
                FILTER NOT EXISTS {?next_subject <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?next_predicate),str(event:)).
            }   LIMIT <MAX_EDGES>  
        }  
    }
    LIMIT <MAX_EDGES>
""",
                  'Extract_Benign_Subgraph_withTime': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/<DATASET>/<GRAPH_NAME>/> 
    PREFIX event: <http://grapt.org/<DATASET>/<GRAPH_NAME>/event/> 
    SELECT  DISTINCT ?subject ?predicate ?object ?timestamp {
        {
            # 1- forward
            SELECT DISTINCT ?subject ?predicate ?object ?timestamp
            WHERE {
                << ?subject ?predicate ?object >> <GRAPH_NAME>:timestamp ?timestamp .
                ?subject <GRAPH_NAME>:uuid ?IOC_node .
                FILTER NOT EXISTS {?object <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?predicate),str(event:)) .
            }   LIMIT <MAX_EDGES> 
        } 
        UNION 
        {
            #2- backward
            SELECT DISTINCT ?subject ?predicate ?object ?timestamp
            WHERE {
                << ?subject ?predicate ?object >> <GRAPH_NAME>:timestamp ?timestamp .
                ?object <GRAPH_NAME>:uuid ?IOC_node .
                FILTER NOT EXISTS {?subject <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?predicate),str(event:)) .
            } LIMIT <MAX_EDGES> 
        } 
        UNION 
        {
            # 3-a forward from all first neighbours  
            SELECT (?first_object as ?subject) (?next_predicate as ?predicate) (?next_object as ?object) ?timestamp
            WHERE {
                << ?first_object ?next_predicate ?next_object >> <GRAPH_NAME>:timestamp ?timestamp .
                {
                    SELECT DISTINCT ?first_object 
                    WHERE {
                        ?first_subject ?first_predicate ?first_object .
                        ?first_subject <GRAPH_NAME>:uuid ?IOC_node .
                        FILTER NOT EXISTS {?first_object <GRAPH_NAME>:suspicious ?susp}.
                        FILTER strstarts(str(?first_predicate),str(event:)) .
                    }
                }
                FILTER NOT EXISTS {?next_object <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?next_predicate),str(event:)) .
            }    LIMIT <MAX_EDGES>
        } 
        UNION {
        #     # 3-b forward from all first neighbours  
            SELECT DISTINCT (?first_subject as ?subject) (?next_predicate as ?predicate) (?next_object as ?object) ?timestamp  
            WHERE {
                << ?first_subject ?next_predicate ?next_object >> <GRAPH_NAME>:timestamp ?timestamp .
                { 
                    SELECT DISTINCT ?first_subject
                    WHERE {
                        ?first_subject ?first_predicate ?first_object .
                        ?first_object <GRAPH_NAME>:uuid ?IOC_node .
                        FILTER NOT EXISTS {?first_subject <GRAPH_NAME>:suspicious ?susp}.
                        FILTER strstarts(str(?first_predicate),str(event:)) .
                    }
                }
                FILTER NOT EXISTS {?next_object <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?next_predicate),str(event:)) .
            } LIMIT <MAX_EDGES>
        } 
        UNION {
            #4-a Backward from all first neighbours  
            SELECT DISTINCT (?next_subject as ?subject) (?next_predicate as ?predicate) (?first_object as ?object) ?timestamp
            WHERE {
                << ?next_subject ?next_predicate ?first_object >> <GRAPH_NAME>:timestamp ?timestamp .
                {
                    SELECT DISTINCT ?first_object
                    WHERE{
                        ?first_subject ?first_predicate ?first_object .
                        ?first_subject <GRAPH_NAME>:uuid ?IOC_node . 
                        FILTER NOT EXISTS {?first_object <GRAPH_NAME>:suspicious ?susp}.
                        FILTER strstarts(str(?first_predicate),str(event:)) .
                    }
                }
                FILTER NOT EXISTS {?next_subject <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?next_predicate),str(event:)) .
            }    LIMIT <MAX_EDGES> 
        } 
        UNION {
        #     #4-b Backward from all first neighbours  
            SELECT DISTINCT (?next_subject as ?subject) (?next_predicate as ?predicate) (?first_subject as ?object) ?timestamp 
            WHERE {
                << ?next_subject ?next_predicate ?first_subject >> <GRAPH_NAME>:timestamp ?timestamp .
                {
                    SELECT DISTINCT  ?first_subject  
                    WHERE {
                        ?first_subject ?first_predicate ?first_object .
                        ?first_object <GRAPH_NAME>:uuid ?IOC_node .
                        FILTER NOT EXISTS {?first_subject <GRAPH_NAME>:suspicious ?susp}.
                        FILTER strstarts(str(?first_predicate),str(event:)) .
                    }
                }
                FILTER NOT EXISTS {?next_subject <GRAPH_NAME>:suspicious ?susp}.
                FILTER strstarts(str(?next_predicate),str(event:)) .
            }   LIMIT <MAX_EDGES>  
        }  
    }
    LIMIT <MAX_EDGES>
"""
                 }        


def Extract_benign_rdf_triples(params):
    traverse_time = time.time()
    graph_sparql_queries = params[0]
    node = params[1]
    node = "\"" + node + "\""
    rand_limit = random.randint((args.max_edges / 10), args.max_edges)
    try:
        if args.traverse_with_time:
            csv_results = conn.select(graph_sparql_queries['Extract_Benign_Subgraph_withTime'], content_type='text/csv',
                                  bindings={'IOC_node': node}, limit=(rand_limit),timeout=10000)
        else:
            csv_results = conn.select(graph_sparql_queries['Extract_Benign_Subgraph_NoTime'], content_type='text/csv',
                                  bindings={'IOC_node': node}, limit=(rand_limit),timeout=10000)
    except Exception as e:
        print("Error in Querying subgraph with seed", node, e)
        return None ,None
    subgraphTriples = pd.read_csv(io.BytesIO(csv_results))
    if len(subgraphTriples) > args.max_edges: 
        print("Subgraph not within range")
        return None ,None
    subgraphTriples_df = subgraphTriples.copy()
    print("Extracted a subgraph with", len(subgraphTriples), "triples")
    print("Traversed in ", time.time() - traverse_time, "seconds")
    # Convert subgraphTriples to networkx "subgraph"
    # Parse Triples
    try:
        if args.traverse_with_time:
            subgraphTriples['timestamp'] = subgraphTriples['timestamp'] / 1000
            subgraphTriples['timestamp'] = subgraphTriples['timestamp'].apply(lambda x: '%.f' % x)
            subgraphTriples = subgraphTriples.drop_duplicates()
        subgraphTriples['subject_type'] = subgraphTriples['subject'].str.split('/').str[-2]
        subgraphTriples['subject_uuid'] = subgraphTriples['subject'].str.split('/').str[-1]
        subgraphTriples['type'] = subgraphTriples['predicate'].str.split('/').str[-1]
        subgraphTriples['object_type'] = subgraphTriples['object'].str.split('/').str[-2]
        subgraphTriples['object_uuid'] = subgraphTriples['object'].str.split('/').str[-1]
    except Exception as e :
        print("Not standard format for", node, e)
        return None, None
    # Construct Graph from Edges
    if args.traverse_with_time:
        subgraph = nx.from_pandas_edgelist(
        subgraphTriples,
        source="subject_uuid",
        target="object_uuid",
        edge_attr=["type","timestamp"],
        create_using=nx.MultiDiGraph())
    else:
        subgraph = nx.from_pandas_edgelist(
            subgraphTriples,
            source="subject_uuid",
            target="object_uuid",
            edge_attr=["type"],
            create_using=nx.MultiDiGraph()
        )
    if subgraph.number_of_nodes() < args.min_nodes or subgraph.number_of_nodes() > args.max_nodes:
        print("Subgraph not within range")
        return None, None
    print("Extracted a subgraph with", subgraph.number_of_nodes(), "nodes, and ", subgraph.number_of_edges(), "edges")
    print("Traversed and converted to NetworkX in ", time.time() - traverse_time, "seconds")
    return subgraph, subgraphTriples_df


def Extract_Random_Benign_Subgraphs(graph_sparql_queries, n_subgraphs):
    start_time = time.time()
    benignSubGraphs,benignSubGraphs_df = [],[]
    if args.parallel:
        # Query with DASK
        cores = multiprocessing.cpu_count() - 4
        seed_number = n_subgraphs
        while len(benignSubGraphs) < n_subgraphs:
            csv_results = conn.select(graph_sparql_queries['Random_Benign_Nodes'], content_type='text/csv',
                                      limit=(seed_number))
            benign_nodes = list(pd.read_csv(io.BytesIO(csv_results))["uuid"])
            print("Number of Random Benign Seed Nodes:", len(benign_nodes))
            benign_nodes = list(pd.read_csv(io.BytesIO(csv_results))["uuid"])
            multi_queries = [[graph_sparql_queries, node] for node in benign_nodes]
            benign_nodes_dask = db.from_sequence(multi_queries, npartitions=cores)
            tmp_benignSubGraphs = benign_nodes_dask.map(lambda g: Extract_benign_rdf_triples(g)).compute()
            for subgraph,subgraphTriples in tmp_benignSubGraphs:
                if subgraph:
                    benignSubGraphs.append(subgraph.copy())
                    benignSubGraphs_df.append(subgraphTriples.copy())
                    subgraph.clear()
                    del subgraphTriples
            seed_number = 10
    else:
        # Query Sequentially
        csv_results = conn.select(graph_sparql_queries['Random_Benign_Nodes'], content_type='text/csv',
                                  limit=(n_subgraphs * 10))
        benign_nodes = list(pd.read_csv(io.BytesIO(csv_results))["uuid"])
        print("Number of Random Benign Seed Nodes:", len(benign_nodes))
        for node in benign_nodes:
            subgraph,subgraphTriples = Extract_benign_rdf_triples([graph_sparql_queries, node])
            if subgraph:
                benignSubGraphs.append(subgraph.copy())
                benignSubGraphs_df.append(subgraphTriples.copy())
                subgraph.clear()
                del subgraphTriples
            if len(benignSubGraphs) >= n_subgraphs:
                break
    print("Number of benign subgraphs:", len(benignSubGraphs))
    print("Max number of nodes in benign subgraphs:", max([supgraph.number_of_nodes() for supgraph in benignSubGraphs]))
    print("Min number of nodes in benign subgraphs:", min([supgraph.number_of_nodes() for supgraph in benignSubGraphs]))
    print("Average number of nodes in benign subgraphs:",
          round(mean([supgraph.number_of_nodes() for supgraph in benignSubGraphs])))
    print("Max number of edges in benign subgraphs:", max([supgraph.number_of_edges() for supgraph in benignSubGraphs]))
    print("Min number of edges in benign subgraphs:", min([supgraph.number_of_edges() for supgraph in benignSubGraphs]))
    print("Average number of edges in benign subgraphs:",
          round(mean([supgraph.number_of_edges() for supgraph in benignSubGraphs])))
    print("--- %s seconds ---" % (time.time() - start_time))
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
    benign_nodes = None
    return benignSubGraphs,benignSubGraphs_df

def insertion_edge_type(dataset,node_type):
    mapping_edge = {}
    if dataset == "darpa_cadets":
        mapping_edge = {"process":"fork","file":"write","flow":"connect","pipe":"create_object"}
    elif dataset == "darpa_theia":
        mapping_edge = {"process":"clone","file":"write","flow":"connect","memory":"mmap"}
    elif dataset == "darpa_trace":
        mapping_edge = {"process":"clone","file":"write","flow":"connect","memory":"mmap"}
    elif dataset == "darpa_optc":
        mapping_edge = {"process":"create","file":"write","flow":"message","shell":"command"}
    else:
        print("Undefined dataset")
        return None
    return mapping_edge[node_type]

def ingest_benign_subgraph(insertion_node,benign_subgraph_df,GRAPH_IRI,benign_pg_name):
    GRAPH_NAME = str(GRAPH_IRI.split("/")[-2])
    benign_subgraph_df["subject"] = benign_subgraph_df["subject"].apply(lambda x:str(x).replace(benign_pg_name,GRAPH_NAME))
    benign_subgraph_df["predicate"] = benign_subgraph_df["predicate"].apply(lambda x: str(x).replace(benign_pg_name,GRAPH_NAME))
    benign_subgraph_df["object"] = benign_subgraph_df["object"].apply(lambda x: str(x).replace(benign_pg_name,GRAPH_NAME))
    #writing triples to turtle
    #write prefix
    benign_subgraph_turtle = "@prefix " + GRAPH_NAME + ': <' + GRAPH_IRI + '> .'
    benign_subgraph_turtle += '\n@prefix ' + 'process: <' + GRAPH_IRI + 'process/> .'
    benign_subgraph_turtle += '\n@prefix ' + "file: <" + GRAPH_IRI + 'file/> .'
    benign_subgraph_turtle += '\n@prefix ' + 'flow: <' + GRAPH_IRI + 'flow/> .'
    benign_subgraph_turtle += '\n@prefix ' + 'memory: <' + GRAPH_IRI + 'memory/> .'
    benign_subgraph_turtle += '\n@prefix ' + 'pipe: <' + GRAPH_IRI + 'pipe/> .'
    benign_subgraph_turtle += '\n@prefix ' + 'shell: <' + GRAPH_IRI + 'shell/> .'
    benign_subgraph_turtle += '\n@prefix ' + 'event: <' + GRAPH_IRI + 'event/> .'
    benign_subgraph_turtle += '\n@prefix ' + 'mutated_event: <' + GRAPH_IRI + 'event/mutated/> .'
    benign_subgraph_turtle += '\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n'
    #write nodes
    source_df = benign_subgraph_df[["subject"]]
    source_df.columns = ["node"]
    dest_df = benign_subgraph_df[["object"]]
    dest_df.columns = ["node"]
    allNodes_df = pd.concat([source_df, dest_df]).drop_duplicates()
    allNodes_df["node"] = allNodes_df["node"].apply(lambda x: x.split("/")[-2] +":" +x.split("/")[-1] + " a \"" + x.split("/")[-2] + "\" .")
    benign_subgraph_turtle += allNodes_df.to_string(header=None,index=None)
    print("Number of unique mutated nodes",len(allNodes_df))
    del source_df, dest_df, allNodes_df
    # Add insertion node 
    if args.traverse_with_time:
        benign_subgraph_df = benign_subgraph_df.sort_values(by=['timestamp'],ignore_index=True)
    insert_object = benign_subgraph_df.loc[0,"subject"]
    insert_subject = insert_object.replace(insert_object.split("/")[-1],insertion_node)
    insert_object_type = insert_object.split("/")[-2]
    insert_edge_type = insertion_edge_type(args.dataset,insert_object_type)
    current_predicate = benign_subgraph_df.loc[0,"predicate"]
    insert_edge = current_predicate.replace(current_predicate.split("/")[-1],insert_edge_type)
    insert_timestamp = benign_subgraph_df.loc[0,"timestamp"] 
    benign_subgraph_df.loc[len(benign_subgraph_df.index)] = [insert_subject,insert_edge,insert_object,insert_timestamp]
    #write edges
    benign_subgraph_df_temp = benign_subgraph_df.copy()
    benign_subgraph_df_temp["subject"] = benign_subgraph_df_temp["subject"].apply(lambda x: "<< " + str(x).split("/")[-2] +":" +x.split("/")[-1] )
    benign_subgraph_df_temp["predicate"] = benign_subgraph_df_temp["predicate"].apply(lambda x: "mutated_event:" + str(x).split("/")[-1] )
    benign_subgraph_df_temp["object"] = benign_subgraph_df_temp["object"].apply(lambda x: str(x).split("/")[-2] +":" +x.split("/")[-1]+ " >>")
    benign_subgraph_df_temp["timestamp"] = benign_subgraph_df_temp["timestamp"].apply(lambda x: GRAPH_NAME + ':timestamp "' + str(x) + '" .')
    benign_subgraph_turtle += "\n"
    benign_subgraph_turtle += benign_subgraph_df_temp.to_string(header=None,index=None)
    print("Number of mutated edges",len(benign_subgraph_df))
    del benign_subgraph_df_temp   
    return benign_subgraph_turtle

def insert_into_db(benign_subgraph_turtle,file_path):
    ensure_dir(file_path)
    with open(file_path, "w") as turtle_file:
        turtle_file.write(benign_subgraph_turtle)
    # push data to stardog
    conn.begin()
    conn.add(stardog.content.Raw(benign_subgraph_turtle.encode('utf-8'), content_type='text/turtle'))
    conn.commit()
    print("Done insertion into db")
    return
    
def mutate_attack(insertion_node,n_subgraphs,GRAPH_IRI,graph_sparql_queries,benign_pg_name):
    benignSubGraphs,benignSubGraphs_df = Extract_Random_Benign_Subgraphs(graph_sparql_queries, n_subgraphs)
    total_inserted_edges = 0
    all_inserted_subgraphs = []
    for subgraph in benignSubGraphs_df:
        total_inserted_edges += len(subgraph)
        benign_subgraph_turtle = ingest_benign_subgraph(insertion_node,subgraph,GRAPH_IRI,benign_pg_name)
        all_inserted_subgraphs.append(benign_subgraph_turtle)
        del benign_subgraph_turtle
    print("Total mutated edges",total_inserted_edges)
    print("Total mutated subgraphs",len(all_inserted_subgraphs))
    return all_inserted_subgraphs,total_inserted_edges
    
    
def main():
    print(args)
    start_running_time = time.time()
    query_graphs = {}
    for graph_name in glob.glob(args.query_graphs_folder+'*'):
        query_graphs[graph_name.replace(".json","").split("/")[-1]] = read_json_graph(graph_name)
    with open(args.ioc_file) as f:
        query_graphs_IOCs = json.load(f)
    benign_pg_name = benign_pg_map[args.dataset] 
    query_pattern = '\"' + args.qg_name + '\"' 
    graph_sparql_queries = copy.deepcopy(sparql_queries)
    for sparql_name, sparql_query in graph_sparql_queries.items():
        graph_sparql_queries[sparql_name] = sparql_query.replace("<Query>", query_pattern).replace("<GRAPH_NAME>",benign_pg_name).replace("<DATASET>", GRAPT_IRI_map[args.dataset]).replace("<MAX_EDGES>", str(args.max_edges+10))
       
    GRAPH_IRI = "http://grapt.org/" +GRAPT_IRI_map[args.dataset]+ "/" + args.pg_name + "/"
    all_inserted_subgraphs,total_inserted_edges = mutate_attack(args.insertion_node,args.n_subgraphs,GRAPH_IRI,graph_sparql_queries,benign_pg_name)
    file_path =  "./dataset/" + args.dataset +"/" + args.output_prx + "/inserted_subgraphs/mimic_attack_"+args.qg_name+ "_with_" + str(total_inserted_edges)+ "_edges_into_" + args.pg_name + ".ttl"
    for benign_subgraph_turtle in all_inserted_subgraphs:
        insert_into_db(benign_subgraph_turtle,file_path)
    
        
if __name__ == "__main__":
    main()
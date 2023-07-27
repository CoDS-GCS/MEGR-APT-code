import networkx as nx
from networkx.readwrite import json_graph
import json
from statistics import mean
import pandas as pd
import random
from random import randrange
import time
import dgl
import pickle
import glob
import argparse
import os
import io
import torch
import torch.nn.functional as F
from torch_geometric.data import Data
import resource
import copy
import dask
from dask.distributed import Client, LocalCluster
import dask.bag as db
import stardog
import os, psutil
import gc
import ctypes
import sys
current_dir = os.getcwd()
sys.path.append(current_dir+"/src")
from dataset_config import get_stardog_cred

process = psutil.Process(os.getpid())
import multiprocessing

parser = argparse.ArgumentParser()
parser.add_argument('--min-nodes', type=int, help='Minimum number of nodes for subgraphs', default=3)
parser.add_argument('--max-nodes-mult-qg', type=int, help='Maximum number of nodes for subgraphs', default=10)
parser.add_argument('--max-nodes-training', type=int, help='Maximum number of nodes for subgraphs', default=200)
parser.add_argument('--max-edges-mult-qg', type=int, help='Maximum number of edges for subgraphs', default=25)
parser.add_argument('--max-edges-training', type=int, help='Maximum number of edges for subgraphs', default=1000)
parser.add_argument('--min-iocs', type=int, help='Minimum number of Query Graph IOCs to accept subgraph', default=1)
parser.add_argument('--output-prx', type=str, help='output file prefix ', default=None)
parser.add_argument('--parallel', help='Encode Subgraphs in parallel', action="store_true", default=False)
parser.add_argument('--query-graphs-folder', nargs="?", help='Path of Query Graph folder', default="./dataset/darpa_cadets/query_graphs/")
parser.add_argument('--ioc-file', nargs="?", help='Path of Query Graph IOCs file', default="./dataset/darpa_cadets/query_graphs_IOCs.json")
parser.add_argument('--dataset', nargs="?", help='Dataset name', default="darpa_cadets")
parser.add_argument('--training', help='Prepare training set', action="store_true", default=False)
parser.add_argument('--n-subgraphs', type=int, help='Number of Subgraph', default=None)
parser.add_argument('--traverse-with-time', help='Consider timestamp while traversing', action="store_false", default=True)
parser.add_argument("--test-a-qg",type=str,default=None,help="The name of the tested query graph.")
parser.add_argument("--pg-name",type=str,default=None,help="The nae of the tested provenance graph.")
parser.add_argument('--database-name', type=str, help='Stardog database name', default='tc3-cadets')
args = parser.parse_args()

def read_json_graph(filename):
    with open(filename) as f:
        js_graph = json.load(f)
    return json_graph.node_link_graph(js_graph)

def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

def checkpoint(data, file_path):
    ensure_dir(file_path)
    torch.save(data, file_path)

def load_checkpoint(file_path):
    with open(file_path, 'rb') as f:
        data = torch.load(f)
    return data

database_name, connection_details = get_stardog_cred(args.database_name)
conn = stardog.Connection(database_name, **connection_details)


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


sparql_queries = {'Query_Suspicious_IP': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/>
    SELECT DISTINCT ?ip ?uuid 
    WHERE{
        ?s <GRAPH_NAME>:uuid ?uuid .
        ?s rdf:type "flow" .
        ?s <GRAPH_NAME>:attributes ?_att .
        ?_att <GRAPH_NAME>:remote_ip ?ip .
        FILTER(?ip IN <IOC_IP_LIST> ) . 
    }
""",
'Query_Suspicious_Files': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/>
    SELECT DISTINCT ?uuid 
    WHERE{
        ?s rdf:type "file" .
        ?s <GRAPH_NAME>:attributes ?_att .
        ?_att <GRAPH_NAME>:object_paths ?paths .
        FILTER regex(?paths, ?IOC ,'i') .
        ?s  <GRAPH_NAME>:uuid ?uuid .
    }
""",
'Label_Suspicious_Nodes': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/>
    INSERT {?s <GRAPH_NAME>:suspicious <Query> . }
    WHERE {
        ?s <GRAPH_NAME>:uuid ?uuid .
        FILTER(?uuid IN <SUSPICIOUS_LIST> ) .
    } 
""",
'Random_Benign_Nodes': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/>
    SELECT DISTINCT ?uuid
    WHERE{
    ?s <GRAPH_NAME>:uuid ?uuid.
    filter(rand()<0.5) .
    FILTER NOT EXISTS {?s <GRAPH_NAME>:suspicious ?susp}.
    } 
""",
'Delete_Suspicious_Labels': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/>
    DELETE {?s <GRAPH_NAME>:suspicious ?q . }
    WHERE {
        ?s <GRAPH_NAME>:suspicious ?q .
    } 

""",
                  'Extract_Suspicious_Subgraph_withTime' : """
    PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/>

    SELECT DISTINCT * {
        {
            # 1- forward
            SELECT DISTINCT ?subject ?predicate ?object ?timestamp
            WHERE {
                << ?subject ?predicate ?object >> <GRAPH_NAME>:timestamp ?timestamp .
                ?subject <GRAPH_NAME>:uuid ?IOC_node .
                {?object rdf:type "process"} UNION {?object <GRAPH_NAME>:suspicious <Query> } .
            }
        } UNION {
            #2- backward
            SELECT DISTINCT ?subject ?predicate ?object ?timestamp
            WHERE {
                << ?subject ?predicate ?object >> <GRAPH_NAME>:timestamp ?timestamp .
                ?object <GRAPH_NAME>:uuid ?IOC_node .
                {?subject rdf:type "process"} UNION {?subject <GRAPH_NAME>:suspicious <Query>} .
            }
        } 
        UNION {
            #3-a forward from all first neighbours  
            SELECT DISTINCT (?first_object as ?subject) (?next_predicate as ?predicate) (?next_object as ?object) ?timestamp
            WHERE {
                ?first_subject ?first_predicate ?first_object .
                << ?first_object ?next_predicate ?next_object >> <GRAPH_NAME>:timestamp ?timestamp . 
                ?first_subject <GRAPH_NAME>:uuid ?IOC_node .
                {?first_object rdf:type "process"} UNION {?first_object <GRAPH_NAME>:suspicious <Query>} .
                {?next_object rdf:type "process"} UNION {?next_object <GRAPH_NAME>:suspicious <Query>} .
            }    
        } UNION {
            #3-b forward from all first neighbours  
            SELECT DISTINCT (?first_subject as ?subject) (?next_predicate as ?predicate) (?next_object as ?object)  ?timestamp
            WHERE {
                ?first_subject ?first_predicate ?first_object .
                <<?first_subject ?next_predicate ?next_object >> <GRAPH_NAME>:timestamp ?timestamp . 
                ?first_object <GRAPH_NAME>:uuid ?IOC_node .
                {?first_subject rdf:type "process"} UNION {?first_subject <GRAPH_NAME>:suspicious <Query>} .
                {?next_object rdf:type "process"} UNION {?next_object <GRAPH_NAME>:suspicious <Query>} .
            }    
        } UNION {
            #4-a Backward from all first neighbours  
            SELECT DISTINCT (?next_subject as ?subject) (?next_predicate as ?predicate) (?first_object as ?object) ?timestamp 
            WHERE {
                ?first_subject ?first_predicate ?first_object .
                << ?next_subject ?next_predicate ?first_object >> <GRAPH_NAME>:timestamp ?timestamp .
                ?first_subject <GRAPH_NAME>:uuid ?IOC_node . 
                {?next_subject rdf:type "process"} UNION {?next_subject <GRAPH_NAME>:suspicious <Query>} .
                {?first_object rdf:type "process"} UNION {?first_object <GRAPH_NAME>:suspicious <Query>} .
            }    
        } UNION {
            #4-b Backward from all first neighbours  
            SELECT DISTINCT (?next_subject as ?subject) (?next_predicate as ?predicate) (?first_subject as ?object) ?timestamp
            WHERE {
                ?first_subject ?first_predicate ?first_object .
                << ?next_subject ?next_predicate ?first_subject >> <GRAPH_NAME>:timestamp ?timestamp .
                ?first_object <GRAPH_NAME>:uuid ?IOC_node .
                {?next_subject rdf:type "process"} UNION {?next_subject <GRAPH_NAME>:suspicious <Query>} .
                {?first_subject rdf:type "process"} UNION {?first_subject <GRAPH_NAME>:suspicious <Query>} .
            }    
        }  
    }   
""",
'Extract_Suspicious_Subgraph_NoTime': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/> 
    SELECT  DISTINCT ?subject ?predicate ?object {
        {
            # 1- forward
            SELECT DISTINCT ?subject ?predicate ?object 
            WHERE {
                ?subject ?predicate ?object .
                ?subject <GRAPH_NAME>:uuid ?IOC_node .
                ?object rdf:type|<GRAPH_NAME>:suspicious ?candidate .
                FILTER (?candidate IN ("process", <Query>)).
                FILTER regex(str(?predicate), ".*/event/.*") .
            }   LIMIT <MAX_EDGES>  
        } 
        UNION 
        {
            #2- backward
            SELECT DISTINCT ?subject ?predicate ?object 
            WHERE {
                ?subject ?predicate ?object .
                ?object <GRAPH_NAME>:uuid ?IOC_node .
                ?subject rdf:type|<GRAPH_NAME>:suspicious ?candidate .
                FILTER (?candidate IN ("process", <Query>)).
                FILTER regex(str(?predicate), ".*/event/.*") .
            } LIMIT <MAX_EDGES>  
        } 
        UNION 
        {
            # 3-a forward from all first neighbours  
            SELECT 
            (?first_object as ?subject) (?next_predicate as ?predicate) (?next_object as ?object) 
            WHERE {
                ?first_object ?next_predicate ?next_object .
                {
                    SELECT DISTINCT ?first_object 
                    WHERE {
                        ?first_subject ?first_predicate ?first_object .
                        ?first_subject <GRAPH_NAME>:uuid ?IOC_node .
                        ?first_object rdf:type|<GRAPH_NAME>:suspicious ?candidate .
                        FILTER (?candidate IN ("process", <Query>)).
                        FILTER regex(str(?first_predicate), ".*/event/.*") .
                    }
                }
                ?next_object rdf:type|<GRAPH_NAME>:suspicious ?candidate2 .
                FILTER (?candidate2 IN ("process", <Query>)).
                FILTER regex(str(?next_predicate), ".*/event/.*") .
            }    LIMIT <MAX_EDGES> 
        } 
        UNION {
             # 3-b forward from all first neighbours  
            SELECT DISTINCT (?first_subject as ?subject) (?next_predicate as ?predicate) (?next_object as ?object)  
            WHERE {
                ?first_subject ?next_predicate ?next_object
                { 
                    SELECT DISTINCT ?first_subject
                    WHERE {
                        ?first_subject ?first_predicate ?first_object .
                        ?first_object <GRAPH_NAME>:uuid ?IOC_node .
                        ?first_subject rdf:type|<GRAPH_NAME>:suspicious ?candidate .
                        FILTER (?candidate IN ("process", <Query>)).
                        FILTER regex(str(?first_predicate), ".*/event/.*") .
                    }
                }
                ?next_object rdf:type|<GRAPH_NAME>:suspicious ?candidate2 .
                FILTER (?candidate2 IN ("process", <Query>)).
                FILTER regex(str(?next_predicate), ".*/event/.*") .
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
                        ?first_object rdf:type|<GRAPH_NAME>:suspicious ?candidate .
                        FILTER (?candidate IN ("process", <Query>)).
                        FILTER regex(str(?first_predicate), ".*/event/.*") .
                    }
                }
                ?next_subject rdf:type|<GRAPH_NAME>:suspicious ?candidate2 .
                FILTER (?candidate2 IN ("process", <Query>)).
                FILTER regex(str(?next_predicate), ".*/event/.*") .
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
                        ?first_subject rdf:type|<GRAPH_NAME>:suspicious ?candidate .
                        FILTER (?candidate IN ("process", <Query>)).
                        FILTER regex(str(?first_predicate), ".*/event/.*") .
                    }
                }
                ?next_subject rdf:type|<GRAPH_NAME>:suspicious ?candidate2 .
                FILTER (?candidate2 IN ("process", <Query>)).
                FILTER regex(str(?next_predicate), ".*/event/.*") .
            }   LIMIT <MAX_EDGES>   
        }  
    } LIMIT <MAX_EDGES> 
""",

'Extract_Benign_Subgraph': """
    PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/> 
    SELECT  DISTINCT ?subject ?predicate ?object {
        {
            # 1- forward
            SELECT DISTINCT ?subject ?predicate ?object 
            WHERE {
                ?subject ?predicate ?object .
                ?subject <GRAPH_NAME>:uuid ?IOC_node .
                FILTER NOT EXISTS {?object <GRAPH_NAME>:suspicious ?susp}.
                FILTER regex(str(?predicate), ".*/event/.*") .
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
                FILTER regex(str(?predicate), ".*/event/.*") .
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
                        FILTER regex(str(?first_predicate), ".*/event/.*") .
                    }
                }
                FILTER NOT EXISTS {?next_object <GRAPH_NAME>:suspicious ?susp}.
                FILTER regex(str(?next_predicate), ".*/event/.*") .
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
                        FILTER regex(str(?first_predicate), ".*/event/.*") .
                    }
                }
                FILTER NOT EXISTS {?next_object <GRAPH_NAME>:suspicious ?susp}.
                FILTER regex(str(?next_predicate), ".*/event/.*") .
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
                        FILTER regex(str(?first_predicate), ".*/event/.*") .
                    }
                }
                FILTER NOT EXISTS {?next_subject <GRAPH_NAME>:suspicious ?susp}.
                FILTER regex(str(?next_predicate), ".*/event/.*") .
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
                        FILTER regex(str(?first_predicate), ".*/event/.*") .
                    }
                }
                FILTER NOT EXISTS {?next_subject <GRAPH_NAME>:suspicious ?susp}.
                FILTER regex(str(?next_predicate), ".*/event/.*") .
            }   LIMIT <MAX_EDGES>  
        }  
    }
    LIMIT <MAX_EDGES>
""",

'Process_attributes': """
PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/>
SELECT ?command_line
WHERE {
    ?s <GRAPH_NAME>:uuid ?Node .
    ?s rdf:type "process" . 
    ?s <GRAPH_NAME>:attributes ?_attr .
    ?_attr <GRAPH_NAME>:command_line ?command_line .
}
""",
'File_attributes': """
PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/>
SELECT ?object_paths
WHERE {
    ?s <GRAPH_NAME>:uuid ?Node .
    ?s rdf:type "file" . 
    ?s <GRAPH_NAME>:attributes ?_attr .
    ?_attr <GRAPH_NAME>:object_paths ?object_paths .
}
""",
'Flow_attributes': """
PREFIX <GRAPH_NAME>: <http://grapt.org/darpa_tc3/cadets/<GRAPH_NAME>/>
SELECT ?remote_ip ?remote_port ?local_ip ?local_port
WHERE {
    ?s <GRAPH_NAME>:uuid ?Node .
    ?s rdf:type "flow" .
    ?s <GRAPH_NAME>:attributes ?_attr .
    ?_attr <GRAPH_NAME>:remote_ip ?remote_ip .
    ?_attr <GRAPH_NAME>:remote_port ?remote_port .
    ?_attr <GRAPH_NAME>:local_ip ?local_ip .
    ?_attr <GRAPH_NAME>:local_port ?local_port .
}
"""
}

def label_candidate_nodes_rdf(graph_sparql_queries, query_graph_name):
    start_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    start_time = time.time()
    with open(args.ioc_file) as f:
        query_graphs_IOCs = json.load(f)
    try:
        ioc_ips = query_graphs_IOCs[query_graph_name]["ip"]
        ioc_files = query_graphs_IOCs[query_graph_name]["file"]
    except:
        print("No IOCs file",query_graphs_IOCs)
    suspicious_nodes = {}
    for ioc in ioc_files:
        ioc_pattern = "\"^(.*=>)?" + ioc + "(=>.*)?$\""
        csv_results = conn.select(graph_sparql_queries['Query_Suspicious_Files'], content_type='text/csv',bindings={'IOC': ioc_pattern}, timeout=900000)
        suspicious_nodes[ioc] = list(pd.read_csv(io.BytesIO(csv_results))["uuid"])
    for ip in ioc_ips:
        suspicious_nodes[ip] = []
    ioc_ips_string = str('( \"' + "\", \"".join(ioc_ips) + '\" )')

    graph_sparql_queries['Query_Suspicious_IP'] = graph_sparql_queries['Query_Suspicious_IP'].replace("<IOC_IP_LIST>",ioc_ips_string)
    csv_results = conn.select(graph_sparql_queries['Query_Suspicious_IP'], content_type='text/csv', timeout=1200000)
    df_suspicious_ip = pd.read_csv(io.BytesIO(csv_results))
    for _, row in df_suspicious_ip.iterrows():
        suspicious_nodes[row["ip"]].append(row["uuid"])
    count_suspicious_nodes = {}
    for n in suspicious_nodes:
        count_suspicious_nodes[n] = len(suspicious_nodes[n])
    all_suspicious_nodes = set([item for sublist in suspicious_nodes.values() for item in sublist])
    print("\nTotal number of matched nodes:", len(all_suspicious_nodes))
    print(count_suspicious_nodes)
    all_suspicious_nodes_string = str('( \"' + "\", \"".join(all_suspicious_nodes) + '\" )')
    Label_Suspicious_Nodes = graph_sparql_queries['Label_Suspicious_Nodes'].replace("<SUSPICIOUS_LIST>",
                                                                                    all_suspicious_nodes_string)
    conn.update(Label_Suspicious_Nodes)
    print("labelling Suspicious nodes in: --- %s seconds ---" % (time.time() - start_time))
    print("Memory usage : ", process.memory_info().rss / (1024 ** 2), "MB")
    if args.training:
        return
    return suspicious_nodes, all_suspicious_nodes


# def Traverse_rdf(graph_sparql_queries,node,suspicious = True):
def Traverse_rdf(params):
    traverse_time = time.time()
    global max_edges,max_node
    graph_sparql_queries = params[0]
    ioc = params[1]
    node = params[2]
    node = "\"" + node + "\""
    if args.training:
        rand_limit = random.randint((max_edges / 10), max_edges)
        try:
            csv_results = conn.select(graph_sparql_queries['Extract_Benign_Subgraph'], content_type='text/csv',
                                      bindings={'IOC_node': node}, limit=(rand_limit))
        except Exception as e:
            print("Error in Querying subgraph with seed", node, e)
            return None, None
    else:
        try:
            if args.traverse_with_time:
                csv_results = conn.select(graph_sparql_queries['Extract_Suspicious_Subgraph_withTime'],
                                          content_type='text/csv',
                                          bindings={'IOC_node': node}, limit=(max_edges+10))
            else:
                csv_results = conn.select(graph_sparql_queries['Extract_Suspicious_Subgraph_NoTime'], content_type='text/csv',
                                          bindings={'IOC_node': node}, limit=(max_edges+10))
        except Exception as e:
            print("Error in Querying subgraph with seed", node, e)
            return None, None
    subgraphTriples = pd.read_csv(io.BytesIO(csv_results))
    if len(subgraphTriples) > max_edges:
        print("Subgraph not within range", len(subgraphTriples))
        return None, None
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
    except:
        print("Not standard format for", node)
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
    nodes_df_s = pd.DataFrame()
    nodes_df_o = pd.DataFrame()
    nodes_df_s[["uuid", "type"]] = subgraphTriples[["subject_uuid", "subject_type"]]
    nodes_df_o[["uuid", "type"]] = subgraphTriples[["object_uuid", "object_type"]]
    nodes_df = pd.concat([nodes_df_s, nodes_df_o], ignore_index=True)
    nodes_df_s, nodes_df_o, subgraphTriples = None, None, None
    nodes_df = nodes_df.drop_duplicates()
    attributes_df = {}
    for index, row in nodes_df.iterrows():
        Node_pattern = "\"" + str(row['uuid']) + "\""
        if row['type'] == 'process':
            csv_results = conn.select(graph_sparql_queries['Process_attributes'], content_type='text/csv',
                                      bindings={'Node': Node_pattern})
            temp_df = pd.read_csv(io.BytesIO(csv_results))
            if temp_df.empty:
                attributes_df[row['uuid']] = {'type': row['type']}
            else:
                temp_df['type'] = row['type']
                attributes_df[row['uuid']] = temp_df.to_dict('records')[0]
        elif row['type'] == 'file':
            csv_results = conn.select(graph_sparql_queries['File_attributes'], content_type='text/csv',
                                      bindings={'Node': Node_pattern})
            temp_df = pd.read_csv(io.BytesIO(csv_results))
            if temp_df.empty:
                attributes_df[row['uuid']] = {'type': row['type']}
            else:
                temp_df['type'] = row['type']
                attributes_df[row['uuid']] = temp_df.to_dict('records')[0]
        elif row['type'] == 'flow':
            csv_results = conn.select(graph_sparql_queries['Flow_attributes'], content_type='text/csv',
                                      bindings={'Node': Node_pattern})
            temp_df = pd.read_csv(io.BytesIO(csv_results))
            if temp_df.empty:
                attributes_df[row['uuid']] = {'type': row['type']}
            else:
                temp_df['type'] = 'flow'
                attributes_df[row['uuid']] = temp_df.to_dict('records')[0]
        elif row['type'] in ['memory','pipe','shell']:
            attributes_df[row['uuid']] = {'type': row['type']}
        else:
            print("Undefined node type", row['type'])
    nx.set_node_attributes(subgraph, attributes_df)
    attributes_df, nodes_df, temp_df = None, None, None
    if subgraph.number_of_nodes() < args.min_nodes or subgraph.number_of_nodes() > max_nodes :
        print("Subgraph not within range", subgraph.number_of_nodes())
        return None, None
    print("Extracted a subgraph with", subgraph.number_of_nodes(), "nodes, and ", subgraph.number_of_edges(), "edges")
    print("Traversed in ", time.time() - traverse_time, "seconds")
    return ioc,subgraph



def extract_suspGraphs_depth_rdf(graph_sparql_queries, suspicious_nodes, all_suspicious_nodes):
    start_time = time.time()
    start_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    suspGraphs = []
    # suspGraphs_iterations = {}
    considered_per_ioc = {}
    represented_nodes_per_ioc = {}
    represented_ioc = set()
    matched_ioc_mask = copy.deepcopy(suspicious_nodes)
    for ioc in matched_ioc_mask:
        considered_per_ioc[ioc] = 0
    for ioc in matched_ioc_mask:
        represented_nodes_per_ioc[ioc] = 0
    if args.parallel:
        cores = multiprocessing.cpu_count() - 2
        if len(all_suspicious_nodes) < cores:
            cores = len(all_suspicious_nodes)
        multi_queries = [[graph_sparql_queries,ioc, node] for ioc,nodes in matched_ioc_mask.items() for node in nodes if len(nodes) > 0]
        suspicious_nodes_dask = db.from_sequence(multi_queries, npartitions=cores)
        tmp_suspGraphs = suspicious_nodes_dask.map(lambda g: Traverse_rdf(g)).compute()
        tmp_suspGraphs = [suspGraphs for suspGraphs in tmp_suspGraphs if suspGraphs is not None]
        for ioc,subgraph in tmp_suspGraphs:
            if subgraph:
                suspGraphs.append(subgraph.copy())
                considered_per_ioc[ioc] += 1
                subgraph.clear()
    else:
        for ioc,nodes in matched_ioc_mask.items():
            if len(nodes) > 0:
                for node in nodes:
                    ioc,subgraph = Traverse_rdf([graph_sparql_queries,ioc, node])
                    if subgraph:
                        suspGraphs.append(subgraph.copy())
                        considered_per_ioc[ioc] += 1
                        subgraph.clear()
    # clear Suspicious Nodes Labels
    conn.update(graph_sparql_queries['Delete_Suspicious_Labels'])
    # Add ioc attributes
    revert_suspicious_nodes = dict((node, ioc) for ioc, list_nodes in suspicious_nodes.items() for node in list_nodes)
    for subgraph in suspGraphs:
        for node_id, node_attr in list(subgraph.nodes.data()):
            subgraph.nodes[node_id]["candidate"] = False
            if node_id in all_suspicious_nodes:
                subgraph.nodes[node_id]["candidate"] = True
                subgraph.nodes[node_id]["ioc"] = revert_suspicious_nodes[node_id]
                represented_ioc.add(revert_suspicious_nodes[node_id])
                represented_nodes_per_ioc[revert_suspicious_nodes[node_id]] += 1
    suspicious_nodes, all_suspicious_nodes, revert_suspicious_nodes = None, None, None

    print("Number of subgraphs:", len(suspGraphs))
    print("Number of extracted subgraph per IOC:\n", considered_per_ioc)
    print("Total extracted subgraphs represent",len(represented_ioc),"IOCs out of",len(matched_ioc_mask.keys()))
    print("Number of represented nodes per IOC in all extracted subgraphs:\n",represented_nodes_per_ioc)
    if len(suspGraphs) > 0:
        print("Average number of nodes in subgraphs:",
              round(mean([supgraph.number_of_nodes() for supgraph in suspGraphs])))
        print("Average number of edges in subgraphs:",
              round(mean([supgraph.number_of_edges() for supgraph in suspGraphs])))
    print("Extract suspicious subgraphs in --- %s seconds ---" % (time.time() - start_time))
    construct_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - start_mem
    print("\nMemory usage: ", process.memory_info().rss / (1024 ** 2), "MB")
    return suspGraphs


def Extract_Random_Benign_Subgraphs(graph_sparql_queries, n_subgraphs):
    start_time = time.time()
    benignSubGraphs = []
    if args.parallel:
        # Query with DASK
        cores = multiprocessing.cpu_count() - 2
        seed_number = n_subgraphs
        while len(benignSubGraphs) < n_subgraphs:
            csv_results = conn.select(graph_sparql_queries['Random_Benign_Nodes'], content_type='text/csv',
                                      limit=(seed_number))
            benign_nodes = list(pd.read_csv(io.BytesIO(csv_results))["uuid"])
            print("Number of Random Benign Seed Nodes:", len(benign_nodes))
            benign_nodes = list(pd.read_csv(io.BytesIO(csv_results))["uuid"])
            multi_queries = [[graph_sparql_queries, node] for node in benign_nodes]
            benign_nodes_dask = db.from_sequence(multi_queries, npartitions=cores)
            tmp_benignSubGraphs = benign_nodes_dask.map(lambda g: Traverse_rdf(g)).compute()
            for subgraph in tmp_benignSubGraphs:
                if subgraph:
                    print(subgraph.number_of_nodes(), subgraph.number_of_edges())
                    benignSubGraphs.append(subgraph.copy())
                    subgraph.clear()
            seed_number = 10
    else:
        # Query Sequentially
        csv_results = conn.select(graph_sparql_queries['Random_Benign_Nodes'], content_type='text/csv',
                                  limit=(n_subgraphs * 3))
        benign_nodes = list(pd.read_csv(io.BytesIO(csv_results))["uuid"])
        print("Number of Random Benign Seed Nodes:", len(benign_nodes))
        for node in benign_nodes:
            subgraph = Traverse_rdf([graph_sparql_queries, node])
            if subgraph:
                print(subgraph.number_of_nodes(), subgraph.number_of_edges())
                if subgraph.number_of_nodes() >= args.min_nodes and subgraph.number_of_nodes() <= args.max_nodes:
                    benignSubGraphs.append(subgraph.copy())
                subgraph.clear()
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
    return benignSubGraphs


def subgraph_quality_check_per_query(subgraphs, suspicious_nodes, min_iocs):
    covered_attacks = {}
    accepted_subgraphs = []
    for i, g in enumerate(subgraphs):
        covered_ioc = set([nodes[1]["ioc"] for nodes in g.nodes.data() if nodes[1]["candidate"]])
        covered_ioc_per_query = []
        accepted = False
        for ioc in suspicious_nodes:
            if ioc.lower() in covered_ioc:
                covered_ioc_per_query.append(ioc.lower())
        if len(covered_ioc_per_query) >= min_iocs:
            accepted = True
        if accepted:
            accepted_subgraphs.append(g)
    if len(subgraphs) == 0:
        print("No Subgraphs")
    else:
        print("Accepted", len(accepted_subgraphs), " out of ", len(subgraphs))
        print("Acceptance rate is: ", len(accepted_subgraphs) / len(subgraphs))
    if min_iocs == args.min_iocs:
        return accepted_subgraphs
    else:
        return


def encode_for_RGCN(g):
#     print("Encoding a subgraph with",g.number_of_nodes(),g.number_of_edges())
    types = ['PROCESS', 'FILE', 'FLOW','memory']
    mapping = {name: j for j, name in enumerate(g.nodes())}
    g = nx.relabel_nodes(g, mapping)
    x = torch.zeros(g.number_of_nodes(), dtype=torch.long)
    tmp_g = copy.deepcopy(g)
    for node, info in g.nodes(data=True):
        try:
            x[int(node)] = types.index(info['type'].upper())
        except Exception as e:
            print("Undefined node type. The error", e, "The nodes attributes", info)
            g.remove_node(node)
            continue
    g = copy.deepcopy(tmp_g)
    x = F.one_hot(x, num_classes=len(types)).to(torch.float)
    for node in g.nodes():
        g.nodes[node]["label"] = x[node]
    edge_types = ['ACCEPT', 'ADD_OBJECT_ATTRIBUTE', 'BIND', 'CHANGE_PRINCIPAL', 'CLOSE', 'CONNECT', 'CREATE_OBJECT', 'EXECUTE', 'EXIT', 'FCNTL', 'FLOWS_TO', 'FORK', 'LINK', 'LOGIN', 'LSEEK', 'MMAP', 'MODIFY_FILE_ATTRIBUTES', 'MODIFY_PROCESS', 'MPROTECT', 'OPEN', 'OTHER', 'READ', 'RECVFROM', 'RECVMSG', 'RENAME', 'SENDMSG', 'SENDTO', 'SIGNAL', 'TRUNCATE', 'UNLINK', 'WRITE']
    for n1, n2, info in g.edges(data=True):
        for k, info in g.get_edge_data(n1, n2).items():
            try:
                g.edges[n1, n2, k]["edge_label"] = edge_types.index(info['type'].upper())
            except Exception as e:
                print("Undefined edge type. The error", e, "The nodes attributes", info)
    dgl_graph = dgl.from_networkx(g, node_attrs=["label"], edge_attrs=["edge_label"])
    g.clear()
    x = None
    return dgl_graph


def convert_prediction_to_torch_data(prediction_graphs_dgl, g_name):
    prediction_data_list = []
    for i, g in enumerate(prediction_graphs_dgl):
        edge_index = torch.tensor([g.edges()[0].tolist(), g.edges()[1].tolist()])
        data = Data(edge_index=edge_index, g_name=g_name, i=str(i))
        data.num_nodes = g.number_of_nodes()
        data.nlabel = g.ndata['label']
        data.elabel = g.edata['edge_label']
        prediction_data_list.append(data)
    return prediction_data_list


def convert_query_to_torch_data(query_graphs_dgl):
    query_data_list = []
    for g_name, g in query_graphs_dgl.items():
        edge_index = torch.tensor([g.edges()[0].tolist(), g.edges()[1].tolist()])
        data = Data(edge_index=edge_index, g_name=g_name)
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


def process_one_graph(GRAPH_IRI, sparql_queries, query_graph_name):
    start_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    one_graph_time = time.time()
    global max_edges,max_node
    query_pattern = '\"' + query_graph_name + '\"'
    GRAPH_NAME = str(GRAPH_IRI.split("/")[-2])
    print("\nprocessing ", GRAPH_NAME, "with", query_graph_name)
    print("Extract Subgraphs From", GRAPH_NAME)
    graph_sparql_queries = copy.deepcopy(sparql_queries)
    for sparql_name, sparql_query in graph_sparql_queries.items():
        graph_sparql_queries[sparql_name] = sparql_query.replace("<Query>", query_pattern).replace("<GRAPH_NAME>",GRAPH_NAME).replace("<MAX_EDGES>", str(max_edges+10))
    suspicious_nodes, all_suspicious_nodes = label_candidate_nodes_rdf(graph_sparql_queries, query_graph_name)
    if len(all_suspicious_nodes) == 0:
        print("No suspicious Nodes in ", GRAPH_NAME, "with", query_graph_name)
        print("\nprocessed", GRAPH_NAME, "with", query_graph_name,
              " in: --- %s seconds ---" % (time.time() - one_graph_time))
        print("\nExtraction Memory usage: ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
        return
    suspSubGraphs = extract_suspGraphs_depth_rdf(graph_sparql_queries, suspicious_nodes,
                                                                       all_suspicious_nodes)
    if len(suspSubGraphs) == 0:
        print("No suspicious subgraphs in", GRAPH_NAME, "with", query_graph_name)
        print("\nprocessed", GRAPH_NAME, "with", query_graph_name,
              " in: --- %s seconds ---" % (time.time() - one_graph_time))
        print("\nExtraction Memory usage: ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
        return
    checkpoint(suspSubGraphs,
               ( "./dataset/" + args.dataset + "/" + args.output_prx + "/predict/nx_suspicious_" + query_graph_name + "_in_" + GRAPH_NAME + ".pt"))
    for i in range(1, 4):
        print("\nCheck Quality for", i, " IOCs of corresponding query graph")
        if i == args.min_iocs:
            accepted_suspSubGraphs = subgraph_quality_check_per_query(suspSubGraphs, suspicious_nodes, min_iocs=i)
            print("\nAccepted Subgraphs with ", args.min_iocs, " IOCs of corresponding query graph")
            print("Number of accepted subgraph:", len(accepted_suspSubGraphs))
            if accepted_suspSubGraphs == 0:
                print("No accepted subgraphs for", GRAPH_NAME, "with", query_graph_name)
                return
            checkpoint(accepted_suspSubGraphs, (
                        "./dataset/" + args.dataset + "/" + args.output_prx + "/predict/nx_accepted_suspSubGraphs_" + query_graph_name + "_in_" + GRAPH_NAME + ".pt"))
            suspSubGraphs = accepted_suspSubGraphs
        else:
            subgraph_quality_check_per_query(suspSubGraphs, suspicious_nodes, min_iocs=i)
    if len(suspSubGraphs) == 0:
        print("No suspicious subgraphs in", GRAPH_NAME, "with", query_graph_name)
        print("\nprocessed", GRAPH_NAME, "with", query_graph_name,
              " in: --- %s seconds ---" % (time.time() - one_graph_time))
        print("\nExtraction Memory usage: ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
        return
    print("Encoding prediction subgraphs")
    if args.parallel:
        cores = multiprocessing.cpu_count() - 2
        suspSubGraphs_dask = db.from_sequence(suspSubGraphs, npartitions=cores)
        prediction_graphs_dgl = suspSubGraphs_dask.map(lambda g: encode_for_RGCN(g)).compute()
    else:
        prediction_graphs_dgl = [encode_for_RGCN(g) for g in suspSubGraphs]
    checkpoint(prediction_graphs_dgl,
               ("./dataset/" + args.dataset + "/" + args.output_prx + "/predict/dgl_prediction_graphs_" + query_graph_name + "_in_" + GRAPH_NAME + ".pt"))
    suspSubGraphs, suspicious_nodes, all_suspicious_nodes = None, None, None
    prediction_data_list_host = convert_prediction_to_torch_data(prediction_graphs_dgl,GRAPH_NAME)
    prediction_graphs_dgl= None
    print("Number of prediction samples from host", GRAPH_NAME, len(prediction_data_list_host))
    checkpoint(prediction_data_list_host, ("./dataset/" + args.dataset + "/" + args.output_prx + "/raw/torch_prediction/" + query_graph_name + "_in_" + GRAPH_NAME + ".pt"))
    prediction_data_list_host = None
    extraction_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - start_mem
    print("\nprocessed", GRAPH_NAME, "with", query_graph_name," in: --- %s seconds ---" % (time.time() - one_graph_time))
    print("\nExtraction Memory usage: ", process.memory_info().rss / (1024 ** 2), "MB (based on psutil Lib)")
    print("\n Extraction Memory usage: ", extraction_mem / 1024, "MB (based on resource - ru_maxrss)")
    return


def process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs, n_subgraphs=args.n_subgraphs):
    one_graph_time = time.time()
    current_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    global max_edges,max_node
    GRAPH_NAME = GRAPH_IRI.split("/")[-2]
    print("\nprocessing ", GRAPH_NAME)
    graph_sparql_queries = copy.deepcopy(sparql_queries)
    for sparql_name, sparql_query in graph_sparql_queries.items():
        graph_sparql_queries[sparql_name] = sparql_query.replace("<GRAPH_NAME>", GRAPH_NAME).replace("<MAX_EDGES>",str(max_edges + 10))
    for query_graph_name in query_graphs:
        query_pattern = '\"' + query_graph_name + '\"'
        temp_graph_sparql_queries = copy.deepcopy(graph_sparql_queries)
        temp_graph_sparql_queries["Label_Suspicious_Nodes"] = temp_graph_sparql_queries[
            "Label_Suspicious_Nodes"].replace("<Query>", query_pattern)
        print("Labelling", query_graph_name)
        label_candidate_nodes_rdf(temp_graph_sparql_queries, query_graph_name)
    benignSubGraphs = Extract_Random_Benign_Subgraphs(graph_sparql_queries, n_subgraphs)
    print("Encoding the random benign subgraphs")
    benignSubGraphs_dgl = [encode_for_RGCN(g) for g in benignSubGraphs]
    benignSubGraphs = None
    # clear suspicious labels
    conn.update(graph_sparql_queries['Delete_Suspicious_Labels'])
    print("\nprocessed", GRAPH_NAME, " in: --- %s seconds ---" % (time.time() - one_graph_time))
    return benignSubGraphs_dgl


def trim_memory() -> int:
    libc = ctypes.CDLL("libc.so.6")
    return libc.malloc_trim(0)
def release_memory(client):
    client.restart()
    client.run(gc.collect)
    client.run(trim_memory)
    
def main():
    print(args)
    start_running_time = time.time()
    random.seed(123)
    global max_edges,max_nodes
    max_edges = args.max_edges_training
    max_nodes = args.max_nodes_training
    if args.parallel:
        cores = multiprocessing.cpu_count() - 2
        print("Number of used cores is ", cores)
        cluster = LocalCluster(n_workers=cores)
        client = Client(cluster)
        client.run(gc.collect)
    client.run(trim_memory)
    print("processing query graphs")
    query_graphs = {}
    for graph_name in glob.glob((args.query_graphs_folder + '*')):
        query_graphs[graph_name.replace(".json", "").split("/")[-1]] = read_json_graph(graph_name)
    query_graphs_dgl = {g_name: encode_for_RGCN(query_graphs[g_name]) for g_name in query_graphs}
    query_data_list = convert_query_to_torch_data(query_graphs_dgl)
    print("processed", len(query_data_list), "query graphs")
    checkpoint(query_data_list,
               ("./dataset/" + args.dataset + "/" + args.output_prx + "/raw/torch_query_dataset.pt"))
    if args.training:
        training_dataset = []
        testing_dataset = []
        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_3_4/"
        if args.n_subgraphs:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs)
        else:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs, 250)

        print("Add ", GRAPH_IRI.split("/")[-2], " to training set.\n\n")
        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
        checkpoint(training_dataset,
                   ("./dataset/" + args.dataset + "/" + args.output_prx + "/raw/tmp_dgl_training_dataset.pt"))

        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_1/"
        if args.n_subgraphs:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs)
        else:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs, 250)

        print("Add ", GRAPH_IRI.split("/")[-2], " to training set.\n\n")
        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
        checkpoint(training_dataset,
                   ("./dataset/" + args.dataset + "/" + args.output_prx + "/raw/tmp_dgl_training_dataset.pt"))

        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_2/"
        if args.n_subgraphs:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs)
        else:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs, 250)
        print("Add ", GRAPH_IRI.split("/")[-2], " to training set.\n\n")
        training_dataset = training_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None
        print("Training Samples", len(training_dataset))
        checkpoint(training_dataset,
                   ("./dataset/" + args.dataset + "/" + args.output_prx + "/raw/dgl_training_dataset.pt"))

        print("Training Samples", len(training_dataset))
        # Don't use any of the testing (prediction) samples in training
        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/benign_BSD/"
        if args.n_subgraphs:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs)
        else:
            benignSubGraphs_dgl = process_one_graph_training(GRAPH_IRI, sparql_queries, query_graphs, 250)

        print("Add ", GRAPH_IRI.split("/")[-2], " to testing set.\n\n")
        testing_dataset = testing_dataset + benignSubGraphs_dgl
        benignSubGraphs_dgl = None

        print("Testing Samples", len(testing_dataset))
        checkpoint(testing_dataset,
                   ("./dataset/" + args.dataset + "/" + args.output_prx + "/raw/dgl_testing_dataset.pt"))

        torch_training_set, torch_testing_set = convert_to_torch_data(training_dataset, testing_dataset)
        checkpoint(torch_training_set,
                   ("./dataset/" + args.dataset + "/" + args.output_prx + "/raw/torch_training_dataset.pt"))
        checkpoint(torch_testing_set,
                   ("./dataset/" + args.dataset + "/" + args.output_prx + "/raw/torch_testing_dataset.pt"))

    elif(args.test_a_qg):
        print("Extracting suspicious subgraphs for",args.test_a_qg,"in PG:",args.pg_name)
        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/" + args.pg_name +"/"
        max_nodes = query_graphs[args.test_a_qg].number_of_nodes() * args.max_nodes_mult_qg
        print("Max Nodes",max_nodes)
        max_edges = query_graphs[args.test_a_qg].number_of_edges() * args.max_edges_mult_qg
        print("Max Edges",max_edges)
        process_one_graph(GRAPH_IRI, sparql_queries, args.test_a_qg)
        print("********************************************")
        print("********************************************")
    else:
        print("processing Provenance Graphs prediction samples")
        query_graph_name = "BSD_1"
        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_1/"
        max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
        print("Max Nodes",max_nodes)
        max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
        print("Max Edges",max_edges)
        process_one_graph(GRAPH_IRI, sparql_queries, query_graph_name)

        query_graph_name = "BSD_2"
        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_2/"
        max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
        print("Max Nodes",max_nodes)
        max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
        print("Max Edges",max_edges)
        process_one_graph(GRAPH_IRI, sparql_queries, query_graph_name)

        query_graph_name = "BSD_3"
        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_3_4/"
        max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
        print("Max Nodes",max_nodes)
        max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
        print("Max Edges",max_edges)
        process_one_graph(GRAPH_IRI, sparql_queries, query_graph_name)

        query_graph_name = "BSD_4"
        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/attack_BSD_3_4/"
        max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
        print("Max Nodes",max_nodes)
        max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
        print("Max Edges",max_edges)
        process_one_graph(GRAPH_IRI, sparql_queries, query_graph_name)

        GRAPH_IRI = "http://grapt.org/darpa_tc3/cadets/benign_BSD/"
        for query_graph_name in query_graphs:
            max_nodes = query_graphs[query_graph_name].number_of_nodes() * args.max_nodes_mult_qg
            print("Max Nodes",max_nodes)
            max_edges = query_graphs[query_graph_name].number_of_edges() * args.max_edges_mult_qg
            print("Max Edges",max_edges)
            process_one_graph(GRAPH_IRI, sparql_queries, query_graph_name)

    print("---Total Running Time for", args.dataset, "host is: %s seconds ---" % (time.time() - start_running_time))
    if args.parallel:
        release_memory(client)

if __name__ == "__main__":
    main()
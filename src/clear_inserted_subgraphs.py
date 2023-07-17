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
parser.add_argument('--output-prx', type=str, help='output file prefix ', default=None)
parser.add_argument('--file-path', nargs="?", help='delete one file', default=None)
parser.add_argument('--dataset', nargs="?", help='Dataset name', default="darpa_cadets")
parser.add_argument("--pg-name",type=str,default=None,help="The nae of the tested provenance graph.")
parser.add_argument('--database-name', type=str, help='Stardog database name', default='tc3_cadets_mimicry')
args = parser.parse_args()

database_name, connection_details = get_stardog_cred(args.database_name)
conn = stardog.Connection(database_name, **connection_details)
GRAPT_IRI_map = {"darpa_cadets":"darpa_tc3/cadets","darpa_theia":"darpa_tc3/theia","darpa_trace":"darpa_tc3/trace","darpa_optc":"darpa_optc"}

def read_json_graph(filename):
    with open(filename) as f:
        js_graph = json.load(f)
    return json_graph.node_link_graph(js_graph)
def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

        
delete_mutated_edges = """
    PREFIX <GRAPH_NAME>: <http://grapt.org/<DATASET>/<GRAPH_NAME>/>
    PREFIX mutated_event: <http://grapt.org/<DATASET>/<GRAPH_NAME>/event/mutated> 
    DELETE {?s ?p ?o . }
    WHERE {
        ?s ?p ?o .
        filter strstarts(str(?p),str(mutated_event:))
    }  
    """ 
        
# delete data from stardog
def delete_all_inserted_subgraphs(folder_path):
    n_files = 0
    for file_path in glob.glob(folder_path+'*'):
        with open(file_path, "r") as turtle_file:
            benign_subgraph_turtle = turtle_file.read()
        conn.begin()
        conn.remove(stardog.content.Raw(benign_subgraph_turtle.encode('utf-8'), content_type='text/turtle'))
        conn.commit()
        print("deleted inserted subgraphs from stardog, file",file_path)
        n_files +=1
    print("deleted", n_files, "files")
    return 


def delete_inserted_subgraphs(file_path):
    with open(file_path, "r") as turtle_file:
        benign_subgraph_turtle = turtle_file.read()
    conn.begin()
    conn.remove(stardog.content.Raw(benign_subgraph_turtle.encode('utf-8'), content_type='text/turtle'))
    conn.commit()
    return

def delete_all_mutated_edges():
    delete_mutated_edges_tmp = copy.deepcopy(delete_mutated_edges)
    delete_mutated_edges_tmp = delete_mutated_edges.replace("<GRAPH_NAME>",args.pg_name).replace("<DATASET>", GRAPT_IRI_map[args.dataset])
    conn.update(delete_mutated_edges_tmp)  
    print("Deleted all mutated edges") 
    return 
    
def main():
    print(args)
    start_running_time = time.time()
    delete_all_mutated_edges()
    # if args.file_path:
    #     delete_inserted_subgraphs(args.file_path)
    # else:
    #     folder_path =  "./dataset/" + args.dataset +"/" + args.output_prx + "/inserted_subgraphs/"
    #     delete_all_inserted_subgraphs(folder_path)
    #     bck_path = folder_path.replace("inserted_subgraphs","bck_inserted_subgraphs")
    #     ensure_dir(bck_path)
    #     os.system('mv  '+folder_path+'* ' + bck_path)
    #     print("moved inserted subgraphs to bck folder")
   
if __name__ == "__main__":
    main()
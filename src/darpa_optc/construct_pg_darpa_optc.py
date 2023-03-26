import networkx as nx 
import pandas as pd
import numpy as np
from datetime import datetime
import pytz
import time
import os
import json
from networkx.readwrite import json_graph
import resource

def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
username = ""
password = ""
dataset = "darpa_optc"
db_url = 'postgresql+psycopg2://' + username + ':' + password + '@localhost/' + dataset

n_query = """
SELECT COUNT(*)
FROM "{}"
WHERE DATE("timestamp") >=  %(start_date)s AND DATE("timestamp") < %(end_date)s;
"""
query_events = """
SELECT "actorID" , "objectID" ,"event_id","action" as type,"timestamp"
FROM "{}"
WHERE DATE("timestamp") >= %(start_date)s AND DATE("timestamp") < %(end_date)s;
"""
query_type_nodes = """
SELECT "objectID" ,MAX("object") as type
FROM "{}"
WHERE DATE("timestamp") >= %(start_date)s AND DATE("timestamp") < %(end_date)s
GROUP BY "objectID";
"""

query_file_attrs = """
    SELECT ev."objectID" , STRING_AGG(DISTINCT pr."file_path",'=>') as file_paths
    FROM "{}" as pr ,"{}" as ev
    WHERE pr."property_id" = ev."event_id"
    AND ev."object" = 'FILE'
    AND pr."file_path" IS NOT NULL
    AND DATE("timestamp") >= %(start_date)s AND DATE("timestamp") < %(end_date)s
    GROUP BY 1;
"""
query_flow_attrs = """
    SELECT DISTINCT ev."objectID" , pr."src_ip" , pr."src_port" , pr."dest_ip" , pr."dest_port",pr."l4protocol"
    FROM "{}" as pr ,"{}" as ev
    WHERE pr."property_id" = ev."event_id"
    AND ev."object" = 'FLOW'
    AND DATE("timestamp") >= %(start_date)s AND DATE("timestamp") < %(end_date)s;
"""
query_process_attrs = """
    SELECT ev."objectID" , STRING_AGG(pr."command_line",'=>') as command_lines , STRING_AGG(DISTINCT pr."image_path",'=>') as image_paths 
    FROM "{}" as pr ,"{}" as ev
    WHERE pr."property_id" = ev."event_id"
    AND ev."object" = 'PROCESS'
    AND (pr."command_line" IS NOT NULL OR pr."image_path" IS NOT NULL )
    AND DATE("timestamp") >= %(start_date)s AND DATE("timestamp") < %(end_date)s
    GROUP BY 1;
"""

def explore_graph(g):
    print("Number of nodes: ", g.number_of_nodes())
    print("Number of edges: ", g.number_of_edges())
    x  = list(g.nodes.data("type"))
    unique_nodes_types = list(set([y[1] for y in x]))
    print("\nUnique nodes type:",unique_nodes_types)
    for i in unique_nodes_types:
        print(i,": ", len([node_id for node_id, node_type in g.nodes.data("type") if node_type == i]) )
    x  = list(g.edges.data("type"))
    unique_edges_types = list(set([y[2] for y in x]))
    print("\nUnique edges type:",unique_edges_types)
    for i in unique_edges_types:
        print(i,": ", len([node_id for node_id,_, node_type in g.edges.data("type") if node_type == i]) )
        
def build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end):
    start_time = time.time()
    current_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print("Constructing:", provenance_graph_name)
    event_table_name = provenance_graph_name.replace("attack_","").replace("benign_","") + "Events"
    property_table_name = provenance_graph_name.replace("attack_","").replace("benign_","") + "Properties"
    total_events = pd.read_sql(n_query.format(event_table_name),db_url,
                       params={"start_date":provenance_graph_start,"end_date":provenance_graph_end})["count"].item()                   
    print("Total Number of Events:",total_events)
    df_events = pd.read_sql(query_events.format(event_table_name),db_url,
                       params={"start_date":provenance_graph_start,"end_date":provenance_graph_end})
    df_events['timestamp'] = df_events['timestamp'].astype(str)
    provenance_graph = nx.from_pandas_edgelist(
        df_events,
        source="actorID",
        target="objectID",
        edge_attr=["event_id","type","timestamp"],
        create_using=nx.MultiDiGraph()
    )
    df_events = None
    print("Number of Nodes:",provenance_graph.number_of_nodes(),"\nNumber of Edges",provenance_graph.number_of_edges())
    
    df_nodes_types = pd.read_sql(query_type_nodes.format(event_table_name),db_url,
                       params={"start_date":provenance_graph_start,"end_date":provenance_graph_end})
    node_attr = df_nodes_types.set_index('objectID').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    df_nodes_types,node_attr = None, None
    
    df_files_attrs = pd.read_sql(query_file_attrs.format(property_table_name,event_table_name),db_url,
                       params={"start_date":provenance_graph_start,"end_date":provenance_graph_end})
    node_attr = df_files_attrs.set_index('objectID').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    df_files_attrs,node_attr = None, None
    
    df_flow_attrs = pd.read_sql(query_flow_attrs.format(property_table_name,event_table_name),db_url,
                       params={"start_date":provenance_graph_start,"end_date":provenance_graph_end})
    node_attr = df_flow_attrs.set_index('objectID').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    df_flow_attrs,node_attr = None,None
    
    df_process_attrs = pd.read_sql(query_process_attrs.format(property_table_name,event_table_name),db_url,
                       params={"start_date":provenance_graph_start,"end_date":provenance_graph_end})
    node_attr = df_process_attrs.set_index('objectID').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    df_process_attrs,node_attr = None,None
    explore_graph(provenance_graph)
#     print("Writing the graph to a file")
#     json_provenance_graph = json_graph.node_link_data(provenance_graph)
#     file_path = "./dataset/darpa_optc/provenance_graphs_v2/" + provenance_graph_name + ".json"
#     with open(file_path, 'w') as f:
#         json.dump(json_provenance_graph, f)
#     json_provenance_graph = None
    construct_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - current_mem
    print("\nMemory usage to constract the provenance graph: %s"% construct_mem," KB") 
    print("\n",resource.getrusage(resource.RUSAGE_SELF))
    provenance_graph.clear()
    print("\n---Running Time : %s seconds ---" % (time.time() - start_time))
    print("\n*********************************************\n")
    return 
            
        
def main():
    
    provenance_graph_name = "attack_SysClient0201"
    provenance_graph_start = '2019-09-23'
    provenance_graph_end = '2019-09-26'
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)
    
    provenance_graph_name = "benign_SysClient0201"
    provenance_graph_start = '2019-09-16'
    provenance_graph_end = '2019-09-23'
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)
    
    
    provenance_graph_name = "attack_SysClient0051"
    provenance_graph_start = '2019-09-23'
    provenance_graph_end = '2019-09-26'
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)
    
    provenance_graph_name = "benign_SysClient0051"
    provenance_graph_start = '2019-09-16'
    provenance_graph_end = '2019-09-23'
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)
    
    
    provenance_graph_name = "attack_SysClient0358"
    provenance_graph_start = '2019-09-23'
    provenance_graph_end = '2019-09-26'
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)
    
    provenance_graph_name = "benign_SysClient0358"
    provenance_graph_start = '2019-09-16'
    provenance_graph_end = '2019-09-23'
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)
    
    
    provenance_graph_name = "attack_SysClient0501"
    provenance_graph_start = '2019-09-23'
    provenance_graph_end = '2019-09-26'
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)
    
    provenance_graph_name = "benign_SysClient0501"
    provenance_graph_start = '2019-09-16'
    provenance_graph_end = '2019-09-23'
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)
    
if __name__ == "__main__":
    main()
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
import os, psutil
process = psutil.Process(os.getpid())

def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

username = ""
password = ""
dataset = "darpa_theia"
db_url = 'postgresql+psycopg2://' + username + ':' + password + '@localhost/' + dataset

#DARPA timezone
timezone = pytz.timezone("America/Nipigon")
query_events_objects = """
SELECT "subject" as subject, "predicate_object" as object, "uuid" as event, "type" ,"time_stamp_nanos" as timestamp
FROM public."Event" 
WHERE time_stamp_nanos BETWEEN  %(start_timestamp)s AND %(end_timestamp)s
AND uuid IS NOT NULL AND "subject" IS NOT NULL
AND "predicate_object" IS NOt NULL AND "predicate_object" != '00000000-0000-0000-0000-000000000000'
AND "predicate_object" IN (
    SELECT DISTINCT uuid
    FROM public."Subject" 
    WHERE uuid IS NOT NULL AND "cmd_line" != 'N/A'
    GROUP BY 1
    UNION
    SELECT DISTINCT uuid
    FROM public."FileObject" 
    WHERE uuid IS NOT NULL
    UNION
    SELECT DISTINCT uuid 
    FROM public."NetflowObject" 
    WHERE uuid IS NOT NULL AND "remote_address" != 'NA'
    UNION
    SELECT DISTINCT uuid 
    FROM public."MemoryObject" 
    WHERE uuid IS NOT NULL 
)
UNION
SELECT "subject" as subject, "predicate_object_2" as object,"uuid" as event,"type" ,"time_stamp_nanos" as timestamp
FROM public."Event"
WHERE time_stamp_nanos BETWEEN  %(start_timestamp)s AND %(end_timestamp)s
AND uuid IS NOT NULL AND "subject" IS NOT NULL
AND "predicate_object_2" IS NOT NULL AND "predicate_object_2" != '00000000-0000-0000-0000-000000000000'
AND "predicate_object_2" IN (
    SELECT DISTINCT uuid
    FROM public."Subject" 
    WHERE uuid IS NOT NULL AND "cmd_line" != 'N/A'
    GROUP BY 1
    UNION
    SELECT DISTINCT uuid
    FROM public."FileObject" 
    WHERE uuid IS NOT NULL
    UNION
    SELECT DISTINCT uuid 
    FROM public."NetflowObject" 
    WHERE uuid IS NOT NULL AND "remote_address" != 'NA'
    UNION
    SELECT DISTINCT uuid  
    FROM public."MemoryObject" 
    WHERE uuid IS NOT NULL 
)
"""
query_subjects ="""
SELECT DISTINCT uuid as subject, 'PROCESS' as type ,STRING_AGG(DISTINCT regexp_replace(split_part("cmd_line",' ',1),'^.*/', ''),'=>') as command_lines
FROM public."Subject" 
WHERE uuid IS NOT NULL AND "cmd_line" != 'N/A'
GROUP BY 1,2;
"""
query_files = """
SELECT DISTINCT uuid as object, 'FILE' as type 
FROM public."FileObject" 
WHERE uuid IS NOT NULL 
"""

query_flows = """
SELECT DISTINCT uuid as object, 'FLOW' as type, remote_address as "remote_ip" ,  local_address as "local_ip" 
FROM public."NetflowObject" 
WHERE uuid IS NOT NULL AND "remote_address" != 'NA'
"""
query_memory = """
SELECT DISTINCT uuid as object, 'MEMORY' as type 
FROM public."MemoryObject" 
WHERE uuid IS NOT NULL 
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
    start_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print("Constructing:", provenance_graph_name)
    dt_start = datetime.fromtimestamp(provenance_graph_start // 1000000000,tz=timezone)
    print("The Provenance Graph Start on ",dt_start.strftime('%Y-%m-%d %H:%M:%S'))
    dt_end = datetime.fromtimestamp(provenance_graph_end // 1000000000,tz=timezone)
    print("The Provenance Graph Ends on ",dt_end.strftime('%Y-%m-%d %H:%M:%S'))
    print("The Provenance Graph duration is:",dt_end-dt_start)   
    #Get Events of the first objects
    df_events = pd.read_sql(query_events_objects,db_url,
                       params={"start_timestamp":provenance_graph_start,"end_timestamp":provenance_graph_end})
    df_events['type'] = [event.split("EVENT_")[1].lower() if event else None for event in df_events["type"]]
    print("Total Number of Events:",len(df_events))
    provenance_graph = nx.from_pandas_edgelist(
        df_events,
        source="subject",
        target="object",
        edge_attr=["event","type","timestamp"],
        create_using=nx.MultiDiGraph()
    )    
    print("Number of Nodes:",provenance_graph.number_of_nodes(),"\nNumber of Edges",provenance_graph.number_of_edges())
    df_events = None
    
    print("Set Subjects attributes")
    subjects = pd.read_sql(query_subjects,db_url)
    node_attr = subjects.set_index('subject').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    node_attr,subjects = None,None
    
    print("Set Objects attributes")
    
    object_files = pd.read_sql(query_files,db_url)
    node_attr = object_files.set_index('object').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    node_attr,object_files = None,None

    object_flows = pd.read_sql(query_flows,db_url)
    node_attr = object_flows.set_index('object').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    node_attr,object_flows = None,None
    

    object_memory = pd.read_sql(query_memory,db_url)
    node_attr = object_memory.set_index('object').to_dict('index')
    nx.set_node_attributes(provenance_graph, node_attr)
    node_attr,object_memory = None,None

    
    None_nodes = [node for node,node_type in provenance_graph.nodes.data("type") if node_type == None]
    print("Number of filtered None nodes",len(None_nodes))
    provenance_graph.remove_nodes_from(None_nodes)
    
    explore_graph(provenance_graph)
    print("Writing the graph to a file")
    json_provenance_graph = json_graph.node_link_data(provenance_graph)
    file_path = "./dataset/darpa_theia/provenance_graphs/" + provenance_graph_name + ".json"
    with open(file_path, 'w') as f:
        json.dump(json_provenance_graph, f)
    json_provenance_graph = None
    construct_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - start_mem
    print("\nMemory usage to constract the provenance graph: ", construct_mem / 1024,"MB (based on resource Lib)")
    print("\nMemory usage to constract the provenance graph: ",process.memory_info().rss / (1024 ** 2),"MB (based on psutil Lib)")
    provenance_graph.clear()
    print("/n---Running Time : %s seconds ---" % (time.time() - start_time))
    print("/n*********************************************/n")
    return 
            
def main():
    
    provenance_graph_name = "attack_Linux_1&2_provenance_graph"
    provenance_graph_start = 1523376000000000000
    provenance_graph_end = 1523653470865469444
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)

    provenance_graph_name = "benign_Linux_provenance_graph"
    provenance_graph_start = 1522728000000000000
    provenance_graph_end = 1523376000000000000
    build_graph(provenance_graph_name,provenance_graph_start,provenance_graph_end)
    

    
if __name__ == "__main__":
    main()
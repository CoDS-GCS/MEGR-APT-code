import time
import pickle
import torch
import pickle
import argparse
from ged import graph_edit_distance
import os
import dask.bag as db
import argparse
import glob
from dask.distributed import Client, LocalCluster
import dask
import multiprocessing
import gc
import ctypes


parser = argparse.ArgumentParser()
parser.add_argument('--root-path', nargs="?", help='Root path for the experiment',required=True)
# parser.add_argument('--n-workers', type=int, help='Number of Worker to Process GED', default=30)
args = parser.parse_args()
print(args)


def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

def release_memory(client):
    client.restart()
    client.run(gc.collect)
    client.run(trim_memory)
    time.sleep(5)

def main():
    cores = multiprocessing.cpu_count() - 4
    cluster = LocalCluster(n_workers=cores)
    client = Client(cluster)
    release_memory(client)
    start_running_time = time.time()
    training_file = args.root_path + r"/raw/dgl_training_dataset.pt"
    print(training_file)
    with open(training_file, 'rb') as f:
        training_dataset = torch.load(f)
    testing_file = args.root_path + r"/raw/dgl_testing_dataset.pt"
    with open(testing_file, 'rb') as f:
        testing_dataset = torch.load(f)
    print("Training Samples", len(training_dataset))
    print("Testing Samples", len(testing_dataset))
    graph_data = training_dataset + testing_dataset

    n_training = len(training_dataset)
    n_dataset = len(graph_data)
    
    uncomputedd = []

    def last_ged_distance_dask(i):
        start_time = time.time()
        g1 = graph_data[i]
        ged_matrix_temp = torch.full((len(graph_data), len(graph_data)), float('inf'))
        if i < n_training:
            for j in range(i, n_training):
                start_s_time = time.time()
                distance_beam,distance_bipartite,distance_hausdorff,distance = None,None,None,None
                g2 = graph_data[j]
                try:
                    distance_beam  = graph_edit_distance(g1, g2, algorithm='beam', max_beam_size=2)
                except: 
                    print("Error for beam algorithm: ",i,j)
                    #give arbitrary big value to avoid confusing calculation
                    distance_beam = 100000
                try:
                    distance_bipartite  = graph_edit_distance(g1, g2, algorithm='bipartite')
                except: 
                    print("Error for bipartite algorithm: ",i,j)
                    distance_bipartite = 100000
                try:    
                    distance_hausdorff  = graph_edit_distance(g1, g2, algorithm='hausdorff')
                except: 
                    print("Error for hausdorff algorithm: ",i,j)
                    distance_hausdorff = 100000
                
                distance = min(distance_beam, distance_bipartite, distance_hausdorff)
                if distance == 100000:
                    print("couldn't compute GED for:",i,j) 
                    uncomputedd.append((i,j))
                    distance = None
                    continue
                ged_matrix_temp[i, j] = distance
                ged_matrix_temp[j, i] = distance
                print("Done Training",i, j," in : %s seconds"% (time.time() - start_s_time))
                g2 = None
        else:
            for j in range(n_training):
                start_s_time = time.time()             
                g2 = graph_data[j]
                try:
                    distance_beam = graph_edit_distance(g1, g2, algorithm='beam', max_beam_size=2)
                except: 
                    print("Error for beam algorithm: ",i,j)
                    #give arbitrary big value to avoid confusing calculation
                    distance_beam = 100000
                try:
                    distance_bipartite = graph_edit_distance(g1, g2, algorithm='bipartite')
                except: 
                    print("Error for bipartite algorithm: ",i,j)
                    distance_bipartite = 100000
                try:    
                    distance_hausdorff = graph_edit_distance(g1, g2, algorithm='hausdorff')
                except: 
                    print("Error for hausdorff algorithm: ",i,j)
                    distance_hausdorff = 100000
                distance = min(distance_beam, distance_bipartite, distance_hausdorff)
                if distance == 100000:
                    distance = None
                    print("couldn't compute GED for:",i,j) 
                    uncomputedd.append((i,j))
                    continue
                ged_matrix_temp[i, j] = distance
                print("Done Testing",i, j," in : %s seconds"% (time.time() - start_s_time))
                g2 = None
                
        print("\nDone: ", i,"in %s seconds\n" % (time.time() - start_time))
        if ~torch.all(torch.isinf(ged_matrix_temp)):
            print("\Store: ", i)
            ged_file = args.root_path +"/ged_samples/ged_"+str(i)+".pt"
            ensure_dir(ged_file)
            torch.save(ged_matrix_temp,ged_file)
        ged_matrix_temp,g1 = None,None
        return 

    list_indices = list(range(len(graph_data)))
    
    done = []
    for ged_file in glob.glob((args.root_path +'/ged_samples/ged_*')):
        done.append(int(ged_file.split("_")[-1].replace(".pt","")))
    done.sort()
    print("Done: ", len(done))
    rest_indices = [x for x in list_indices if x not in done]

    graph_dask = db.from_sequence(rest_indices, npartitions=cores)
    graph_dask.map(lambda x: last_ged_distance_dask(x)).compute()  
    
    ged_matrix = torch.full((len(graph_data), len(graph_data)), float('inf'))
    for ged_file in glob.glob((args.root_path +'/ged_samples/ged_*')):
        temp_ged = torch.load(ged_file)
        ged_matrix[~torch.isinf(temp_ged)] = temp_ged[~torch.isinf(temp_ged)]
        temp_ged = None
    ged_matrix
    
    ged_file = args.root_path + "/raw/ged_matrix.pt"
    ensure_dir(ged_file)
    torch.save(ged_matrix,ged_file)
    print("Training smples: ",(~torch.isinf(ged_matrix[0:len(training_dataset)])).float().sum())
    print("Testing Samples: ", (~torch.isinf(ged_matrix[len(training_dataset):])).float().sum())

    print("Normalize GED matrix")
    normal_ged_matrix = torch.full((len(graph_data), len(graph_data)), float('inf'))
    for i in range(len(graph_data)):
        for j in range(len(graph_data)):
            normal_ged_matrix[i][j] = ged_matrix[i][j] / (0.5 * (graph_data[i].num_nodes() + graph_data[j].num_nodes()))
    ged_file = args.root_path + "/raw/nged_matrix.pt"
    ensure_dir(ged_file)
    torch.save(normal_ged_matrix,ged_file)
    
    print("\n Total Number of uncomputed paris: ",len(uncomputedd))
    uncomputedd_file = args.root_path + "/ged_samples/uncomputed_pairs.pt" 
    ensure_dir(uncomputedd_file)
    torch.save(uncomputedd,uncomputedd_file)
    print("\n---Total Running Time : %s seconds ---" % (time.time() - start_running_time))


if __name__ == "__main__":
    main()

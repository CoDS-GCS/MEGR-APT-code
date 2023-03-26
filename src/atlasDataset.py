import torch
import random
import numpy as np
import torch.nn.functional as F
from tqdm import tqdm, trange
from scipy.stats import spearmanr, kendalltau

from layers import AttentionModule, TensorNetworkModule, DiffPool
from utils import calculate_ranking_correlation, calculate_prec_at_k, gen_pairs, ensure_dir

from torch_geometric.nn import GCNConv, GINConv
from torch_geometric.data import DataLoader, Batch , Data
from torch_geometric.utils import to_dense_batch, to_dense_adj, degree
from torch_geometric.datasets import GEDDataset
from torch_geometric.transforms import OneHotDegree
from torch_geometric.data import InMemoryDataset

import matplotlib.pyplot as plt

class ATLASDataset(InMemoryDataset):
    num_features = 7
    num_relations = 14
    root_file = "/shared_mnt/GnnDeepHunter/"
    def __init__(self, root,train:bool=True,predict=False,query = False, transform=None, pre_transform=None, pre_filter=None):
        super().__init__(root, transform, pre_transform, pre_filter)  
        self.name = "ATLAS_Dataset"
        if query:
            path = self.processed_paths[3]
            self.data, self.slices = torch.load(path)  
        elif predict:
            path = self.processed_paths[4]
            self.data, self.slices = torch.load(path)  
        else:
            path = self.processed_paths[0] if train else self.processed_paths[1]
            self.data, self.slices = torch.load(path)
            self.norm_ged = torch.load(self.processed_paths[2])

    @property
    def raw_file_names(self):
        return ['torch_training_dataset.pt', 'torch_testing_dataset.pt']

    @property
    def processed_file_names(self):
        return ['torch_training_dataset.pt','torch_testing_dataset.pt','nged_matrix.pt','query_graphs_dataset.pt','predict_dataset.pt']

#     def process(self):
        # Read data into huge `Data` list.
#         data_path_training = self.raw_path[0]
#         data_path_training = root_file + "./dataset/atlas/simgnn/hot_encoding/rgcn_exp/torch_training_dataset.pt"
#         data_list = torch.load(data_path_training)
#         torch.save(self.collate(data_list), self.processed_paths[0])
#         data_path_testing = self.raw_path[1]
#         data_path_testing = root_file + "./dataset/atlas/simgnn/hot_encoding/rgcn_exp/torch_testing_dataset.pt"
#         data_list = torch.load(data_path_testing)
#         torch.save(self.collate(data_list), self.processed_paths[1])
#         nged_path = root_file + "./dataset/atlas/simgnn/hot_encoding/rgcn_exp/nged_matrix.pt"
#         nged_matrix = torch.load(nged_path)
#         torch.save(nged_matrix,self.processed_paths[2])
#         query_path = "./dataset/atlas/simgnn/hot_encoding/predict/exp2/query_graphs_dataset.pt"
#         query_list = torch.load(query_path)
#         try:
#             query_list = torch.load(self.processed_paths[3])
#             torch.save(self.collate(query_list),self.processed_paths[3])
#         except:
#             print("No stored prediction dataset")
# #         predict_path = "./dataset/atlas/simgnn/hot_encoding/predict/exp2/predict_dataset.pt"
# #         predict_list = torch.load(predict_path)
#         try:
#             predict_list = torch.load(self.processed_paths[4])
#             torch.save(self.collate(predict_list),self.processed_paths[4])
#         except:
#             print("No stored query graphs")

#         if self.pre_filter is not None:
#             data_list = [data for data in data_list if self.pre_filter(data)]

#         if self.pre_transform is not None:
#             data_list = [self.pre_transform(data) for data in data_list]
    
    def annotate(self,predict_dataset):
        torch.save(self.collate(predict_dataset),self.processed_paths[4])
    
    def process_predict_pairs(self,suspSubGraphs,benignSubGraphs,query_graphs):
        print("process prediction dataset")
        ids = 0 
        query_data_list = []
        for g in query_graphs:
            edge_index = torch.tensor([query_graphs[g].edges()[0].tolist(),query_graphs[g].edges()[1].tolist()])
            data = Data(edge_index=edge_index, i= g)
            data.num_nodes = query_graphs[g].number_of_nodes()
            data.nlabel = query_graphs[g].ndata['label']
            data.elabel = query_graphs[g].edata['edge_label']
#             data.x = query_graphs[g].ndata['label']
            query_data_list.append(data)
            ids += 1
        data_file = root_file + "./dataset/atlas/simgnn/hot_encoding/rgcn_exp/predict/query_graphs_dataset.pt"  
        ensure_dir(data_file)
        torch.save(query_data_list, data_file)
        torch.save(self.collate(query_data_list),self.processed_paths[3])
        
        print("process query graphs")
        predict_data_list = []
        ids = 0 
        for host in suspSubGraphs:
            host_id = 0
            for g in suspSubGraphs[host]:
                edge_index = torch.tensor([g.edges()[0].tolist(),g.edges()[1].tolist()])
                grapg_id = host + "_suspicious_" + str(host_id)
                data = Data(edge_index= edge_index, i= str(ids),name=grapg_id)
                data.num_nodes = g.number_of_nodes()
                data.nlabel = g.ndata['label']
                data.elabel = g.edata['edge_label']
#                 data.x = g.ndata['label']
                predict_data_list.append(data)
                ids += 1
                host_id +=1
        for host in benignSubGraphs:
            host_id = 0
            for g in benignSubGraphs[host]:
                edge_index = torch.tensor([g.edges()[0].tolist(),g.edges()[1].tolist()])
                grapg_id = host + "_benign_" + str(host_id)
                data = Data(edge_index= edge_index, i= str(ids), name=grapg_id)
                data.num_nodes = g.number_of_nodes()
                data.nlabel = g.ndata['label']
                data.elabel = g.edata['edge_label']
                predict_data_list.append(data)
                ids += 1
                host_id+=1
        data_file = root_file + "./dataset/atlas/simgnn/hot_encoding/rgcn_exp/predict/predict_dataset.pt"  
        ensure_dir(data_file)
        torch.save(predict_data_list, data_file)
        torch.save(self.collate(predict_data_list),self.processed_paths[4])
    
        return predict_data_list, query_data_list            
            
    def __repr__(self) -> str:
        return f'{self.name}({len(self)})'
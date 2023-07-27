import torch
import random
import numpy as np
import torch.nn.functional as F
from tqdm import tqdm, trange
from scipy.stats import spearmanr, kendalltau
import pickle 
import glob

from layers import AttentionModule, TensorNetworkModule, DiffPool
from utils import calculate_ranking_correlation, calculate_prec_at_k, gen_pairs, ensure_dir

from torch_geometric.nn import GCNConv, GINConv
from torch_geometric.data import DataLoader, Batch , Data
from torch_geometric.utils import to_dense_batch, to_dense_adj, degree
from torch_geometric.datasets import GEDDataset
from torch_geometric.transforms import OneHotDegree
from torch_geometric.data import InMemoryDataset
from parser import parameter_parser

import matplotlib.pyplot as plt

class DARPADataset(InMemoryDataset):
    args = parameter_parser()
    if args.dataset == "DARPA_OPTC":
        num_features = 4
        num_relations = 10
    elif args.dataset == "DARPA_CADETS":
        num_features = 4
        num_relations = 31
    elif args.dataset == "DARPA_THEIA":
        num_features = 4
        num_relations = 17
    elif args.dataset == "DARPA_TRACE":
        num_features = 4
        num_relations = 24
    def __init__(self, root,train:bool=True,predict=False,query = False,file_name=None):
        super().__init__(root)  
        self.name = "DARPA_Dataset"
        if query:
            path = self.processed_paths[3]
            self.data, self.slices = torch.load(path)  
        elif predict:
            file_path = self.root + "/processed/predict_dataset/" + file_name
            self.process()
            try:
                self.data, self.slices = torch.load(file_path) 
            except:
                self.process()            
        else:
            path = self.processed_paths[0] if train else self.processed_paths[1]
            self.data, self.slices = torch.load(path)
            self.norm_ged = torch.load(self.processed_paths[2])

    @property
    def raw_file_names(self):
        return ['torch_training_dataset.pt', 'torch_testing_dataset.pt']

    @property
    def processed_file_names(self):
        return ['torch_training_dataset.pt','torch_testing_dataset.pt','nged_matrix.pt','query_graphs_dataset.pt']


    def process(self):
        if self.args.predict:
            query_path = self.args.dataset_path + "raw/torch_query_dataset.pt"
            query_list = torch.load(query_path)
            torch.save(self.collate(query_list),self.processed_paths[3])

            predict_paths = self.args.dataset_path + "raw/torch_prediction/*"
            ensure_dir(self.root + "/processed/predict_dataset/")
            for predict_path in glob.glob(predict_paths):
                predict_list = torch.load(predict_path)
                save_path = self.root + "/processed/predict_dataset/" + predict_path.split("/")[-1]
                torch.save(self.collate(predict_list),save_path)
        else:    
            print("processing dataset from",self.args.dataset_path," path")        
            data_path_training = self.args.dataset_path + "raw/torch_training_dataset.pt"
            with open(data_path_training, 'rb') as f:
                data_list = torch.load(f)
            torch.save(self.collate(data_list), self.processed_paths[0])

            data_path_testing = self.args.dataset_path + "raw/torch_testing_dataset.pt"
            with open(data_path_testing, 'rb') as f:
                data_list = torch.load(f)
            torch.save(self.collate(data_list), self.processed_paths[1])

            nged_path = self.args.dataset_path + "raw/nged_matrix.pt"
            nged_matrix = torch.load(nged_path)
            torch.save(nged_matrix,self.processed_paths[2])
        
        
             
        
    def __repr__(self) -> str:
        return f'{self.name}({len(self)})'    
    

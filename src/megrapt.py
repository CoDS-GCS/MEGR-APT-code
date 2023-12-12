import torch
import random
import numpy as np
import pickle
import time
from resource import *
import torch.nn.functional as F
from tqdm import tqdm, trange
from scipy.stats import spearmanr, kendalltau
import glob
from sklearn import metrics
from layers import AttentionModule, TensorNetworkModule, DiffPool
from utils import calculate_ranking_correlation, calculate_prec_at_k, gen_pairs, ensure_dir, checkpoint, print_memory_cpu_usage
from darpaDataset import DARPADataset
from dataset_config import get_ground_cases

from torch_geometric.nn import GCNConv, GINConv , FastRGCNConv
from torch_geometric.data import DataLoader, Batch
from torch_geometric.utils import to_dense_batch, to_dense_adj, degree
from torch_geometric.datasets import GEDDataset
from torch_geometric.transforms import OneHotDegree
from torch_geometric.data import InMemoryDataset

import matplotlib.pyplot as plt
import psutil,os
process = psutil.Process(os.getpid())

class MEGRAPT(torch.nn.Module):
    """
    MEGRAPT:
    """

    def __init__(self, args, number_of_labels,number_of_edge_labels):
        """
        :param args: Arguments object.
        :param number_of_labels: Number of node labels.
        """

        super(MEGRAPT, self).__init__()
        self.args = args
        self.number_labels = number_of_labels
        self.number_edge_labels = number_of_edge_labels
        self.setup_layers()

    def calculate_bottleneck_features(self):
        """
        Deciding the shape of the bottleneck layer.
        """
        if self.args.histogram:
            self.feature_count = self.args.tensor_neurons + self.args.bins
        else:
            self.feature_count = self.args.tensor_neurons

    def setup_layers(self):
        """
        Creating the layers.
        """
        self.calculate_bottleneck_features()
        if self.args.gnn_operator == "gcn":
            if self.args.embedding_layers == 3: 
                self.convolution_1 = GCNConv(self.number_labels, self.args.filters_1)
                self.convolution_2 = GCNConv(self.args.filters_1, self.args.filters_2)
                self.convolution_3 = GCNConv(self.args.filters_2, self.args.filters_3)
            elif self.args.embedding_layers == 2:
                self.convolution_1 = GCNConv(self.number_labels, self.args.filters_2)
                self.convolution_2 = GCNConv(self.args.filters_2, self.args.filters_3)
            elif self.args.embedding_layers == 1:
                self.convolution_1 = GCNConv(self.number_labels, self.args.filters_3)
        elif self.args.gnn_operator == "rgcn":
            if self.args.embedding_layers == 3: 
                self.convolution_1 = FastRGCNConv(self.number_labels, self.args.filters_1,self.number_edge_labels)
                self.convolution_2 = FastRGCNConv(self.args.filters_1, self.args.filters_2,self.number_edge_labels) 
                self.convolution_3 = FastRGCNConv(self.args.filters_2, self.args.filters_3,self.number_edge_labels)
            elif self.args.embedding_layers == 2:
                self.convolution_1 = FastRGCNConv(self.number_labels, self.args.filters_2,self.number_edge_labels)
                self.convolution_2 = FastRGCNConv(self.args.filters_2, self.args.filters_3,self.number_edge_labels)
            elif self.args.embedding_layers == 1:
                self.convolution_1 = FastRGCNConv(self.number_labels, self.args.filters_3,self.number_edge_labels)         
        elif self.args.gnn_operator == "gin":
            nn1 = torch.nn.Sequential(
                torch.nn.Linear(self.number_labels, self.args.filters_1),
                torch.nn.ReLU(),
                torch.nn.Linear(self.args.filters_1, self.args.filters_1),
                torch.nn.BatchNorm1d(self.args.filters_1),
            )

            nn2 = torch.nn.Sequential(
                torch.nn.Linear(self.args.filters_1, self.args.filters_2),
                torch.nn.ReLU(),
                torch.nn.Linear(self.args.filters_2, self.args.filters_2),
                torch.nn.BatchNorm1d(self.args.filters_2),
            )

            nn3 = torch.nn.Sequential(
                torch.nn.Linear(self.args.filters_2, self.args.filters_3),
                torch.nn.ReLU(),
                torch.nn.Linear(self.args.filters_3, self.args.filters_3),
                torch.nn.BatchNorm1d(self.args.filters_3),
            )

            self.convolution_1 = GINConv(nn1, train_eps=True)
            self.convolution_2 = GINConv(nn2, train_eps=True)
            self.convolution_3 = GINConv(nn3, train_eps=True)
        else:
            raise NotImplementedError("Unknown GNN-Operator.")

        if self.args.diffpool:
            self.attention = DiffPool(self.args)
        else:
            self.attention = AttentionModule(self.args)

        self.tensor_network = TensorNetworkModule(self.args)
        self.fully_connected_first = torch.nn.Linear(
            self.feature_count, self.args.bottle_neck_neurons
        )
        self.scoring_layer = torch.nn.Linear(self.args.bottle_neck_neurons, 1)

    def calculate_histogram(
            self, abstract_features_1, abstract_features_2, batch_1, batch_2
    ):
        """
        Calculate histogram from similarity matrix.
        :param abstract_features_1: Feature matrix for target graphs.
        :param abstract_features_2: Feature matrix for source graphs.
        :param batch_1: Batch vector for source graphs, which assigns each node to a specific example
        :param batch_1: Batch vector for target graphs, which assigns each node to a specific example
        :return hist: Histsogram of similarity scores.
        """
        abstract_features_1, mask_1 = to_dense_batch(abstract_features_1, batch_1)
        abstract_features_2, mask_2 = to_dense_batch(abstract_features_2, batch_2)

        B1, N1, _ = abstract_features_1.size()
        B2, N2, _ = abstract_features_2.size()

        mask_1 = mask_1.view(B1, N1)
        mask_2 = mask_2.view(B2, N2)
        num_nodes = torch.max(mask_1.sum(dim=1), mask_2.sum(dim=1))

        scores = torch.matmul(
            abstract_features_1, abstract_features_2.permute([0, 2, 1])
        ).detach()

        hist_list = []
        for i, mat in enumerate(scores):
            mat = torch.sigmoid(mat[: num_nodes[i], : num_nodes[i]]).view(-1)
            hist = torch.histc(mat, bins=self.args.bins)
            hist = hist / torch.sum(hist)
            hist = hist.view(1, -1)
            hist_list.append(hist)

        return torch.stack(hist_list).view(-1, self.args.bins)

    def convolutional_pass(self, edge_index, features):
        """
        Making convolutional pass.
        :param edge_index: Edge indices.
        :param features: Feature matrix.
        :return features: Abstract feature matrix.
        """
        if self.args.embedding_layers == 3:
            features = self.convolution_1(features, edge_index)
            features = F.relu(features)
            features = F.dropout(features, p=self.args.dropout, training=self.training)
            features = self.convolution_2(features, edge_index)
            features = F.relu(features)
            features = F.dropout(features, p=self.args.dropout, training=self.training)
            features = self.convolution_3(features, edge_index)
        if self.args.embedding_layers == 2:
            features = self.convolution_1(features, edge_index)
            features = F.relu(features)
            features = F.dropout(features, p=self.args.dropout, training=self.training)
            features = self.convolution_2(features, edge_index)
        if self.args.embedding_layers == 1:
            features = self.convolution_1(features, edge_index)
        return features

    
    def relation_convolutional_pass(self, edge_index, features,edge_features):
        """
        Making convolutional pass with RGCN.
        :param edge_index: Edge indices.
        :param features: Feature matrix.
        :param edge_features: Edge Feature matrix.
        :return features: Abstract feature matrix.
        """
        if self.args.embedding_layers == 3:
            features = self.convolution_1(features, edge_index,edge_features)
            features = F.relu(features)
            features = F.dropout(features, p=self.args.dropout, training=self.training)
            features = self.convolution_2(features, edge_index,edge_features)
            features = F.relu(features)
            features = F.dropout(features, p=self.args.dropout, training=self.training)
            features = self.convolution_3(features, edge_index,edge_features)
        if self.args.embedding_layers == 2:
            features = self.convolution_1(features, edge_index,edge_features)
            features = F.relu(features)
            features = F.dropout(features, p=self.args.dropout, training=self.training)
            features = self.convolution_2(features, edge_index,edge_features)
        if self.args.embedding_layers == 1:
            features = self.convolution_1(features, edge_index,edge_features)
        return features

    

    def diffpool(self, abstract_features, edge_index, batch):
        """
        Making differentiable pooling.
        :param abstract_features: Node feature matrix.
        :param edge_index: Edge indices
        :param batch: Batch vector, which assigns each node to a specific example
        :return pooled_features: Graph feature matrix.
        """
        x, mask = to_dense_batch(abstract_features, batch)
        adj = to_dense_adj(edge_index, batch)
        return self.attention(x, adj, mask)

    def forward(self, data):
        """
        Forward pass with graphs.
        :param data: Data dictionary.
        :return score: Similarity score.
        """
        edge_index_1 = data["g1"].edge_index
        edge_index_2 = data["g2"].edge_index
        features_1 = data["g1"].nlabel
        features_2 = data["g2"].nlabel
        if self.args.gnn_operator == "rgcn":
            edge_features_1 = data["g1"].elabel
            edge_features_2 = data["g2"].elabel

        
        batch_1 = (
            data["g1"].batch
            if hasattr(data["g1"], "batch")
            else torch.tensor((), dtype=torch.long).new_zeros(data["g1"].num_nodes)
        )
        batch_2 = (
            data["g2"].batch
            if hasattr(data["g2"], "batch")
            else torch.tensor((), dtype=torch.long).new_zeros(data["g2"].num_nodes)
        )

        if self.args.gnn_operator == "rgcn":
            abstract_features_1 = self.relation_convolutional_pass(edge_index_1, features_1,edge_features_1)
            abstract_features_2 = self.relation_convolutional_pass(edge_index_2, features_2,edge_features_2)
        else:    
            abstract_features_1 = self.convolutional_pass(edge_index_1, features_1)
            abstract_features_2 = self.convolutional_pass(edge_index_2, features_2)
        
        if self.args.histogram:
            hist = self.calculate_histogram(
                abstract_features_1, abstract_features_2, batch_1, batch_2
            )

        if self.args.diffpool:
            pooled_features_1 = self.diffpool(
                abstract_features_1, edge_index_1, batch_1
            )
            pooled_features_2 = self.diffpool(
                abstract_features_2, edge_index_2, batch_2
            )
        else:
            pooled_features_1 = self.attention(abstract_features_1, batch_1)
            pooled_features_2 = self.attention(abstract_features_2, batch_2)
            
        scores = self.tensor_network(pooled_features_1, pooled_features_2)
        if self.args.histogram:
            scores = torch.cat((scores, hist), dim=1)

        scores = F.relu(self.fully_connected_first(scores))
        score = torch.sigmoid(self.scoring_layer(scores)).view(-1)
        return score


class MEGRAPTTrainer(object):
    """
    MEGRAPT model trainer.
    """

    def __init__(self, args):
        """
        :param args: Arguments object.
        """
        self.start_running_time = time.time()
        self.current_mem = getrusage(RUSAGE_SELF).ru_maxrss
        print_memory_cpu_usage("Initial memory usage")
        self.args = args
        if self.args.predict:
            self.root_file = self.args.dataset_path
            if args.dataset == "DARPA_OPTC":
                self.number_of_labels = 4
                self.number_of_edge_labels = 10
            elif args.dataset == "DARPA_CADETS":
                self.number_of_labels = 4
                self.number_of_edge_labels = 31
            elif args.dataset == "DARPA_THEIA":
                self.number_of_labels = 4
                self.number_of_edge_labels = 17
            elif args.dataset == "DARPA_TRACE":
                self.number_of_labels = 4
                self.number_of_edge_labels = 24
            print("Number of labels",self.number_of_labels) 
            print("Number of edge labels",self.number_of_edge_labels)                 
        else:
            self.process_dataset()
        self.mem_loading_dataset = getrusage(RUSAGE_SELF).ru_maxrss - self.current_mem
        print_memory_cpu_usage("Loading")
        self.setup_model()


    def setup_model(self):
        """
        Creating a MEGRAPT.
        """
        self.model = MEGRAPT(self.args, self.number_of_labels,self.number_of_edge_labels)

    def save(self):
        """
        Saving model.
        """
        torch.save(self.model.state_dict(), self.args.save)
        print(f"Model is saved under {self.args.save}.")

    def load(self):
        """
        Loading model.
        """
        self.model.load_state_dict(torch.load(self.args.load))
        print(f"Model is loaded from {self.args.load}.")

    def process_dataset(self):
        """
        Downloading and processing dataset.
        """
        print("\nPreparing dataset.\n")
        if self.args.dataset == "DARPA_OPTC" or self.args.dataset == "DARPA_CADETS" or self.args.dataset == "DARPA_THEIA" or self.args.dataset == "DARPA_TRACE":
            self.root_file = self.args.dataset_path
            self.training_graphs = DARPADataset(self.root_file, train=True)
            self.testing_graphs = DARPADataset(self.root_file, train=False)
            self.nged_matrix = self.training_graphs.norm_ged
            
            print("Training set:",len(self.training_graphs),"\nTesting set:",len(self.testing_graphs))
            print("Training samples: ",(~torch.isinf(self.nged_matrix[0:len(self.training_graphs)])).float().sum())
            print("Testing Samples: ", (~torch.isinf(self.nged_matrix[len(self.training_graphs):])).float().sum())   
        else:
            print("Undefined dataset")
    
        self.number_of_labels = self.training_graphs.num_features
        self.number_of_edge_labels = self.training_graphs.num_relations
        self.real_data_size = self.nged_matrix.size(0)
        print("Number of labels",self.number_of_labels) 
        print("Number of edge labels",self.number_of_edge_labels) 
        
        

    def create_batches(self):
        """
        Creating batches from the training graph list.
        :return batches: Zipped loaders as list.
        """
        if self.args.synth:
            synth_data_ind = random.sample(range(len(self.synth_data_1)), 100)

        source_loader = DataLoader(
            self.training_graphs.shuffle()
            + (
                [self.synth_data_1[i] for i in synth_data_ind]
                if self.args.synth
                else []
            ),
            batch_size=self.args.batch_size,
        )
        target_loader = DataLoader(
            self.training_graphs.shuffle()
            + (
                [self.synth_data_2[i] for i in synth_data_ind]
                if self.args.synth
                else []
            ),
            batch_size=self.args.batch_size,
        )

        return list(zip(source_loader, target_loader))

    def transform(self, data, predict=False):
        """
        Getting ged for graph pair and grouping with data into dictionary.
        :param data: Graph pair.
        :return new_data: Dictionary with data.
        """
        new_data = dict()

        new_data["g1"] = data[0]
        new_data["g2"] = data[1]
        if not predict:
            normalized_ged = self.nged_matrix[
                data[0]["i"].reshape(-1).tolist(), data[1]["i"].reshape(-1).tolist()
            ].tolist()

            new_data["target"] = (
                torch.from_numpy(np.exp([(-el) for el in normalized_ged])).view(-1).float()
            )
        return new_data

    def process_batch(self, data):
        """
        Forward pass with a data.
        :param data: Data that is essentially pair of batches, for source and target graphs.
        :return loss: Loss on the data.
        """
        self.optimizer.zero_grad()
        data = self.transform(data)
        target = data["target"]
        prediction = self.model(data)
        loss = F.mse_loss(prediction, target, reduction="sum")
        loss.backward()
        self.optimizer.step()
        return loss.item()

    def fit(self):
        """
        Training a model.
        """
        print("\nModel training.\n")
        self.optimizer = torch.optim.Adam(
            self.model.parameters(),
            lr=self.args.learning_rate,
            weight_decay=self.args.weight_decay,
        )
        self.model.train()
        self.mem_train = getrusage(RUSAGE_SELF).ru_maxrss - self.mem_loading_dataset - self.current_mem
        print_memory_cpu_usage("Training")
        epochs = trange(self.args.epochs, leave=True, desc="Epoch")
        loss_list = []
        loss_list_test = []
        for epoch in epochs:

            if self.args.plot:
                if epoch % 10 == 0:
                    self.model.train(False)
                    cnt_test = 20
                    cnt_train = 100
                    t = tqdm(
                        total=cnt_test * cnt_train,
                        position=2,
                        leave=False,
                        desc="Validation",
                    )
                    scores = torch.empty((cnt_test, cnt_train))

                    for i, g in enumerate(self.testing_graphs[:cnt_test].shuffle()):
                        source_batch = Batch.from_data_list([g] * cnt_train)
                        target_batch = Batch.from_data_list(
                            self.training_graphs[:cnt_train].shuffle()
                        )
                        data = self.transform((source_batch, target_batch))
                        target = data["target"]
                        prediction = self.model(data)

                        scores[i] = F.mse_loss(
                            prediction, target, reduction="none"
                        ).detach()
                        t.update(cnt_train)

                    t.close()
                    loss_list_test.append(scores.mean().item())
                    print("\nIn epoch",epoch,"Validation mse(10^-3): " + str(round(scores.mean().item() * 1000, 5)) + ".")
                    if loss_list:
                        print("Loss is:",round(loss_list[-1],5))
                    self.model.train(True)
                    

            batches = self.create_batches()
            main_index = 0
            loss_sum = 0
            for index, batch_pair in tqdm(
                    enumerate(batches), total=len(batches), desc="Batches", leave=False
            ):
                loss_score = self.process_batch(batch_pair)
                main_index = main_index + batch_pair[0].num_graphs
                loss_sum = loss_sum + loss_score
            loss = loss_sum / main_index
            epochs.set_description("Epoch (Loss=%g)" % round(loss, 5))
            loss_list.append(loss)

        if self.args.plot:
            plt.plot(loss_list, label="Train")
            plt.plot(
                [*range(0, self.args.epochs, 10)], loss_list_test, label="Validation"
            )
            plt.ylim([0, 0.1])
            plt.legend()
            filepath = self.args.dataset_path + "plots/"
            ensure_dir(filepath)
            filename = filepath + self.args.dataset
            filename += "_" + str(self.args.embedding_layers)
            filename += self.args.gnn_operator
            if self.args.diffpool:
                filename += "_diffpool"
            if self.args.histogram:
                filename += "_hist"
            filename += "_" + str(self.args.learning_rate)
            filename += "_" + str(self.args.dropout)
            filename += "_" + str(self.args.filters_1) + "-" + str(self.args.filters_2) + "-"+str(self.args.filters_3)
            filename += "_" + str(self.args.epochs) + ".pdf"
            plt.savefig(filename)

    def measure_time(self):
        import time

        self.model.eval()
        count = len(self.testing_graphs) * len(self.training_graphs)

        t = np.empty(count)
        i = 0
        tq = tqdm(total=count, desc="Graph pairs")
        for g1 in self.testing_graphs:
            for g2 in self.training_graphs:
                source_batch = Batch.from_data_list([g1])
                target_batch = Batch.from_data_list([g2])
                data = self.transform((source_batch, target_batch))

                start = time.process_time()
                self.model(data)
                t[i] = time.process_time() - start
                i += 1
                tq.update()
        tq.close()

        print(
            "Average time (ms): {}; Standard deviation: {}".format(
                round(t.mean() * 1000, 5), round(t.std() * 1000, 5)
            )
        )

    def predict(self):
        """
        predict similarity of predict dataset
        """
        print("\n\nsample prediction.\n")
        self.prediction_time = time.time()
        self.model.eval()
        if(self.args.predict_file):
            self.predict_graphs = DARPADataset(self.root_file,predict=True,file_name=self.args.predict_file)
            if self.predict_graphs[0]==None:
                raised_alarms = np.array([])
                print("No suspicious subgraphs from that case")
            else:
                print("Number of predict graphs", len(self.predict_graphs))
                query_graph_name = self.args.predict_file.split("_in_")[0]
                all_query_graphs = DARPADataset(self.root_file, query=True)
                if query_graph_name != "all":
                    self.query_graphs = [query for query in all_query_graphs if query.g_name == query_graph_name]
                print("Number of query graphs", len(self.query_graphs))
                similarity_matrix = np.empty((len(self.query_graphs) , len(self.predict_graphs)))
                for i, g in enumerate(self.query_graphs):
                    source_batch = Batch.from_data_list([g] * len(self.predict_graphs))
                    target_batch = Batch.from_data_list(self.predict_graphs)
                    data = self.transform((source_batch, target_batch), predict=True)
                    prediction = self.model(data)
                    similarity_matrix[i] = prediction.detach().numpy()
                if self.args.log_similarity:
                    checkpoint(similarity_matrix,(self.root_file+"predict/"+self.args.load.split("/")[-1].replace(".pt","") + "_similarity/similarity_matrix_"+self.args.predict_file))
                Highest_index = np.argmax(similarity_matrix)
                print("\nHighest similarity: ", round(np.amax(similarity_matrix),4))
                print("The highest similarity subgraph is: ",self.predict_graphs[Highest_index])
                raised_alarms = np.where(similarity_matrix > self.args.threshold)[1]

            if raised_alarms.size == 0:
                print("\nNone of subgraphs passed the threshold")
            else:
                print("Number of subgraphs passed the threshold:", raised_alarms.size)

        if(self.args.predict_folder):
            ground_cases, y_true = get_ground_cases(self.args.dataset,self.args.similar_attack)
            all_query_graphs = DARPADataset(self.root_file, query=True)
            self.tp,self.tn,self.fp,self.fn = 0,0,0,0
            self.max_score = []
            for self.predict_file in ground_cases:
                predict_file_time = time.time()
                print("\nProcessing :",self.predict_file)
                self.predict_graphs = DARPADataset(self.root_file,predict=True,file_name=self.predict_file)
                query_graph_name = self.predict_file.split("_in_")[0]
                all_query_graphs = DARPADataset(self.root_file, query=True)
                if query_graph_name != "all":
                    self.query_graphs = [query for query in all_query_graphs if query.g_name == query_graph_name]
                    self.predict_pairs()
                else:
                    temp_name = self.predict_file
                    for query_graph in all_query_graphs:
                        self.query_graphs = [query_graph]
                        self.predict_file = temp_name.replace("all",query_graph.g_name)
                        self.predict_pairs()
                print("\nProcessed :",self.predict_file,"in %s seconds ---" % (time.time() - predict_file_time))
                self.mem_match = getrusage(RUSAGE_SELF).ru_maxrss  - self.current_mem
                print_memory_cpu_usage("match the query graph")
                print("Memory usage to match the query graph: %s"% self.mem_match," KB")
                print("**************************************************************")
            self.print_predict_evaluation_metrics(y_true,self.max_score)
                
        print("\n---Total Prediction Time : %s seconds ---" % (time.time() - self.prediction_time))
        io_counters = process.io_counters()
        print("IOPS is : ", (io_counters[0] + io_counters[1]) / (time.time() - self.prediction_time))
        print("I/O counters", io_counters)


    def predict_pairs(self):
        if self.predict_graphs[0]==None:
            raised_alarms = np.array([])
            print("No suspicious subgraphs from that case")
            self.max_score.append(0)
        else:    
            print("Number of predict graphs", len(self.predict_graphs))
            print("Query graph:", self.query_graphs[0].g_name)
            similarity_matrix = np.empty((len(self.query_graphs) , len(self.predict_graphs)))
            for i, g in enumerate(self.query_graphs):
                source_batch = Batch.from_data_list([g] * len(self.predict_graphs))
                target_batch = Batch.from_data_list(self.predict_graphs)
                data = self.transform((source_batch, target_batch), predict=True)
                prediction = self.model(data)
                similarity_matrix[i] = prediction.detach().numpy()
            if self.args.log_similarity:    
                checkpoint(similarity_matrix,(self.root_file+"predict/"+self.args.load.split("/")[-1].replace(".pt","") + "_similarity/similarity_matrix_"+self.predict_file))
            Highest_index = np.argmax(similarity_matrix)
            print("\nHighest similarity: ", round(np.amax(similarity_matrix),4))
            self.max_score.append(round(np.amax(similarity_matrix),4))
            print("The highest similarity subgraph is: ",self.predict_graphs[Highest_index])

            raised_alarms = np.where(similarity_matrix > self.args.threshold)[1]
            if raised_alarms.size == 0:
                print("\nNone of subgraphs passed the threshold")
            else:
                print("Number of subgraphs passed the threshold:", raised_alarms.size)
        
        if raised_alarms.size == 0:
            if "attack" in self.predict_file:
                self.fn +=1
                print(self.predict_file," is false negative")
            elif "benign" in self.predict_file:
                self.tn +=1
                print(self.predict_file," is true negative")
        else:
            if "attack" in self.predict_file:
                self.tp +=1
                print(self.predict_file," is true positive")
            elif "benign" in self.predict_file:
                self.fp +=1
                print(self.predict_file," is false positive")
        return 
    
    def score(self):
        """
        Scoring.
        """
        print("\n\nModel evaluation.\n")
        self.validate_time = time.time()
        
        self.model.eval()    
        
        scores = np.empty((len(self.testing_graphs), len(self.training_graphs)))
        ground_truth = np.empty((len(self.testing_graphs), len(self.training_graphs)))
        prediction_mat = np.empty((len(self.testing_graphs), len(self.training_graphs)))
        
        rho_list = []
        tau_list = []
        prec_at_1_list = []
        prec_at_5_list = []
        prec_at_10_list = []
        prec_at_20_list = []

        t = tqdm(total= len(self.testing_graphs) * len(self.training_graphs))
        


        for i, g in enumerate(self.testing_graphs):
            source_batch = Batch.from_data_list([g] * len(self.training_graphs))
            target_batch = Batch.from_data_list(self.training_graphs)
            data = self.transform((source_batch, target_batch))
            target = data["target"]
            ground_truth[i] = target
            prediction = self.model(data)
            prediction_mat[i] = prediction.detach().numpy()

            scores[i] = (
                F.mse_loss(prediction, target, reduction="none").detach().numpy()
            )

            rho_list.append(
                calculate_ranking_correlation(
                    spearmanr, prediction_mat[i], ground_truth[i]
                )
            )
            tau_list.append(
                calculate_ranking_correlation(
                    kendalltau, prediction_mat[i], ground_truth[i]
                )
            )
            prec_at_1_list.append(
                calculate_prec_at_k(1, prediction_mat[i], ground_truth[i])
            )
            prec_at_5_list.append(
                calculate_prec_at_k(5, prediction_mat[i], ground_truth[i])
            )
            prec_at_10_list.append(
                calculate_prec_at_k(10, prediction_mat[i], ground_truth[i])
            )
            prec_at_20_list.append(
                calculate_prec_at_k(20, prediction_mat[i], ground_truth[i])
            )

            t.update(len(self.training_graphs))

        self.rho = np.mean(rho_list).item()
        self.tau = np.mean(tau_list).item()
        self.prec_at_1 = np.mean(prec_at_1_list).item()
        self.prec_at_5 = np.mean(prec_at_5_list).item()
        self.prec_at_10 = np.mean(prec_at_10_list).item()
        self.prec_at_20 = np.mean(prec_at_20_list).item()
        self.model_error = np.mean(scores).item()
        self.mem_evaluate = getrusage(RUSAGE_SELF).ru_maxrss - self.mem_loading_dataset - self.current_mem
        print_memory_cpu_usage("Evaluation")
        self.print_evaluation()
        
        
    def print_evaluation(self):
        """
        Printing the error rates.
        """
        print("\nmse(10^-3): " + str(round(self.model_error * 1000, 5)) + ".")
        print("Spearman's rho: " + str(round(self.rho, 5)) + ".")
        print("Kendall's tau: " + str(round(self.tau, 5)) + ".")
        print("p@1: " + str(round(self.prec_at_1, 5)) + ".")
        print("p@5: " + str(round(self.prec_at_5, 5)) + ".")
        print("p@10: " + str(round(self.prec_at_10, 5)) + ".")
        print("p@20: " + str(round(self.prec_at_20, 5)) + ".")
        
        print("\n---Total Running Time : %s seconds ---" % (time.time() - self.start_running_time))
        io_counters = process.io_counters()
        print("IOPS is : ", (io_counters[0] + io_counters[1]) / (time.time() - self.start_running_time))
        print("I/O counters",io_counters)
        print("\n---Validating Time : %s seconds ---" % (time.time() - self.validate_time))
        print("Memory usage to load data: %s"% self.mem_loading_dataset," KB") 
        print("Memory usage to train the model: %s"% self.mem_train," KB") 
        print("Memory usage to evaluate the model: %s"% self.mem_evaluate," KB") 
        print("\n",getrusage(RUSAGE_SELF))
        print_memory_cpu_usage("Final memory usage")
    
    
    def print_predict_evaluation_metrics(self,y_true,max_score):
        if (self.tp + self.fp) == 0:
            precision = None
        else:
            precision = self.tp / (self.tp + self.fp)
        if (self.tp + self.fn) == 0:
            recall = None
            tpr = None
        else:
            recall = self.tp / (self.tp + self.fn)
            tpr = self.tp / (self.tp + self.fn)
        accuracy = (self.tp + self.tn) / (self.tp + self.tn + self.fp + self.fn)
        if not precision or not recall or (precision + recall) == 0:
            f_measure = None
        else:
            f_measure = 2 * (precision * recall) / (precision + recall)
        if (self.fp + self.tn) == 0:
            fpr = None
        else:
            fpr = self.fp / (self.fp + self.tn)
        fpr_lst, tpr_lst, _ = metrics.roc_curve(y_true, max_score)
        auc = metrics.auc(fpr_lst, tpr_lst)
        print("\n************************************************************")
        print("\nThreshold is:",self.args.threshold)
        print("TP: {}\tTN: {}\tFP: {}\tFN: {}".format(self.tp, self.tn, self.fp, self.fn))
        print("Accuracy: {}\tPrecision: {}\tRecall: {}\tF-1: {}".format(accuracy, precision, recall, f_measure))
        print("TPR: {}\tFPR: {}\tAUC: {}".format(tpr, fpr, auc))
        print("************************************************************\n")   

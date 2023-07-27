"""SimGNN class and runner."""
import time
import glob
import torch
import random
import numpy as np
from tqdm import tqdm, trange
from torch_geometric.nn import GCNConv
from layers import AttentionModule, TenorNetworkModule
from utils import process_pair, calculate_loss
import json
import pickle
import datetime
import math
from dataset_config import get_ground_cases

class SimGNN(torch.nn.Module):
    """
    SimGNN: A Neural Network Approach to Fast Graph Similarity Computation
    https://arxiv.org/abs/1808.05689
    """

    def __init__(self, args, number_of_labels):
        """
        :param args: Arguments object.
        :param number_of_labels: Number of node labels.
        """
        super(SimGNN, self).__init__()
        self.args = args
        self.number_labels = number_of_labels
        self.setup_layers()

    def calculate_bottleneck_features(self):
        """
        Deciding the shape of the bottleneck layer.
        """
        self.feature_count = self.args.tensor_neurons

    def setup_layers(self):
        """
        Creating the layers.
        """
        self.calculate_bottleneck_features()
        # node-level embedding For Query Graph

        if self.args.one_gcn_pass:
            self.convolution_onepass = GCNConv(self.number_labels, self.args.filters_3)
        elif self.args.two_gcn_pass:
            self.convolution_twopass_1 = GCNConv(self.number_labels, self.args.filters_2)
            self.convolution_twopass_2 = GCNConv(self.args.filters_2, self.args.filters_3)
        else:
            self.convolution_1 = GCNConv(self.number_labels, self.args.filters_1)
            self.convolution_2 = GCNConv(self.args.filters_1, self.args.filters_2)
            self.convolution_3 = GCNConv(self.args.filters_2, self.args.filters_3)

        # graph-level embedding
        self.attention = AttentionModule(self.args)

        # GNN-based Architecture
        self.tensor_network = TenorNetworkModule(self.args)
        self.fully_connected_first = torch.nn.Linear(self.feature_count,
                                                     self.args.bottle_neck_neurons)

        self.scoring_layer = torch.nn.Linear(self.args.bottle_neck_neurons, 1)

    def convolutional_pass(self, edge_index, features):
        """
        Making convolutional pass.
        :param edge_index: Edge indices.
        :param features: Feature matrix.
        :return features: Absstract feature matrix.
        """
        if self.args.one_gcn_pass:
            features = self.convolution_onepass(features, edge_index)
        elif self.args.two_gcn_pass:
            features = self.convolution_twopass_1(features, edge_index)
            features = torch.nn.functional.relu(features)
            features = torch.nn.functional.dropout(features,
                                                   p=self.args.dropout,
                                                   training=self.training)
            features = self.convolution_twopass_2(features, edge_index)
        else:
            features = self.convolution_1(features, edge_index)
            features = torch.nn.functional.relu(features)
            features = torch.nn.functional.dropout(features,
                                                   p=self.args.dropout,
                                                   training=self.training)

            features = self.convolution_2(features, edge_index)
            features = torch.nn.functional.relu(features)
            features = torch.nn.functional.dropout(features,
                                                   p=self.args.dropout,
                                                   training=self.training)

            features = self.convolution_3(features, edge_index)

        return features

    def forward(self, data):
        """
        Forward pass with graphs.
        :param data: Data dictiyonary.
        :return score: Similarity score.
        """
        edge_index_1 = data["edge_index_1"]
        edge_index_2 = data["edge_index_2"]
        features_1 = data["features_1"]
        features_2 = data["features_2"]

        abstract_features_1 = self.convolutional_pass(edge_index_1, features_1)
        abstract_features_2 = self.convolutional_pass(edge_index_2, features_2)

        if self.args.with_attrs:
            attribute_1 = data['attrsEmbedding_1']
            attribute_2 = data['attrsEmbedding_2']
            aggregated_embedding_1 = torch.add(abstract_features_1, attribute_1)
            aggregated_embedding_2 = torch.add(abstract_features_2, attribute_2)
            pooled_features_1 = self.attention(aggregated_embedding_1)
            pooled_features_2 = self.attention(aggregated_embedding_2)

        elif self.args.only_attrs:
            attribute_1 = data['attrsEmbedding_1']
            attribute_2 = data['attrsEmbedding_2']
            pooled_features_1 = self.attention(attribute_1)
            pooled_features_2 = self.attention(attribute_2)
        else:
            pooled_features_1 = self.attention(abstract_features_1)
            pooled_features_2 = self.attention(abstract_features_2)

        scores = self.tensor_network(pooled_features_1, pooled_features_2)
        scores = torch.t(scores)

        scores = torch.nn.functional.relu(self.fully_connected_first(scores))
        score = torch.sigmoid(self.scoring_layer(scores))
        return score


class SimGNNTrainer_attrs(object):
    """
    SimGNN model trainer.
    """

    def __init__(self, args):
        """
        :param args: Arguments object.
        """
        self.args = args
        self.initial_label_enumeration()
        self.setup_model()

    def setup_model(self):
        """
        Creating a SimGNN.
        """
        self.model = SimGNN(self.args, self.number_of_labels)

    def initial_label_enumeration(self):
        """
        Collecting the unique node identifiers.
        """
        print("\nEnumerating unique labels.\n")

        if self.args.predict_case_path:
            self.predict_graphs = glob.glob(self.args.predict_case_path + "*.json")
            graph_pairs = self.predict_graphs
        else:
            self.training_graphs = glob.glob(self.args.training_graphs + "*.json")
            self.testing_graphs = glob.glob(self.args.testing_graphs + "*.json")
            graph_pairs = self.training_graphs + self.testing_graphs
        self.global_labels = set()
        for graph_pair in tqdm(graph_pairs):
            data = process_pair(graph_pair)
            self.global_labels = self.global_labels.union(set(data["labels_1"]))
            self.global_labels = self.global_labels.union(set(data["labels_2"]))
        # self.global_labels = list(range(self.args.number_of_labels))
        self.global_labels = sorted(self.global_labels)
        self.global_labels = {val: index for index, val in enumerate(self.global_labels)}
        self.number_of_labels = len(self.global_labels)
        # if self.args.dataset == "darpa_optc":
        #     self.number_of_labels = 4
        #     self.number_of_edge_labels = 10
        # elif self.args.dataset == "darpa_cadets":
        #     self.number_of_labels = 3
        #     self.number_of_edge_labels = 31
        # elif self.args.dataset == "darpa_theia":
        #     self.number_of_labels = 3
        #     self.number_of_edge_labels = 17
        # elif self.args.dataset == "darpa_trace":
        #     self.number_of_labels = 3
        #     self.number_of_edge_labels = 24
        # else:
        #     print("Undefined dataset")

    def create_batches(self):
        """
        Creating batches from the training graph list.
        :return batches: List of lists with batches.
        """
        random.shuffle(self.training_graphs)
        batches = []
        for graph in range(0, len(self.training_graphs), self.args.batch_size):
            batches.append(self.training_graphs[graph:graph + self.args.batch_size])
        return batches

    def transfer_to_torch(self, data, predict=False):
        """
        Transferring the data to torch and creating a hash table.
        Including the indices, features and target.
        :param data: Data dictionary.
        :return new_data: Dictionary of Torch Tensors.
        """
        new_data = dict()

        edges_1 = data["graph_1"]
        edges_2 = data["graph_2"]

        if len(edges_1) == 0:
            print("Not enough graph edges")
            return 0
        if len(edges_2) == 0:
            print("Not enough graph edges")
            return 0

        edges_1 = torch.from_numpy(np.array(edges_1, dtype=np.int64).T).type(torch.long)
        edges_2 = torch.from_numpy(np.array(edges_2, dtype=np.int64).T).type(torch.long)

        # Fill nan attrs with zeros
        attribute_1 = torch.from_numpy(np.nan_to_num(np.array(data['attrsEmbedding_1'], dtype=np.float32)))
        attribute_2 = torch.from_numpy(np.nan_to_num(np.array(data['attrsEmbedding_2'], dtype=np.float32)))

        features_1, features_2 = [], []

        for n in data["labels_1"]:
            features_1.append([1.0 if self.global_labels[n] == i else 0.0 for i in self.global_labels.values()])

        for n in data["labels_2"]:
            features_2.append([1.0 if self.global_labels[n] == i else 0.0 for i in self.global_labels.values()])

        features_1 = torch.FloatTensor(np.array(features_1))
        features_2 = torch.FloatTensor(np.array(features_2))

        new_data["edge_index_1"] = edges_1
        new_data["edge_index_2"] = edges_2

        new_data["features_1"] = features_1
        new_data["features_2"] = features_2

        new_data['attrsEmbedding_1'] = attribute_1
        new_data['attrsEmbedding_2'] = attribute_2

        if not predict:
            target = data["target"]
            new_data["target"] = torch.from_numpy(np.array(target).reshape(1, 1)).view(-1).float()
            # new_data["target"] = torch.from_numpy(np.exp(-target).reshape(1, 1)).view(-1).float()

        return new_data

    def process_batch(self, batch):
        """
        Forward pass with a batch of data.
        :param batch: Batch of graph pair locations.
        :return loss: Loss on the batch.
        """
        self.optimizer.zero_grad()
        losses = 0
        for graph_pair in batch:
            data = process_pair(graph_pair)
            data = self.transfer_to_torch(data)
            if data == 0:
                continue
            target = data["target"]
            prediction = self.model(data)
            losses = losses + torch.nn.functional.mse_loss(target, prediction.view(-1))
        losses.backward(retain_graph=True)
        self.optimizer.step()
        loss = losses.item()
        return loss

    def fit(self):
        """
        Fitting a model.
        """
        print("\nModel training.\n")

        self.optimizer = torch.optim.Adam(self.model.parameters(),
                                          lr=self.args.learning_rate,
                                          weight_decay=self.args.weight_decay)

        self.model.train()
        epochs = trange(self.args.epochs, leave=True, desc="Epoch")
        for epoch in epochs:
            batches = self.create_batches()
            self.loss_sum = 0
            main_index = 0
            for index, batch in tqdm(enumerate(batches), total=len(batches), desc="Batches"):
                loss_score = self.process_batch(batch)
                main_index = main_index + len(batch)
                self.loss_sum = self.loss_sum + loss_score * len(batch)
                loss = self.loss_sum / main_index
                epochs.set_description("Epoch (Loss=%g)" % round(loss, 5))

    def score(self):
        """
        Scoring on the test set.
        """
        print("\n\nModel evaluation.\n")
        self.model.eval()
        self.scores = []
        self.ground_truth = []
        for graph_pair in tqdm(self.testing_graphs):
            data = process_pair(graph_pair)
            self.ground_truth.append(data["target"])
            title = data['title']
            data = self.transfer_to_torch(data)
            if data == 0:
                continue
            target = data["target"]
            prediction = self.model(data)
            self.scores.append(calculate_loss(prediction, target))
        self.print_evaluation()

    def predict(self):
        """
        predict similarity of predict dataset
        """
        print("\n\nsample prediction.\n")
        self.prediction_time = time.time()
        self.model.eval()
        if (self.args.predict_case_path):
            if not self.predict_graphs:
                raised_alarms = np.array([])
                print("No suspicious subgraphs from that case")
            elif self.predict_graphs[0] == None:
                raised_alarms = np.array([])
                print("No suspicious subgraphs from that case")
            else:
                print("Number of predict graphs", len(self.predict_graphs))
                similarity_matrix = np.empty((1, len(self.predict_graphs)))
                for i,graph_pair in tqdm(enumerate(self.predict_graphs)):
                    data = process_pair(graph_pair)
                    case_name = self.args.predict_case_path.split("/")[-1]
                    data = self.transfer_to_torch(data, predict=True)
                    if data == 0:
                        continue
                    prediction = self.model(data)
                    similarity_matrix[0][i] = prediction.tolist()[0][0]
                if self.args.log_similarity:
                    checkpoint(similarity_matrix, (
                                self.root_file + "predict/" + self.args.load.split("/")[-1].replace(".pt",
                                                                                                    "") + "_similarity/similarity_matrix_" + case_name))
                Highest_index = np.argmax(similarity_matrix)
                print("\nHighest similarity: ",np.amax(similarity_matrix))
                print("The highest similarity subgraph is: ", self.predict_graphs[Highest_index])
                raised_alarms = np.where(similarity_matrix > self.args.threshold)[1]
            if raised_alarms.size == 0:
                print("\nNone of subgraphs passed the threshold")
            else:
                print("Number of subgraphs passed the threshold:", raised_alarms.size)
            print("standard deviation of report predictions is ", format(np.nanstd(similarity_matrix), '.4f'))
            print("Mean of report predictions is ", format(np.nanmean(similarity_matrix), '.4f'))

        elif (self.args.predict_folder_path):
            ground_cases = get_ground_cases(self.args.dataset)
            self.tp, self.tn, self.fp, self.fn = 0, 0, 0, 0
            for case_name in ground_cases:
                predict_file_time = time.time()
                case_name = case_name.replace(".pt","")
                print("\nProcessing :", case_name)
                self.predict_graphs = glob.glob(self.args.predict_folder_path + case_name + "/*.json")
                self.predict_pairs(case_name)
                print("\nProcessed :", case_name, "in %s seconds ---" % (time.time() - predict_file_time))
                print("**************************************************************")
            self.print_predict_evaluation_metrics()

        print("\n---Total Prediction Time : %s seconds ---" % (time.time() - self.prediction_time))

    def predict_pairs(self,case_name):
        if not self.predict_graphs:
            raised_alarms = np.array([])
            print("No suspicious subgraphs from that case")
        elif self.predict_graphs[0] == None:
            raised_alarms = np.array([])
            print("No suspicious subgraphs from that case")
        else:
            print("Number of predict graphs", len(self.predict_graphs))
            self.global_labels = set()
            for graph_pair in tqdm(self.predict_graphs):
                data = process_pair(graph_pair)
                self.global_labels = self.global_labels.union(set(data["labels_1"]))
                self.global_labels = self.global_labels.union(set(data["labels_2"]))
            self.global_labels = sorted(self.global_labels)
            self.global_labels = {val: index for index, val in enumerate(self.global_labels)}
            self.number_of_labels = len(self.global_labels)
            similarity_matrix = np.empty((1, len(self.predict_graphs)))
            for i,graph_pair in tqdm(enumerate(self.predict_graphs)):
                data = process_pair(graph_pair)
                case_name = data['title'].split("/")[0]
                data = self.transfer_to_torch(data, predict=True)
                if data == 0:
                    continue
                prediction = self.model(data)
                similarity_matrix[0][i] = prediction.tolist()[0][0]
            if self.args.log_similarity:
                checkpoint(similarity_matrix, (
                            self.root_file + "predict/" + self.args.load.split("/")[-1].replace(".pt","") + "_similarity/similarity_matrix_" + case_name))
            Highest_index = np.argmax(similarity_matrix)
            print("\nHighest similarity: ", np.amax(similarity_matrix))
            print("The highest similarity subgraph is: ", self.predict_graphs[Highest_index])
            raised_alarms = np.where(similarity_matrix > self.args.threshold)[1]
            if raised_alarms.size == 0:
                print("\nNone of subgraphs passed the threshold")
            else:
                print("Number of subgraphs passed the threshold:", raised_alarms.size)
            print("standard deviation of report predictions is ", format(np.nanstd(similarity_matrix), '.4f'))
            print("Mean of report predictions is ", format(np.nanmean(similarity_matrix),'.4f'))

        if raised_alarms.size == 0:
            if "attack" in case_name:
                self.fn += 1
                print(case_name, " is false negative")
            elif "benign" in case_name:
                self.tn += 1
                print(case_name, " is true negative")
        else:
            if "attack" in case_name:
                self.tp += 1
                print(case_name, " is true positive")
            elif "benign" in case_name:
                self.fp += 1
                print(case_name, " is false positive")
        return

    def print_predict_evaluation_metrics(self):
        if (self.tp + self.fp) == 0:
            precision = None
        else:
            precision = self.tp / (self.tp + self.fp)
        if (self.tp + self.fn) == 0:
            recall = None
        else:
            recall = self.tp / (self.tp + self.fn)
        accuracy = (self.tp + self.tn) / (self.tp + self.tn + self.fp + self.fn)
        if not precision or not recall or (precision + recall) == 0:
            f_measure = None
        else:
            f_measure = 2 * (precision * recall) / (precision + recall)
        print("\n************************************************************")
        print("\nThreshold is:", self.args.threshold)
        print("TP: {}\tTN: {}\tFP: {}\tFN: {}".format(self.tp, self.tn, self.fp, self.fn))
        print("Accuracy: {}\tPrecision: {}\tRecall: {}\tF-1: {}".format(accuracy, precision, recall, f_measure))

        print("************************************************************\n")

    def print_evaluation(self):
        """
        Printing the error rates.
        """
        model_error = np.nanmean(self.scores)
        print("\nModel test error: " + str(round(model_error, 5)))
        print("number of Attrs nan samples is:", np.isnan(self.scores).sum())

    def save(self):
        torch.save(self.model.state_dict(), self.args.save_path)

    def load(self):
        self.model.load_state_dict(torch.load(self.args.load_path))

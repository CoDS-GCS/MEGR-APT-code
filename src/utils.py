import math
import numpy as np
import networkx as nx
import torch
import random
from texttable import Texttable
from torch_geometric.utils import erdos_renyi_graph, to_undirected, to_networkx
from torch_geometric.data import Data
import matplotlib.pyplot as plt
import os,psutil
from resource import *
process = psutil.Process(os.getpid())

def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
    return
def checkpoint(data, file_path):
    ensure_dir(file_path)
    torch.save(data,file_path)
    return
    
def tab_printer(args):
    """
    Function to print the logs in a nice tabular format.
    :param args: Parameters used for the model.
    """
    args = vars(args)
    keys = sorted(args.keys())
    t = Texttable()
    t.add_rows(
        [["Parameter", "Value"]]
        + [[k.replace("_", " ").capitalize(), args[k]] for k in keys]
    )
    print(t.draw())

def print_memory_cpu_usage(message=None):
    print(message)
    print("Memory usage (ru_maxrss) : ",getrusage(RUSAGE_SELF).ru_maxrss/1024," MB")
    print("Memory usage (psutil) : ", psutil.Process(os.getpid()).memory_info().rss / (1024 ** 2), "MB")
    print('The CPU usage is (per process): ', psutil.Process(os.getpid()).cpu_percent(4))
    load1, load5, load15 = psutil.getloadavg()
    cpu_usage = (load15 / os.cpu_count()) * 100
    print("The CPU usage is : ", cpu_usage)
    print('used virtual memory GB:', psutil.virtual_memory().used / (1024.0 ** 3), " percent",
          psutil.virtual_memory().percent)
    return
def draw_metrics_over_threshold(args):
    if args.dataset == "DARPA_OPTC":
        predict_cases = ["Malicious_Upgrade_in_attack_SysClient0051.pt",
                         "Custom_PowerShell_Empire_in_attack_SysClient0358.pt",
                         "Custom_PowerShell_Empire_in_attack_SysClient0501.pt",
                         "Plain_PowerShell_Empire_in_attack_SysClient0201.pt",
                         "Custom_PowerShell_Empire_in_benign_SysClient0358.pt",
                         "Malicious_Upgrade_in_benign_SysClient0358.pt",
                         "Plain_PowerShell_Empire_in_benign_SysClient0358.pt",
                         "Custom_PowerShell_Empire_in_benign_SysClient0051.pt",
                         "Malicious_Upgrade_in_benign_SysClient0201.pt", "Malicious_Upgrade_in_benign_SysClient0051.pt",
                         "Plain_PowerShell_Empire_in_benign_SysClient0501.pt",
                         "Plain_PowerShell_Empire_in_benign_SysClient0051.pt",
                         "Plain_PowerShell_Empire_in_benign_SysClient0201.pt",
                         "Malicious_Upgrade_in_benign_SysClient0501.pt",
                         "Custom_PowerShell_Empire_in_benign_SysClient0501.pt",
                         "Custom_PowerShell_Empire_in_benign_SysClient0201.pt"]
    #               "Custom_PowerShell_Empire_in_attack_SysClient0358_provenance_graph.pt" is challenging
    elif args.dataset == "DARPA_CADETS":
        predict_cases = ["BSD_4_in_benign_BSD.pt", "BSD_3_in_benign_BSD.pt", "BSD_4_in_attack_BSD_3_4.pt",
                         "BSD_3_in_attack_BSD_3_4.pt", "BSD_2_in_attack_BSD_2.pt", "BSD_1_in_attack_BSD_1.pt",
                         "BSD_1_in_benign_BSD.pt", "BSD_2_in_benign_BSD.pt"]
    elif args.dataset == "DARPA_THEIA":
        predict_cases = ["Linux_1_in_attack_linux_1_2.pt", "Linux_2_in_attack_linux_1_2.pt",
                         "Linux_1_in_benign_theia.pt", "Linux_2_in_benign_theia.pt"]
    elif args.dataset == "DARPA_TRACE":
        predict_cases = ["Linux_3_in_benign_trace.pt", "Linux_4_in_benign_trace.pt", "Linux_4_in_attack_linux_4.pt",
                         "Linux_3_in_attack_linux_3.pt"]  
    thresholds = [0,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1]
    accuracy_list,precision_list,recall_list,f_measure_list = [],[],[],[]
    for th in thresholds: 
        tp,tn,fp,fn = 0,0,0,0
        accuracy,precision,recall,f_measure=0,0,0,0
        for case in predict_cases: 
            full_path = args.dataset_path +"predict/"+args.load.split("/")[-1].replace(".pt","") + "_similarity/similarity_matrix_"+ case
            try:
                similarity_matrix = torch.load(full_path)
                raised_alarms = np.where(similarity_matrix > th)[1]
            except:
                raised_alarms = np.empty(0)
            if raised_alarms.size == 0:
                if "attack" in case:
                    fn +=1
                elif "benign" in case:
                    tn +=1
            else:
                if "attack" in case:
                    tp +=1
                elif "benign" in case:
                    fp +=1            
        if (tp + fp) == 0:
            precision = None
        else:
            precision = tp / (tp + fp)
        if (tp + fn) == 0:
            recall = None
        else:
            recall = tp / (tp + fn)
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        if not precision or not recall or (precision + recall) == 0:
            f_measure = None
        else:
            f_measure = 2 * (precision * recall) / (precision + recall)
        accuracy_list.append(accuracy)    
        precision_list.append(precision)
        recall_list.append(recall)
        f_measure_list.append(f_measure)
    plt.plot(thresholds,accuracy_list, label="Accuracy")
    plt.plot(thresholds,precision_list, label="Precision")
    plt.plot(thresholds,recall_list, label="Recall")
    plt.plot(thresholds,f_measure_list, label="F-Measure")
    plt.legend()
    file_path = args.dataset_path + "plots/"
    ensure_dir(file_path)
    filename = file_path + "Thresholds_" + args.load.split("/")[-1].replace(".pt","")+ ".pdf"
    plt.savefig(filename)
    print("The Figured drawed in",filename)

    
def calculate_ranking_correlation(rank_corr_function, prediction, target):
    """
    Calculating specific ranking correlation for predicted values.
    :param rank_corr_function: Ranking correlation function.
    :param prediction: Vector of predicted values.
    :param target: Vector of ground-truth values.
    :return ranking: Ranking correlation value.
    """
    temp = prediction.argsort()
    r_prediction = np.empty_like(temp)
    r_prediction[temp] = np.arange(len(prediction))

    temp = target.argsort()
    r_target = np.empty_like(temp)
    r_target[temp] = np.arange(len(target))

    return rank_corr_function(r_prediction, r_target).correlation


def calculate_prec_at_k(k, prediction, target):
    """
    Calculating precision at k.
    """

    # increase k in case same similarity score values of k-th, (k+i)-th elements
    target_increase = np.sort(target)[::-1]
    target_value_sel = (target_increase >= target_increase[k - 1]).sum()
    target_k = max(k, target_value_sel)

    best_k_pred = prediction.argsort()[::-1][:k]
    best_k_target = target.argsort()[::-1][:target_k]

    return len(set(best_k_pred).intersection(set(best_k_target))) / k


def denormalize_sim_score(g1, g2, sim_score):
    """
    Converts normalized similar into ged.
    """
    return denormalize_ged(g1, g2, -math.log(sim_score, math.e))


def denormalize_ged(g1, g2, nged):
    """
    Converts normalized ged into ged.
    """
    return round(nged * (g1.num_nodes + g2.num_nodes) / 2)


def gen_synth_data(count=200, nl=None, nu=50, p=0.5, kl=None, ku=2):
    """
    Generating synthetic data based on Erdos–Renyi model.
    :param count: Number of graph pairs to generate.
    :param nl: Minimum number of nodes in a source graph.
    :param nu: Maximum number of nodes in a source graph.
    :param p: Probability of an edge.
    :param kl: Minimum number of insert/remove edge operations on a graph.
    :param ku: Maximum number of insert/remove edge operations on a graph.
    """
    if nl is None:
        nl = nu
    if kl is None:
        kl = ku

    data = []
    data_new = []
    mat = torch.full((count, count), float("inf"))
    norm_mat = torch.full((count, count), float("inf"))

    for i in range(count):
        n = random.randint(nl, nu)
        edge_index = erdos_renyi_graph(n, p)
        x = torch.ones(n, 1)

        g1 = Data(x=x, edge_index=edge_index, i=torch.tensor([i]))
        g2, ged = gen_pair(g1, kl, ku)

        data.append(g1)
        data_new.append(g2)
        mat[i, i] = ged
        norm_mat[i, i] = ged / (0.5 * (g1.num_nodes + g2.num_nodes))

    return data, data_new, mat, norm_mat


def gen_pairs(graphs, kl=None, ku=2):
    gen_graphs_1 = []
    gen_graphs_2 = []

    count = len(graphs)
    mat = torch.full((count, count), float("inf"))
    norm_mat = torch.full((count, count), float("inf"))

    for i, g in enumerate(graphs):
        g = g.clone()
        g.i = torch.tensor([i])
        g2, ged = gen_pair(g, kl, ku)
        gen_graphs_1.append(g)
        gen_graphs_2.append(g2)
        mat[i, i] = ged
        norm_mat[i, i] = ged / (0.5 * (g.num_nodes + g2.num_nodes))

    return gen_graphs_1, gen_graphs_2, mat, norm_mat


def to_directed(edge_index):
    row, col = edge_index
    mask = row < col
    row, col = row[mask], col[mask]
    return torch.stack([row, col], dim=0)


def gen_pair(g, kl=None, ku=2):
    if kl is None:
        kl = ku

    directed_edge_index = to_directed(g.edge_index)

    n = g.num_nodes
    num_edges = directed_edge_index.size()[1]
    to_remove = random.randint(kl, ku)

    edge_index_n = directed_edge_index[:, torch.randperm(num_edges)[to_remove:]]
    if edge_index_n.size(1) != 0:
        edge_index_n = to_undirected(edge_index_n)

    row, col = g.edge_index
    adj = torch.ones((n, n), dtype=torch.uint8)
    adj[row, col] = 0
    non_edge_index = adj.nonzero().t()

    directed_non_edge_index = to_directed(non_edge_index)
    num_edges = directed_non_edge_index.size()[1]

    to_add = random.randint(kl, ku)

    edge_index_p = directed_non_edge_index[:, torch.randperm(num_edges)[:to_add]]
    if edge_index_p.size(1):
        edge_index_p = to_undirected(edge_index_p)
    edge_index_p = torch.cat((edge_index_n, edge_index_p), 1)

    if hasattr(g, "i"):
        g2 = Data(x=g.x, edge_index=edge_index_p, i=g.i)
    else:
        g2 = Data(x=g.x, edge_index=edge_index_p)

    g2.num_nodes = g.num_nodes
    return g2, to_remove + to_add


# fmt: off
def aids_labels(g):
    types = [
        "O", "S", "C", "N", "Cl", "Br", "B", "Si", "Hg", "I", "Bi", "P", "F",
        "Cu", "Ho", "Pd", "Ru", "Pt", "Sn", "Li", "Ga", "Tb", "As", "Co", "Pb",
        "Sb", "Se", "Ni", "Te"
    ]

    return [types[i] for i in g.x.argmax(dim=1).tolist()]
# fmt: on


def draw_graphs(glist, aids=False):
    for i, g in enumerate(glist):
        plt.clf()
        G = to_networkx(g).to_undirected()
        if aids:
            label_list = aids_labels(g)
            labels = {}
            for j, node in enumerate(G.nodes()):
                labels[node] = label_list[j]
            nx.draw(G, labels=labels)
        else:
            nx.draw(G)
        plt.savefig("graph{}.png".format(i))


def draw_weighted_nodes(filename, g, model):
    """
    Draw graph with weighted nodes (for AIDS).
    """
    features = model.convolutional_pass(g.edge_index, g.x)
    coefs = model.attention.get_coefs(features)

    print(coefs)

    plt.clf()
    G = to_networkx(g).to_undirected()

    label_list = aids_labels(g)
    labels = {}
    for i, node in enumerate(G.nodes()):
        labels[node] = label_list[i]

    vmin = coefs.min().item() - 0.005
    vmax = coefs.max().item() + 0.005

    nx.draw(
        G,
        node_color=coefs.tolist(),
        cmap=plt.cm.Reds,
        labels=labels,
        vmin=vmin,
        vmax=vmax,
    )

    # sm = plt.cm.ScalarMappable(cmap=plt.cm.Reds, norm=plt.Normalize(vmin=vmin, vmax=vmax))
    # sm.set_array(coefs.tolist())
    # cbar = plt.colorbar(sm)

    plt.savefig(filename)

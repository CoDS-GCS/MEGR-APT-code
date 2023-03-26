import torch
import torch.nn.functional as F

from math import ceil
from torch.nn import Linear, ReLU
from torch_geometric.nn import (
    DenseSAGEConv,
    DenseGCNConv,
    DenseGINConv,
    dense_diff_pool,
    JumpingKnowledge,
)
from torch_scatter import scatter_mean, scatter_add


class AttentionModule(torch.nn.Module):
    """
    MEGR-APT Attention Module to make a pass on graph.
    """

    def __init__(self, args):
        """
        :param args: Arguments object.
        """
        super(AttentionModule, self).__init__()
        self.args = args
        self.setup_weights()
        self.init_parameters()

    def setup_weights(self):
        """
        Defining weights.
        """
        self.weight_matrix = torch.nn.Parameter(
            torch.Tensor(self.args.filters_3, self.args.filters_3)
        )

    def init_parameters(self):
        """
        Initializing weights.
        """
        torch.nn.init.xavier_uniform_(self.weight_matrix)

    def forward(self, x, batch, size=None):
        """
        Making a forward propagation pass to create a graph level representation.
        :param x: Result of the GNN.
        :param size: Dimension size for scatter_
        :param batch: Batch vector, which assigns each node to a specific example
        :return representation: A graph level representation matrix.
        """
        size = batch[-1].item() + 1 if size is None else size
        mean = scatter_mean(x, batch, dim=0, dim_size=size)
        transformed_global = torch.tanh(torch.mm(mean, self.weight_matrix))

        coefs = torch.sigmoid((x * transformed_global[batch]).sum(dim=1))
        weighted = coefs.unsqueeze(-1) * x

        return scatter_add(weighted, batch, dim=0, dim_size=size)

    def get_coefs(self, x):
        mean = x.mean(dim=0)
        transformed_global = torch.tanh(torch.matmul(mean, self.weight_matrix))

        return torch.sigmoid(torch.matmul(x, transformed_global))


class DenseAttentionModule(torch.nn.Module):
    """
    MEGR-APT Dense Attention Module to make a pass on graph.
    """

    def __init__(self, args):
        """
        :param args: Arguments object.
        """
        super(DenseAttentionModule, self).__init__()
        self.args = args
        self.setup_weights()
        self.init_parameters()

    def setup_weights(self):
        """
        Defining weights.
        """
        self.weight_matrix = torch.nn.Parameter(
            torch.Tensor(self.args.filters_3, self.args.filters_3)
        )

    def init_parameters(self):
        """
        Initializing weights.
        """
        torch.nn.init.xavier_uniform_(self.weight_matrix)

    def forward(self, x, mask=None):
        """
        Making a forward propagation pass to create a graph level representation.
        :param x: Result of the GNN.
        :param mask: Mask matrix indicating the valid nodes for each graph.
        :return representation: A graph level representation matrix.
        """
        B, N, _ = x.size()

        if mask is not None:
            num_nodes = mask.view(B, N).sum(dim=1).unsqueeze(-1)
            mean = x.sum(dim=1) / num_nodes.to(x.dtype)
        else:
            mean = x.mean(dim=1)

        transformed_global = torch.tanh(torch.mm(mean, self.weight_matrix))

        koefs = torch.sigmoid(torch.matmul(x, transformed_global.unsqueeze(-1)))
        weighted = koefs * x

        if mask is not None:
            weighted = weighted * mask.view(B, N, 1).to(x.dtype)

        return weighted.sum(dim=1)


class TensorNetworkModule(torch.nn.Module):
    """
    MEGR-APT Tensor Network module to calculate similarity vector.
    """

    def __init__(self, args):
        """
        :param args: Arguments object.
        """
        super(TensorNetworkModule, self).__init__()
        self.args = args
        self.setup_weights()
        self.init_parameters()

    def setup_weights(self):
        """
        Defining weights.
        """
        self.weight_matrix = torch.nn.Parameter(
            torch.Tensor(
                self.args.filters_3, self.args.filters_3, self.args.tensor_neurons
            )
        )
        self.weight_matrix_block = torch.nn.Parameter(
            torch.Tensor(self.args.tensor_neurons, 2 * self.args.filters_3)
        )
        self.bias = torch.nn.Parameter(torch.Tensor(self.args.tensor_neurons, 1))

    def init_parameters(self):
        """
        Initializing weights.
        """
        torch.nn.init.xavier_uniform_(self.weight_matrix)
        torch.nn.init.xavier_uniform_(self.weight_matrix_block)
        torch.nn.init.xavier_uniform_(self.bias)

    def forward(self, embedding_1, embedding_2):
        """
        Making a forward propagation pass to create a similarity vector.
        :param embedding_1: Result of the 1st embedding after attention.
        :param embedding_2: Result of the 2nd embedding after attention.
        :return scores: A similarity score vector.
        """
        batch_size = len(embedding_1)
        
#         print("Embedding 1 \n", embedding_1)
#         print("\nEmbedding 2 \n", embedding_2)

        scoring = torch.matmul(
            embedding_1, self.weight_matrix.view(self.args.filters_3, -1)
        )
        scoring = scoring.view(batch_size, self.args.filters_3, -1).permute([0, 2, 1])
        scoring = torch.matmul(
            scoring, embedding_2.view(batch_size, self.args.filters_3, 1)
        ).view(batch_size, -1)
        combined_representation = torch.cat((embedding_1, embedding_2), 1)
        block_scoring = torch.t(
            torch.mm(self.weight_matrix_block, torch.t(combined_representation))
        )
        scores = F.relu(scoring + block_scoring + self.bias.view(-1))
        return scores


class Block(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels, mode="cat"):
        super(Block, self).__init__()

        # self.conv1 = DenseSAGEConv(in_channels, hidden_channels)
        # self.conv2 = DenseSAGEConv(hidden_channels, out_channels)

        # self.conv1 = DenseGCNConv(in_channels, hidden_channels)
        # self.conv2 = DenseGCNConv(hidden_channels, out_channels)

        nn1 = torch.nn.Sequential(
            Linear(in_channels, hidden_channels),
            ReLU(),
            Linear(hidden_channels, hidden_channels),
        )

        nn2 = torch.nn.Sequential(
            Linear(hidden_channels, out_channels),
            ReLU(),
            Linear(out_channels, out_channels),
        )

        self.conv1 = DenseGINConv(nn1, train_eps=True)
        self.conv2 = DenseGINConv(nn2, train_eps=True)

        self.jump = JumpingKnowledge(mode)
        if mode == "cat":
            self.lin = Linear(hidden_channels + out_channels, out_channels)
        else:
            self.lin = Linear(out_channels, out_channels)

    def reset_parameters(self):
        self.conv1.reset_parameters()
        self.conv2.reset_parameters()
        self.lin.reset_parameters()

    def forward(self, x, adj, mask=None, add_loop=True):
        x1 = F.relu(self.conv1(x, adj, mask, add_loop))
        x2 = F.relu(self.conv2(x1, adj, mask, add_loop))
        return self.lin(self.jump([x1, x2]))


class DiffPool(torch.nn.Module):
    def __init__(self, args, num_nodes=10, num_layers=4, hidden=16, ratio=0.25):
        super(DiffPool, self).__init__()

        self.args = args
        num_features = self.args.filters_3

        self.att = DenseAttentionModule(self.args)

        num_nodes = ceil(ratio * num_nodes)
        self.embed_block1 = Block(num_features, hidden, hidden)
        self.pool_block1 = Block(num_features, hidden, num_nodes)

        self.embed_blocks = torch.nn.ModuleList()
        self.pool_blocks = torch.nn.ModuleList()
        for i in range((num_layers // 2) - 1):
            num_nodes = ceil(ratio * num_nodes)
            self.embed_blocks.append(Block(hidden, hidden, hidden))
            self.pool_blocks.append(Block(hidden, hidden, num_nodes))
        self.jump = JumpingKnowledge(mode="cat")
        self.lin1 = Linear((len(self.embed_blocks) + 1) * hidden, hidden)
        self.lin2 = Linear(hidden, num_features)

    def reset_parameters(self):
        self.embed_block1.reset_parameters()
        self.pool_block1.reset_parameters()
        for block1, block2 in zip(self.embed_blocks, self.pool_blocks):
            block1.reset_parameters()
            block2.reset_parameters()
        self.jump.reset_parameters()
        self.lin1.reset_parameters()
        self.lin2.reset_parameters()

    def forward(self, x, adj, mask):
        s = self.pool_block1(x, adj, mask, add_loop=True)
        x = F.relu(self.embed_block1(x, adj, mask, add_loop=True))

        xs = [self.att(x, mask)]
        x, adj, _, _ = dense_diff_pool(x, adj, s, mask)

        for i, (embed, pool) in enumerate(zip(self.embed_blocks, self.pool_blocks)):
            s = pool(x, adj)
            x = F.relu(embed(x, adj))
            xs.append(self.att(x))
            if i < (len(self.embed_blocks) - 1):
                x, adj, _, _ = dense_diff_pool(x, adj, s)

        x = self.jump(xs)
        x = F.relu(self.lin1(x))
        x = self.lin2(x)
        return x

    def __repr__(self):
        return self.__class__.__name__

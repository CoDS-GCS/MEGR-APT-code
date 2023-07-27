"""Getting params from the command line."""

import argparse

def parameter_parser():
    """
    A method to parse up command line parameters.
    The default hyperparameters give a high performance model without grid search.
    """
    parser = argparse.ArgumentParser(description="Run SimGNN.")

    parser.add_argument(
        "--dataset",
        nargs="?",
        required=True,
        help="Dataset name.",
    )

    parser.add_argument("--training-graphs",
                        nargs="?",
                        default="./dataset/darpa/train/",
	                help="Folder with training graph pair jsons.")

    parser.add_argument("--testing-graphs",
                        nargs="?",
                        default="./dataset/darpa/test/",
	                help="Folder with testing graph pair jsons.")

    parser.add_argument(
        "--log-similarity",
        help="store Similarity Matrix logs.",
        action="store_true",
        default=False
    )

    parser.add_argument("--predict-graphs",
                        nargs="?",
                        default=None,
	                help="Folder with predict graph pair jsons.")

    parser.add_argument("--predict-case-path",
                        type=str,
                        default=None,
                        help="The path of prediction case.")

    parser.add_argument("--predict-folder-path",
                        type=str,
                        default=None,
                        help="The path of prediction dataset folder.")

    parser.add_argument("--logs-path",
                        nargs="?",
                        default="./logs/",
	                help="Folder for logs & prediction reports.")

    parser.add_argument("--epochs",
                        type=int,
                        default=5,
	                help="Number of training epochs. Default is 5.")
                    
    parser.add_argument("--filters-1",
                        type=int,
                        default=128,
	                help="Filters (neurons) in 1st convolution. Default is 128.")

    parser.add_argument("--filters-2",
                        type=int,
                        default=64,
	                help="Filters (neurons) in 2nd convolution. Default is 64.")

    parser.add_argument("--filters-3",
                        type=int,
                        default=32,
	                help="Filters (neurons) in 3rd convolution. Default is 32.")

    parser.add_argument("--tensor-neurons",
                        type=int,
                        default=16,
	                help="Neurons in tensor network layer. Default is 16.")

    parser.add_argument("--bottle-neck-neurons",
                        type=int,
                        default=16,
	                help="Bottle neck layer neurons. Default is 16.")

    parser.add_argument("--batch-size",
                        type=int,
                        default=128,
	                help="Number of graph pairs per batch. Default is 128.")

    parser.add_argument("--bins",
                        type=int,
                        default=16,
	                help="Similarity score bins. Default is 16.")


    parser.add_argument("--dropout",
                        type=float,
                        default=0.5,
	                help="Dropout probability. Default is 0.5.")

    parser.add_argument("--learning-rate",
                        type=float,
                        default=0.001,
	                help="Learning rate. Default is 0.001.")

    parser.add_argument("--weight-decay",
                        type=float,
                        default=5*10**-4,
	                help="Adam weight decay. Default is 5*10^-4.")
    parser.add_argument("--threshold",
                        type=float,
                        default=0.4,
	                help="Alarm threshold . Default is 0.4")

    parser.add_argument("--save-path",
                        type=str,
                        default=None,
                        help="Where to save the trained model")

    parser.add_argument("--load-path",
                        type=str,
                        default=None,
                        help="Load a pretrained model")

    parser.add_argument("--with-attrs",
                        default=False,
                        action='store_true',
                        help="consider attribute embedding in training")

    parser.add_argument("--only-attrs",
                        default=False,
                        action='store_true',
                        help="consider only attribute embedding in training")
    
    parser.add_argument("--one-gcn-pass",
                        default=False,
                        action='store_true',
                        help="take only one propagation pass")
    
    parser.add_argument("--two-gcn-pass",
                        default=False,
                        action='store_true',
                        help="take only two propagation pass")
    
    parser.add_argument("--sigmoid",
                        default=False,
                        action='store_true',
                        help="take only two propagation pass")
    

    return parser.parse_args()

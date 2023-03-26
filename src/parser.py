import argparse


def parameter_parser():
    """
    A method to parse up command line parameters.
    The default hyperparameters give a high performance model without grid search.
    """
    parser = argparse.ArgumentParser(description="Run MEGRAPT.")

    parser.add_argument(
        "--dataset-path",
        nargs="?",
        help="Dataset path for Dataset.",
        required=True
    )
    parser.add_argument(
        "--dataset",
        nargs="?",
        default="DARPA_CADETS",
        help="Dataset name. Default is DARPA_CADETS",
    )
    
    
    parser.add_argument(
        "--gnn-operator",
        nargs="?",
        default="rgcn",
        help="Type of GNN-Operator. Default is rgcn",
    )
    
    parser.add_argument(
        "--log-similarity",
        help="store Similarity Matrix logs.",
        action="store_true",
        default=False
    )
    
    parser.add_argument(
        "--epochs",
        type=int,
        default=350,
        help="Number of training epochs. Default is 350.",
    )
    
    parser.add_argument(
        "--embedding-layers",
        type=int,
        default=3,
        help="Number of Embedding layers for GCN of RGCN. Default is 3.",
    )    

    parser.add_argument(
        "--filters-1",
        type=int,
        default=64,
        help="Filters (neurons) in 1st convolution. Default is 64.",
    )

    parser.add_argument(
        "--filters-2",
        type=int,
        default=32,
        help="Filters (neurons) in 2nd convolution. Default is 32.",
    )

    parser.add_argument(
        "--filters-3",
        type=int,
        default=16,
        help="Filters (neurons) in 3rd convolution. Default is 16.",
    )

    parser.add_argument(
        "--tensor-neurons",
        type=int,
        default=16,
        help="Neurons in tensor network layer. Default is 16.",
    )

    parser.add_argument(
        "--bottle-neck-neurons",
        type=int,
        default=16,
        help="Bottle neck layer neurons. Default is 16.",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=128,
        help="Number of graph pairs per batch. Default is 128.",
    )

    parser.add_argument(
        "--bins", type=int, default=16, help="Similarity score bins. Default is 16."
    )

    parser.add_argument(
        "--dropout", type=float, default=0, help="Dropout probability. Default is 0."
    )

    parser.add_argument(
        "--learning-rate",
        type=float,
        default=0.001,
        help="Learning rate. Default is 0.001.",
    )

    parser.add_argument(
        "--weight-decay",
        type=float,
        default=5 * 10 ** -4,
        help="Adam weight decay. Default is 5*10^-4.",
    )

    parser.add_argument("--histogram", dest="histogram", action="store_true")

    parser.add_argument(
        "--diffpool",
        dest="diffpool",
        action="store_true",
        help="Enable differentiable pooling.",
    )

    parser.add_argument("--plot", dest="plot", action="store_true")
    parser.add_argument("--plot-thresholds", dest="plot_thresholds", action="store_true")
    
    parser.add_argument("--synth", dest="synth", action="store_true")

    parser.add_argument("--save",
                        type=str,
                        default=None,
                        help="Path to save the trained model")

    parser.add_argument("--load",
                        type=str,
                        default=None,
                        help="Path to load a pretrained model")

    parser.add_argument("--predict",
                        action="store_true",
                        default=False,
                        help="predict graph pairs.")
    
    parser.add_argument("--predict-file",
                        type=str,
                        default=None,
                        help="The path of prediction dataset file.")    

    parser.add_argument("--predict-folder",
                        type=str,
                        default=None,
                        help="The path of prediction dataset folder.")    
    
    
    parser.add_argument(
        "--measure-time",
        action="store_true",
        help="Measure average calculation time for one graph pair. Learning is not performed.",
    )

    
    parser.add_argument(
        "--notify",
        dest="notify",
        action="store_true",
        help="Send notification message when the code is finished (only Linux & Mac OS support).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Alarm threshold . Default is 0.5")    
    parser.add_argument('--similar-attack', help='Experiment for detecting similar attack pattern', action="store_true", default=False)
    
    parser.set_defaults(histogram=False)
    parser.set_defaults(diffpool=False)
    parser.set_defaults(plot=False)
    parser.set_defaults(plot_thresholds=False)
    parser.set_defaults(measure_time=False)
    parser.set_defaults(notify=False)
    parser.set_defaults(synth=False)
    return parser.parse_args()

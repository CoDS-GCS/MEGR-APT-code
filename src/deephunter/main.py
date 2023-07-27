from utils import tab_printer
from deephunter import SimGNNTrainer_attrs
from param_parser import parameter_parser
import time

def main():
    """
    Parsing command line parameters, reading data.
    Fitting and scoring a SimGNN model.
    """
    start_time = time.time()
    args = parameter_parser()
    tab_printer(args)

    trainer = SimGNNTrainer_attrs(args)
    
    if args.load_path:
        trainer.load()
    else:
        trainer.fit()
    if args.predict_folder_path or args.predict_case_path:
        trainer.predict()
    else: 
        trainer.score()
    if args.save_path:
        trainer.save()
    print("--- Running Time is %s seconds ---" % (time.time() - start_time))

if __name__ == "__main__":
    main()

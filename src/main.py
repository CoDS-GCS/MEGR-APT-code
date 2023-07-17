from utils import tab_printer , draw_metrics_over_threshold
from megrapt import MEGRAPTTrainer
from parser import parameter_parser


def main():
    """
    Parsing command line parameters, reading data, fitting and scoring a MEGRAPT model.
    """
#    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    args = parameter_parser()
    tab_printer(args)
    if args.plot_thresholds:
        draw_metrics_over_threshold(args)
        exit()
    trainer = MEGRAPTTrainer(args)
#    trainer = trainer.to(device)
        
    if args.measure_time:
        trainer.measure_time()
    else:
        if args.load:
            trainer.load()
        else:
            trainer.fit()
        if args.predict:
            trainer.predict()
        else:
            trainer.score()
        if args.save:
            trainer.save()

    if args.notify:
        import os
        import sys

        if sys.platform == "linux":
            os.system('notify-send MEGRAPT "Program is finished."')
        elif sys.platform == "posix":
            os.system(
                """
                      osascript -e 'display notification "MEGRAPT" with title "Program is finished."'
                      """
            )
        else:
            raise NotImplementedError("No notification support for this OS.")


if __name__ == "__main__":
    main()

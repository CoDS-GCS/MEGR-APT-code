# GNN Model Training
The training pipeline consist of three steps
1. Generate training set by extraction benign subgraphs.
2. Compute GED for pairs of training set.
3. Train the GNN model with selected parameters.
It's prefered to perform hyper parameters experiment to select the best parameter setting based on the model with the least Mean Square Error (MSE).
The training pipeline could be run using `train_megrapt_model.sh` bash script, including an initial configuration for the hyper parameters experiemnt.

## Configuration
To run the training bash script: 
```angular2html
bash bash_src/train_megrapt_model.sh
```

## Generate training set 
First configure the `get_training_testing_sets()` function in `src/dataset_config.py` file.
Then run the extraction script as follows: 
```angular2html
python  ./src/darpa_tc3/extract_rdf_subgraphs_cadets.py --training --dataset darpa_cadets --output-prx TEST_DEV --parallel
```
The training set is stored on disk in `./dataset/[DATASET_NAME]/experiments/[OUTPUT_PRX]`. Therefore, one experiment should use the same --output-prx value.  

## Compute GED
After generating the training set, run the following script to compute GED between all subgraphs' pairs. This script has only parallel mode since it's computationally expensive.
```angular2html
python ./src/compute_ged_for_training.py -root-path ./dataset/[DATASET_NAME]/experiments/[OUTPUT_PRX]
```

## Train GNN model
Use the main GNN model script to train a model with selected parameters.

- Use the defaults model parameters, set a unique model name.
```angular2html
python ./src/main.py --dataset DARPA_CADETS --dataset-path ./dataset/[DATASET_NAME]/experiments/[OUTPUT_PRX]/ --save ./model/[DATASET_NAME]/[OUTPUT_PRX]/[MODEL_NAME].pt --plot
```
- To specify a specefic parameters
```angular2html
python ./src/main.py --dataset DARPA_CADETS --dataset-path ./dataset/[DATASET_NAME]/experiments/[OUTPUT_PRX]/ --save ./model/[DATASET_NAME]/[OUTPUT_PRX]/[MODEL_NAME].pt --plot --embedding-layers [NUMBER_OF_LAYERS] --learning-rate [LEARNING_RATE] --dropout [DROPOUT] --epochs $[EPOUCH] --filters-1 [INPUT_VECTOR_SIZE] --filters-2 [SECOND_VECTOR_SIZE] --filters-3 [OUTPUT_VECTOR_SIZE] --tensor-neurons [OUTPUT_VECTOR_SIZE] 
```
The `train_megrapt_model.sh` bash script has an option to loop over list of parameters in order to select best setting for the dataset.



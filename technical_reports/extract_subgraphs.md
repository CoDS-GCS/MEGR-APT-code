# Subgraph Extraction
The script `extract_rdf_subgraphs_[DATASET_NAME].py` is used to extract suspicious subgraphs from the provenance graph that match query graphs IOCs. The second use case for the script is to generate training sets of benign subgraphs to use in training GNN models.   

## Argument
- `--output-prx`: The experiment folder name. By Default all experiments are stored in `./dataset/[DATASET_NAME]/experiments/[OUTPUT_PRX]`, Defaults value is `TEMP`.
- `--query-graphs-folder`: The path of Query Graph folder. Default is `./dataset/[DATASET_NAME]/query_graphs/`
- `--ioc-file`: The path of Query Graph IOCs json file. Default is  `./dataset/[DATASET_NAME]/query_graphs_IOCs.json`
- `--parallel`: Runs the script in parallel mode. Default is false.
- `--traverse-with-time`: Consider timestamp while extracting subgraphs. If set to false, Duplicated edges with different timestamp is merged together. Default is false.
- Argument related to suspicious subgraphs extraction:
  - `--test-a-qg`: The name of the tested provenance graph. If not provided, the script get hunting cases from `get_ground_cases()` in `src/dataset_config.py` configuration file.
  parser.add_argument("--pg-name", type=str, default=None, help="The nae of the tested provenance graph.")
  - `--min-nodes`: Set the minimum number of nodes for extracted subgraphs. Default value is 3.
  - `--max-nodes`: Set the maximum number of nodes for extracted subgraphs. Default value is 200.
  - `--max-edges`: Set the maximum number of edges for extracted subgraphs. Default value is 1000.
  - `--min-iocs`: Set the minimum number of Query Graph IOCs to accept a suspicious subgraph. Default value is 1.
  - `--similar-attack`: When `--test-a-qg` is not provided, hunt for similar attack pattern not only the corresponding attacks. Defaults is false.
- Argument related to training set generation:
  - `--training`: To enable the training set generation mode. Default is False.
  - `--n-subgraphs`: Set number of subgraphs for training samples. By not provided, the script get number of subgraphs from `get_training_testing_sets()` function in the configuration file `src/dataset_config.py`

## Configuration
To configure the default hunting cases, use the `get_ground_cases()` function in `src/dataset_config.py` configuration file. Here is an example for the kragle_optc dataset:
Use `--similar-attack` argument to hunt for all attack in all available provenance graphs using  
```
def get_ground_cases(dataset, similar_attack=False):
    if dataset == "DARPA_CADETS":
        if not similar_attack:
            ground_cases = ["BSD_4_in_benign_BSD.pt", "BSD_3_in_benign_BSD.pt", "BSD_4_in_attack_BSD_3_4.pt",
                            "BSD_3_in_attack_BSD_3_4.pt", "BSD_2_in_attack_BSD_2.pt", "BSD_1_in_attack_BSD_1.pt",
                            "BSD_1_in_benign_BSD.pt", "BSD_2_in_benign_BSD.pt"]
        else:
            ground_cases = []
            for qg in ["BSD_1","BSD_2","BSD_3","BSD_4"]:
                for pg in ["attack_BSD_1","attack_BSD_2","attack_BSD_3_4","benign_BSD"]:
                    case_name = qg + "_in_" + pg + ".pt"
                    ground_cases.append(case_name)
```

## Examples
1. To extract suspicious subgraphs for cases provided in the configuration file
```angular2html
python  ./src/darpa_tc3/extract_rdf_subgraphs_cadets.py --dataset darpa_cadets --output-prx TEST_DEV --parallel 
```
2. To extract suspicious subgraphs for the query graph `BSD_1` in the provenance graph `attack_BSD_1`
```angular2html
python  ./src/darpa_tc3/extract_rdf_subgraphs_cadets.py --dataset darpa_cadets  --output-prx TEST_DEV --parallel --test-a-qg BSD_1 --pg-name attack_BSD_1
```
3. To generate training set by extracting benign subgraphs:
```angular2html
python  ./src/darpa_tc3/extract_rdf_subgraphs_cadets.py --dataset darpa_cadets  --training --output-prx TEST_DEV --parallel
```
4. To extract subgraphs with timestamps , It helps in investigation, but it takes longer time. The training sets should have the same nature as the suspicious subgraphs, if needs to include timestamp then it's required to train a model on subgraphs with timestamps.   
```angular2html
python ./src/darpa_tc3/extract_rdf_subgraphs_cadets.py --dataset darpa_cadets  --training --traverse-with-time --parallel --output-prx TEST_DEV_withTimestamp
python ./src/darpa_tc3/extract_rdf_subgraphs_cadets.py --dataset darpa_cadets --traverse-with-time --parallel --output-prx TEST_DEV_withTimestamp
```
5. To use the normal sequential mode, It helps in debugging issues, but it takes longer time.
```angular2html
python ./src/darpa_tc3/extract_rdf_subgraphs_cadets.py --dataset darpa_cadets --output-prx TEST_DEV
```
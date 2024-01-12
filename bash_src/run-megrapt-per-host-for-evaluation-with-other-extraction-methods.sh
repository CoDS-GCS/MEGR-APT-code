#!/bin/sh
date=$(date +'%d_%m_%Y') 
output_prx=Temp
read -p "Enter the experiment folder name:" output_prx
echo "The output forlder is: ${output_prx}"

echo "Available Hosts (cadets, theia, trace, optc)"
read -p "Enter the host name:" host

if [[ "$host" == "cadets" ]]
then
  dataset=DARPA_CADETS
  dataset_name=darpa_cadets
  dataset_folder=darpa_tc3
  echo "${dataset_name} dataset includes (BSD_1, BSD_2, BSD_3, BSD_4) Query Graphs"
  echo "${dataset_name} dataset includes (attack_BSD_1, attack_BSD_2, attack_BSD_3_4, benign_BSD) Provenance Graphs"
elif [[ "$host" == "theia" ]]
then
  dataset=DARPA_THEIA
  dataset_name=darpa_theia
  dataset_folder=darpa_tc3
  echo "${dataset_name} dataset includes (Linux_1, Linux_2) Query Graphs"
  echo "${dataset_name} dataset includes (attack_linux_1_2, benign_theia) Provenance Graphs"
elif [[ "$host" == "trace" ]]
then
  dataset=DARPA_TRACE
  dataset_name=darpa_trace
  dataset_folder=darpa_tc3
  echo "${dataset_name} dataset includes (Linux_3, Linux_4) Query Graphs"
  echo "${dataset_name} dataset includes (attack_linux_3, attack_linux_4, benign_trace) Provenance Graphs"
  
elif [[ "$host" == "optc" ]]
then
  dataset=DARPA_OPTC
  dataset_name=darpa_optc
  dataset_folder=darpa_optc
  echo "${dataset_name} dataset includes (Plain_PowerShell_Empire, Custom_PowerShell_Empire, Malicious_Upgrade) Query Graphs"
  echo "${dataset_name} dataset includes (attack_SysClient0201, attack_SysClient0501, attack_SysClient0051, attack_SysClient0358, benign_SysClient0201, benign_SysClient0501, benign_SysClient0051, benign_SysClient0358) Provenance Graphs"
else
  echo "Undefined host."
fi


preprocess_graph () {
    QG=$1
    pg_name=$2
    QG_IOCs=$3
    Influence_score=$4
    sleep 3
    if [ ! -f ./dataset/${dataset}/experiments/${output_prx}/raw/torch_prediction/${QG}_in_${pg_name}.pt ]; then
      if [[ "$method" == "poirot" ]]
      then
        Influence_score=3
        echo "Extract suspicious subgraphs for ${host}, ${QG}, ${pg_name}, with Influence score ${Influence_score}"
        echo "Store output in ${output_prx} at ${date}"
        python -u src/${dataset_folder}/variations_of_extract_subgraphs_${host}.py --IFS-extract --influence-score ${Influence_score} --QG-all --test-a-qg ${QG} --pg-name ${pg_name} --output-prx ${output_prx} > logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/extract_withPoirotAlgorithm_${QG}_in_${pg_name}_${date}.txt
      elif [[ "$method" == "deephunter" ]]
      then
        echo "Extract suspicious subgraphs for ${host}, ${QG}, ${pg_name}"
        echo "Store output in ${output_prx} at ${date}"
        python -u src/${dataset_folder}/variations_of_extract_subgraphs_${host}.py --deephunter-extract --ioc-file ./dataset/${dataset_name}/query_graphs_IOCs.json --test-a-qg ${QG} --pg-name ${pg_name} --output-prx ${output_prx} > logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/extract_withDeepHunterMethod_${QG}_in_${pg_name}_${date}.txt
      else
        echo "The method ${method} does not exist."
      fi
    else
      echo "Suspicious Subgraphs extracted in ./dataset/${dataset}/experiments/${output_prx}/raw/torch_prediction/${QG}_in_${pg_name}.pt "
    fi
}

mkdir -p logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/

read -p "Do you want to skip subgraph extraction (y/N)": skip
if [[ "$skip" == "y" ]]
then
    read -p "Enter the Threshold": Threshold
else  
    Threshold=0.4
    echo "Available extraction methods (poirot, deephunter)"
    read -p "Enter the extraction methods:" method
    if [[ "$host" == "cadets" ]]
    then
        preprocess_graph BSD_1 attack_BSD_1 ${QG_IOCs} ${Influence_score}
        preprocess_graph BSD_2 attack_BSD_2 ${QG_IOCs} ${Influence_score}
        preprocess_graph BSD_3 attack_BSD_3_4 ${QG_IOCs} ${Influence_score}
        preprocess_graph BSD_4 attack_BSD_3_4 ${QG_IOCs} ${Influence_score}
        for Query in {BSD_1,BSD_2,BSD_3,BSD_4}; do 
        preprocess_graph ${Query} benign_BSD ${QG_IOCs} ${Influence_score}
        done
    elif [[ "$host" == "theia" ]]
    then
        preprocess_graph Linux_1 attack_linux_1_2 ${QG_IOCs} ${Influence_score}
        preprocess_graph Linux_2 attack_linux_1_2 ${QG_IOCs} ${Influence_score}
        for Query in {Linux_1,Linux_2}; do 
            preprocess_graph ${Query} benign_theia ${QG_IOCs} ${Influence_score}
        done
    elif [[ "$host" == "trace" ]]
    then
        preprocess_graph Linux_3 attack_linux_3 ${QG_IOCs} ${Influence_score}
        preprocess_graph Linux_4 attack_linux_4 ${QG_IOCs} ${Influence_score}
        for Query in {Linux_3,Linux_4}; do 
            preprocess_graph ${Query} benign_trace ${QG_IOCs} ${Influence_score}
        done
    elif [[ "$host" == "optc" ]]
    then
        preprocess_graph Plain_PowerShell_Empire attack_SysClient0201 ${QG_IOCs} ${Influence_score}
        preprocess_graph Custom_PowerShell_Empire attack_SysClient0501 ${QG_IOCs} ${Influence_score}
        preprocess_graph Malicious_Upgrade attack_SysClient0051 ${QG_IOCs} ${Influence_score}
        preprocess_graph Custom_PowerShell_Empire attack_SysClient0358 ${QG_IOCs} ${Influence_score}
        
        for PG in {benign_SysClient0201,benign_SysClient0501,benign_SysClient0051,benign_SysClient0358}; do
            for Query in {Plain_PowerShell_Empire,Custom_PowerShell_Empire,Malicious_Upgrade}; do
                preprocess_graph ${Query} ${PG} ${QG_IOCs} ${Influence_score}
            done
        done
    else
        echo "Undefined host."
    fi
fi


predict_model () {
    layer=$1
    LR=$2
    vector1=$3
    vector2=$4
    vector3=$5
    DR=$6
    ep=$7
    Threshold=$8
    echo "Predicting PG ${pg_name} with model parameters ${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --log-similarity --threshold ${Threshold} --load ./model/megrapt/${dataset_name}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt > logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}_TH${Threshold}_${output_prx}_${date}.txt
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --plot-thresholds --load ./model/megrapt/${dataset_name}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt

}


if [[ "$host" == "cadets" ]]
then
  predict_model 2 0.001 128 92 64 0 1000 ${Threshold}
elif [[ "$host" == "theia" ]]
then
  predict_model 2 0.001 64 64 32 0.5 1000 ${Threshold}
elif [[ "$host" == "trace" ]]
then
  predict_model 1 0.0001 128 92 64 0 1000 ${Threshold}
elif [[ "$host" == "optc" ]]
then
  predict_model 1 0.0001 128 92 64 0 1000 ${Threshold}
else
  echo "Undefined host."
fi
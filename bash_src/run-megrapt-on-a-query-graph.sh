#!/bin/sh
date=$(date +'%d_%m_%Y') 
output_prx=Temp

predict_model () {
    layer=$1
    LR=$2
    vector1=$3
    vector2=$4
    vector3=$5
    DR=$6
    ep=$7
    Threshold=$8
    echo "Predicting QG ${QG} in PG ${pg_name} with model parameters ${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
    mkdir -p logs/${dataset_name}/experiments/${output_prx}
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-file ${tested_file} --log-similarity --threshold ${Threshold} --load ./model/megrapt/${dataset_name}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt > logs/${dataset_name}/${output_prx}/${stardog_db}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}_${QG}_in_${pg_name}_${date}.txt
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-file ${tested_file} --plot-thresholds --load ./model/megrapt/${dataset_name}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt

}

read -p "Enter the experiment folder name:" output_prx
read -p "Enter the stardog database name:" stardog_db

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

read -p "Enter the query graph name: " QG
read -p "Enter the provenance graph name: " pg_name
tested_file=${QG}_in_${pg_name}.pt


read -p "Do you want to enter specific query graphs folder (y/N)": Answer
if [[ "$Answer" == "y" ]]
then
  read -p "Enter the Query Graphs folder:" QG_folder
  read -p "Enter the Query Graphs IOCs file:" QG_IOCs
  echo preprocessing_${host}_${output_prx}_${date}
  mkdir -p logs/${dataset_name}/experiments/${output_prx}
  python -u src/${dataset_folder}/extract_rdf_subgraphs_${host}.py --database-name ${stardog_db} --parallel --output-prx ${output_prx} --query-graphs-folder ./dataset/${dataset_name}/${QG_folder}/ --ioc-file ./dataset/${dataset_name}/${QG_IOCs}.json --test-a-qg ${QG} --pg-name ${pg_name} > logs/${dataset_name}/${output_prx}/preprocessing_${stardog_db}_${QG}_in_${pg_name}_${date}.txt
else
  echo preprocessing_${host}_${output_prx}_${date}
  python -u src/${dataset_folder}/extract_rdf_subgraphs_${host}.py --database-name ${stardog_db} --test-a-qg ${QG} --pg-name ${pg_name} --parallel --output-prx ${output_prx} > logs/${dataset_name}/${output_prx}/preprocessing_${stardog_db}_${QG}_in_${pg_name}_${date}.txt
fi

if [[ "$host" == "cadets" ]]
then
  predict_model 2 0.001 128 92 64 0 1000 0.4
elif [[ "$host" == "theia" ]]
then
  predict_model 2 0.001 64 64 32 0.5 1000 0.4
elif [[ "$host" == "trace" ]]
then
  predict_model 1 0.0001 128 92 64 0 1000 0.4
elif [[ "$host" == "optc" ]]
then
  predict_model 1 0.0001 128 92 64 0 1000 0.4
else
  echo "Undefined host."
fi


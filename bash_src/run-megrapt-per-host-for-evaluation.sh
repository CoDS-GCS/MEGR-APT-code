#!/bin/sh
date=$(date +'%d_%m_%Y') 
output_prx=Temp
read -p "Enter the experiment folder name:" output_prx
echo "The output forlder is: ${output_prx}"
read -p "Enter the stardog database name:" stardog_db
read -p "Enter the stardog username:" stardogUserName
read -p "Enter the stardog password:" stardogpassword
echo "Available Hosts (cadets, theia, trace, optc)"
read -p "Enter the host name:" host



Max_Nodes_Mult=10
Max_Edges_Mult=25

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
    specific_QG=$3
    QG_folder=$4
    QG_IOCs=$5
    stardog-admin db online ${stardog_db} -u ${stardogUserName} -p ${stardogpassword}
    if [ ! -f ./dataset/${dataset}/experiments/${output_prx}/raw/torch_prediction/${QG}_in_${pg_name}.pt ]; then
    
        echo "Extract suspicious subgraphs for ${host}, ${QG}, ${pg_name}"
        echo "Store output in ${output_prx} at ${date}"
        mkdir -p logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/
        if [[ "$specific_QG" == "y" ]]
        then
          echo "Query Graph Folder ${QG_folder}, IOCs ${QG_IOCs}"
          python -u src/${dataset_folder}/extract_rdf_subgraphs_${host}.py --parallel --output-prx ${output_prx} --max-nodes-mult-qg ${Max_Nodes_Mult} --max-edges-mult-qg ${Max_Edges_Mult} --query-graphs-folder ./dataset/${dataset_name}/${QG_folder}/ --ioc-file ./dataset/${dataset_name}/${QG_IOCs}.json --test-a-qg ${QG} --pg-name ${pg_name} >> logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/MEGRAPT_preprocessing_${host}_rdf_${date}.txt
        else
          python -u src/${dataset_folder}/extract_rdf_subgraphs_${host}.py --parallel --output-prx ${output_prx} --max-nodes-mult-qg ${Max_Nodes_Mult} --max-edges-mult-qg ${Max_Edges_Mult} --test-a-qg ${QG} --pg-name ${pg_name} >> logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/MEGRAPT_preprocessing_${host}_rdf_${date}.txt
        fi
    else
      echo "Suspicious Subgraphs extracted in ./dataset/${dataset}/experiments/${output_prx}/raw/torch_prediction/${QG}_in_${pg_name}.pt "
    fi
    stardog-admin db offline 1m ${stardog_db} -u ${stardogUserName} -p ${stardogpassword}
    sleep 60
}

read -p "Do you want to skip subgraph extraction (y/N)": skip
if [[ "$skip" == "y" ]]
then
    read -p "Enter the Threshold": Threshold
else  
    Threshold=0.4
    read -p "Do you want to enter specific query graphs folder (y/N)": specific_QG
    if [[ "$specific_QG" == "y" ]]
    then
    read -p "Enter the Query Graphs folder:" QG_folder
    read -p "Enter the Query Graphs IOCs file:" QG_IOCs
    fi
    if [[ "$host" == "cadets" ]]
    then
        preprocess_graph BSD_1 attack_BSD_1 ${specific_QG} ${QG_folder} ${QG_IOCs}
        preprocess_graph BSD_2 attack_BSD_2 ${specific_QG} ${QG_folder} ${QG_IOCs}
        preprocess_graph BSD_3 attack_BSD_3_4 ${specific_QG} ${QG_folder} ${QG_IOCs}
        preprocess_graph BSD_4 attack_BSD_3_4 ${specific_QG} ${QG_folder} ${QG_IOCs}
        for Query in {BSD_1,BSD_2,BSD_3,BSD_4}; do 
        preprocess_graph ${Query} benign_BSD ${specific_QG} ${QG_folder} ${QG_IOCs}
        done
    elif [[ "$host" == "theia" ]]
    then
        preprocess_graph Linux_1 attack_linux_1_2 ${specific_QG} ${QG_folder} ${QG_IOCs}
        preprocess_graph Linux_2 attack_linux_1_2 ${specific_QG} ${QG_folder} ${QG_IOCs}
        for Query in {Linux_1,Linux_2}; do 
            preprocess_graph ${Query} benign_theia ${specific_QG} ${QG_folder} ${QG_IOCs}
        done
    elif [[ "$host" == "trace" ]]
    then
        preprocess_graph Linux_3 attack_linux_3 ${specific_QG} ${QG_folder} ${QG_IOCs}
        preprocess_graph Linux_4 attack_linux_4 ${specific_QG} ${QG_folder} ${QG_IOCs}
        for Query in {Linux_3,Linux_4}; do 
            preprocess_graph ${Query} benign_trace ${specific_QG} ${QG_folder} ${QG_IOCs}
        done
    elif [[ "$host" == "optc" ]]
    then
        for PG in {benign_SysClient0201,benign_SysClient0501,benign_SysClient0051,benign_SysClient0358}; do
            for Query in {Plain_PowerShell_Empire,Custom_PowerShell_Empire,Malicious_Upgrade}; do
                preprocess_graph ${Query} ${PG} ${specific_QG} ${QG_folder} ${QG_IOCs}
            done
        done
        preprocess_graph Malicious_Upgrade attack_SysClient0051 ${specific_QG} ${QG_folder} ${QG_IOCs}
        preprocess_graph Custom_PowerShell_Empire attack_SysClient0358 ${specific_QG} ${QG_folder} ${QG_IOCs}
        preprocess_graph Custom_PowerShell_Empire attack_SysClient0501 ${specific_QG} ${QG_folder} ${QG_IOCs}
        sleep 300
        preprocess_graph Plain_PowerShell_Empire attack_SysClient0201 ${specific_QG} ${QG_folder} ${QG_IOCs}
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
    mkdir -p logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/
    echo "Predicting PG ${pg_name} with model parameters ${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --log-similarity --threshold ${Threshold} --load ./model/megrapt/${dataset_name}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt > logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}_TH${Threshold}_${output_prx}_${date}.txt
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --plot-thresholds --load ./model/megrapt/${dataset_name}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt

}

# Default Parameters
predict_model 2 0.001 64 64 32 0 1000 ${Threshold}
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


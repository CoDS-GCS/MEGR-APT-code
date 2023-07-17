#!/bin/sh
date=$(date +'%d_%m_%Y') 
output_prx=Temp



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




insert_benign_subgraphs () {
    run=$1
    n_subgraphs=$2
    echo "insert ${n_subgraphs} benign subgraphs to ${host} ${pg_name} ${output_prx}_${date}" 
    python -u src/insert_benign_subgraphs.py --dataset ${dataset_name} --n-subgraphs ${n_subgraphs} --insertion-node ${insertion_node} --database-name ${stardog_db} --qg-name ${QG} --pg-name ${pg_name}  --output-prx experiments/${output_prx} >> logs/${dataset_name}/${output_prx}/mimicry_attack_with_${n_subgraphs}_subgraphs_run_${run}_${date}.txt
}

extract_subgraphs () {
    run=$1
    n_subgraphs=$2
    echo "extract subgraphs for ${QG} from ${pg_name}. ${output_prx}_${date}" 
    python -u src/${dataset_folder}/extract_rdf_subgraphs_${host}.py --database-name ${stardog_db} --test-a-qg ${QG} --pg-name ${pg_name} --parallel  --output-prx experiments/${output_prx} >> logs/${dataset_name}/${output_prx}/mimicry_attack_with_${n_subgraphs}_subgraphs_run_${run}_${date}.txt
}

predict_model () {
    layer=$1
    LR=$2
    vector1=$3
    vector2=$4
    vector3=$5
    DR=$6
    ep=$7
    Threshold=$8
    run=$9
    n_subgraphs=${10}
    echo "Predicting QG ${QG} in PG ${pg_name} with model parameters ${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
    python ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-file ${QG}_in_${pg_name}.pt --log-similarity --threshold ${Threshold} --load ./model/megrapt/${dataset_name}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt >> logs/${dataset_name}/${output_prx}/mimicry_attack_with_${n_subgraphs}_subgraphs_run_${run}_${date}.txt

}

select_and_predict_model () {
    run=$1
    n_subgraphs=$2
    if [[ "$host" == "cadets" ]]
    then
      predict_model 2 0.001 128 92 64 0 1000 0.4 ${run} ${n_subgraphs}
    elif [[ "$host" == "theia" ]]
    then
      predict_model 2 0.001 64 64 32 0.5 1000 0.4 ${run} ${n_subgraphs}
    elif [[ "$host" == "trace" ]]
    then
      predict_model 1 0.0001 128 92 64 0 1000 0.4 ${run} ${n_subgraphs}
    elif [[ "$host" == "optc" ]]
    then
      predict_model 1 0.0001 128 92 64 0 1000 0.4 ${run} ${n_subgraphs}
    else
      echo "Undefined host."
    fi
}

clear_inserted_subgraphs () {
    run=$1
    n_subgraphs=$2
    echo "insert ${n_subgraphs} benign subgraphs to ${host} ${pg_name} ${output_prx}_${date}" 
    python -u src/clear_inserted_subgraphs.py --dataset ${dataset_name} --database-name ${stardog_db} --output-prx experiments/${output_prx} --pg-name ${pg_name} >> logs/${dataset_name}/${output_prx}/mimicry_attack_with_${n_subgraphs}_subgraphs_run_${run}_${date}.txt
}

mimicry_attack () {
    for n_subgraphs in $(seq 1 10); do
        for run in $(seq 1 ${runs}); do
            echo "Run number ${run}, n_subgraphs: ${n_subgraphs}" 
            echo "Threat Hunting the Query Graph ${QG} within the provenance graph ${pg_name}" >> logs/${dataset_name}/${output_prx}/mimicry_attack_with_${n_subgraphs}_subgraphs_run_${run}_${date}.txt
            echo "The detecion performance before mimicry attack " >> logs/${dataset_name}/${output_prx}/mimicry_attack_with_${n_subgraphs}_subgraphs_run_${run}_${date}.txt
            extract_subgraphs ${run} ${n_subgraphs}
            select_and_predict_model ${run} ${n_subgraphs}
            insert_benign_subgraphs ${run} ${n_subgraphs} 
            echo "The detecion performance after mimicry attack " >> logs/${dataset_name}/${output_prx}/mimicry_attack_with_${n_subgraphs}_subgraphs_run_${run}_${date}.txt
            extract_subgraphs ${run} ${n_subgraphs}
            select_and_predict_model ${run} ${n_subgraphs}
            clear_inserted_subgraphs ${run} ${n_subgraphs}
        done
    done
}

# read -p "Enter the query graph name: " QG
# read -p "Enter the provenance graph name: " pg_name
# read -p "Enter the number of inserted subgraphs: " n_subgraphs
# read -p "Enter the insertion point node UUID: " insertion_node

read -p "Enter the number of runs: " runs
mkdir -p logs/${dataset_name}/${output_prx}

QG=BSD_1
pg_name=attack_BSD_1
insertion_node=D3822AFC-39AF-11E8-BF66-D9AA8AFF4A69
mimicry_attack 

QG=BSD_2
pg_name=attack_BSD_2
insertion_node=2720E25F-39BE-11E8-B8CE-15D78AC88FB6
mimicry_attack

QG=BSD_3
pg_name=attack_BSD_3_4
insertion_node=4FB0BFEA-3F1C-11E8-A5CB-3FA3753A265A
mimicry_attack

QG=BSD_4
pg_name=attack_BSD_3_4
insertion_node=219DE547-3E7E-11E8-A5CB-3FA3753A265A
mimicry_attack
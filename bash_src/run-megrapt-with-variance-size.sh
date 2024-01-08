#!/bin/sh
date=$(date +'%d_%m_%Y')
output_prx=Temp
read -p "Enter the stardog database name:" stardog_db
echo "Available Hosts (cadets, theia, trace, optc)"
read -p "Enter the host name:" host

export PATH="$PATH:/opt/stardog/stardog-9.2.1/bin"
export STARDOG_JAVA_ARGS="-Dstardog.default.cli.server=https://sd-d63d428a.stardog.cloud:5820"
read -p "Enter the experiment folder name:" output_prx_root

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
    output_prx=$3
    Max_Nodes_Mult=$4
    Max_Edges_Mult=$5
    echo ${output_prx}
    stardog-admin db online ${stardog_db} -u ahmed3amerai@gmail.com -p Stardog_Ahmed_2023
    if [ ! -f ./dataset/${dataset}/experiments/${output_prx}/raw/torch_prediction/${QG}_in_${pg_name}.pt ]; then

        echo "Extract suspicious subgraphs for ${host}, ${QG}, ${pg_name}"
        echo "Store output in ${output_prx} at ${date}"
        mkdir -p logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/
        python -u src/${dataset_folder}/extract_rdf_subgraphs_${host}.py --parallel --output-prx ${output_prx} --max-nodes-mult-qg ${Max_Nodes_Mult} --max-edges-mult-qg ${Max_Edges_Mult} --test-a-qg ${QG} --pg-name ${pg_name} >> logs/${dataset_name}/${output_prx}/MEGRAPT_preprocessing_${host}_rdf_${date}.txt
    else
      echo "Suspicious Subgraphs extracted in ./dataset/${dataset}/experiments/${output_prx}/raw/torch_prediction/${QG}_in_${pg_name}.pt "
    fi
    stardog-admin db offline 1m ${stardog_db} -u ahmed3amerai@gmail.com -p Stardog_Ahmed_2023
    sleep 60
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
    output_prx=$9
    echo ${output_prx}
    mkdir -p logs/${dataset_name}/${output_prx}/Evaluate_Per_Host/
    echo "Predicting PG ${pg_name} with model parameters ${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --log-similarity --threshold ${Threshold} --load ./model/megrapt/${dataset_name}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt > logs/${dataset_name}/${output_prx}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}_TH${Threshold}_${output_prx}_${date}.txt
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --plot-thresholds --load ./model/megrapt/${dataset_name}/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt
}

run_megrapt () {
  start_time=`date +%s`
  output_prx=$1
  Max_Nodes_Mult=$2
  Max_Edges_Mult=$3
  echo ${output_prx}

#  if [[ "$host" == "cadets" ]]
#  then
#      preprocess_graph BSD_1 attack_BSD_1 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      preprocess_graph BSD_2 attack_BSD_2 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      preprocess_graph BSD_3 attack_BSD_3_4 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      preprocess_graph BSD_4 attack_BSD_3_4 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      for Query in {BSD_1,BSD_2,BSD_3,BSD_4}; do
#      preprocess_graph ${Query} benign_BSD ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      done
#  elif [[ "$host" == "theia" ]]
#  then
#      preprocess_graph Linux_1 attack_linux_1_2 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      preprocess_graph Linux_2 attack_linux_1_2 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      for Query in {Linux_1,Linux_2}; do
#          preprocess_graph ${Query} benign_theia ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      done
#  elif [[ "$host" == "trace" ]]
#  then
#      preprocess_graph Linux_3 attack_linux_3 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      preprocess_graph Linux_4 attack_linux_4 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      for Query in {Linux_3,Linux_4}; do
#          preprocess_graph ${Query} benign_trace ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      done
#  elif [[ "$host" == "optc" ]]
#  then
#      for PG in {benign_SysClient0201,benign_SysClient0501,benign_SysClient0051,benign_SysClient0358}; do
#          for Query in {Plain_PowerShell_Empire,Custom_PowerShell_Empire,Malicious_Upgrade}; do
#              preprocess_graph ${Query} ${PG} ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#          done
#      done
#      preprocess_graph Malicious_Upgrade attack_SysClient0051 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      preprocess_graph Custom_PowerShell_Empire attack_SysClient0358 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      sleep 300
#      preprocess_graph Custom_PowerShell_Empire attack_SysClient0501 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#      sleep 300
#      preprocess_graph Plain_PowerShell_Empire attack_SysClient0201 ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#  else
#      echo "Undefined host."
#  fi
  Threshold=0.4
  # Default Parameters
  predict_model 2 0.001 64 64 32 0 1000 ${Threshold} ${output_prx}
  if [[ "$host" == "cadets" ]]
  then
    predict_model 2 0.001 128 92 64 0 1000 ${Threshold} ${output_prx}
  elif [[ "$host" == "theia" ]]
  then
    predict_model 2 0.001 64 64 32 0.5 1000 ${Threshold} ${output_prx}
  elif [[ "$host" == "trace" ]]
  then
    predict_model 1 0.0001 128 92 64 0 1000 ${Threshold} ${output_prx}
  elif [[ "$host" == "optc" ]]
  then
    predict_model 1 0.0001 128 92 64 0 1000 ${Threshold} ${output_prx}
  else
    echo "Undefined host."
  fi
  end_time=`date +%s`
  runtime=$(((end_time-start_time)-(60*16)-300))
  echo "Total Time is ${runtime} seconds" > logs/${dataset_name}/${output_prx}/total_running_time_with_bash.txt
}

handle () {
  QG=$1
  pg_name=$2
  Max_Nodes_Mult=$3
  Max_Edges_Mult=$4
  output_prx="${output_prx_root}_${Max_Nodes_Mult}_Nodes_${Max_Edges_Mult}_Edges"
  echo output_prx
  preprocess_graph ${QG} ${pg_name} ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
}


handle Custom_PowerShell_Empire benign_SysClient0051 10 30
handle Malicious_Upgrade attack_SysClient0051 20 25
handle Custom_PowerShell_Empire attack_SysClient0501 20 30
sleep 300
handle Plain_PowerShell_Empire attack_SysClient0201 20 20
sleep 300
handle Plain_PowerShell_Empire attack_SysClient0201 15 25
sleep 300
handle Plain_PowerShell_Empire attack_SysClient0201 10 20


Max_Edges_Mult=25
for Max_Nodes_Mult in {5,15,20};do
  output_prx="${output_prx_root}_${Max_Nodes_Mult}_Nodes_${Max_Edges_Mult}_Edges"
  echo "The output forlder is: ${output_prx}"
  run_megrapt ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#  sleep 300
done
Max_Nodes_Mult=10
for Max_Edges_Mult in {15,20,30};do
  output_prx="${output_prx_root}_${Max_Nodes_Mult}_Nodes_${Max_Edges_Mult}_Edges"
  echo "The output forlder is: ${output_prx}"
  run_megrapt ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#  sleep 300
done

for Max_Nodes_Mult in {5,15,20};do
  for Max_Edges_Mult in {15,20,30};do
    output_prx="${output_prx_root}_${Max_Nodes_Mult}_Nodes_${Max_Edges_Mult}_Edges"
    echo "The output forlder is: ${output_prx}"
    run_megrapt ${output_prx} ${Max_Nodes_Mult} ${Max_Edges_Mult}
#    sleep 300
  done
done



#!/bin/sh
date=$(date +'%d_%m_%Y')
read -p "Enter the experiment folder name:" output_prx
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


if [ ! -f ./dataset/${dataset_name}/experiments/${output_prx}/raw/torch_training_dataset.pt ]
then
    echo "No Training sets extracted in ./dataset/${dataset_name}/experiments/${output_prx}/raw/torch_training_dataset.pt"
    echo "Extract Training sets for ${dataset_name} dataset, store in ${output_prx} experiment"
    read -p "Do you want to extract subgraphs with timestamps (Y/n)": with_timestamp
    if [[ "$with_timestamp" == "n" ]]; then
      echo "extracting without timestamps"
      python -u src/${dataset_folder}/extract_rdf_subgraphs_${host}.py --training --output-prx ${output_prx} --parallel
      sleep 5
    else
      echo "extracting with timestamps"
      python src/${dataset_folder}/extract_rdf_subgraphs_${host}.py --training  --output-prx ${output_prx} --parallel --traverse-with-time
      sleep 5
    fi
else
  echo "Training sets exist in ./dataset/${dataset_name}/experiments/${output_prx}/raw/torch_training_dataset.pt"
fi

if [ ! -f ./dataset/${dataset_name}/experiments/${output_prx}/raw/nged_matrix.pt ]
then
    echo "No computed GED in computed in ./dataset/${dataset_name}/experiments/${output_prx}/raw/nged_matrix.pt"
    echo "Compute GED for ${output_prx} experiment on ${dataset_name} dataset"
    python ./src/compute_ged_for_training.py --root-path ./dataset/${dataset_name}/experiments/${output_prx}
    sleep 5
else
  echo "GED has computed in ./dataset/${dataset_name}/experiments/${output_prx}/raw/nged_matrix.pt"
fi


train_model () {
    layer=$1
    LR=$2
    vector1=$3
    vector2=$4
    vector3=$5
    DR=$6
    ep=$7
    gnn=$8
    echo "Training ${dataset_name}_${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
    mkdir -p model/${dataset_name}/experiments/${output_prx}
    python ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator ${gnn} --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --plot --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --save ./model/megrapt/${dataset_name}/${output_prx}/${dataset_name}_${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt
}




read -p "Do you want to perform Hyper-parameters (y/N)": skip_hyper
if [[ "$skip_hyper" == "y" ]]; then
  epochs=1000
  for layers in {1,2};do
    for learning_rate in {0.001,0.0001,0.01};do
        for dropout in {0,0.5};do
          train_model ${layers} ${learning_rate} 128 92 64 ${dropout} ${epochs} rgcn
          train_model ${layers} ${learning_rate} 64 64 32 ${dropout} ${epochs} rgcn
        done
    done
  done
else
  #The default parameter
  train_model 2 0.001 64 64 32 0 1000 rgcn
  if [[ "$host" == "cadets" ]]
  then
    train_model 2 0.001 128 92 64 0 1000 rgcn
  elif [[ "$host" == "theia" ]]
  then
    train_model 2 0.001 64 64 32 0.5 1000 rgcn
  elif [[ "$host" == "trace" ]]
  then
    train_model 1 0.0001 128 92 64 0 1000 rgcn
  elif [[ "$host" == "optc" ]]
  then
    train_model 1 0.0001 128 92 64 0 1000 rgcn
  else
    echo "Undefined dataset."
  fi
fi

echo "Done Training pipeline"
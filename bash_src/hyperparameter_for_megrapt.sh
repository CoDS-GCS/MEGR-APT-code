#!/bin/sh
date=$(date +'%d_%m_%Y') 
output_prx=Temp
read -p "Enter the experiment folder name:" output_prx
read -p "Enter the training experiment folder name:" training_prx
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


predict_model () {
    layer=$1
    LR=$2
    vector1=$3
    vector2=$4
    vector3=$5
    DR=$6
    ep=$7
    Threshold=$8
    mkdir -p logs/${dataset_name}/hyperparameter/
    echo "Predicting PG ${pg_name} with model parameters ${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --log-similarity --threshold ${Threshold} --load ./model/megrapt/${dataset_name}/hyperparameter/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt > logs/${dataset_name}/hyperparameter/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}_TH${Threshold}_${output_prx}_${date}.txt
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator rgcn --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --plot-thresholds --load ./model/megrapt/${dataset_name}/hyperparameter/${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt

}

train_model () {
    layer=$1
    LR=$2
    vector1=$3
    vector2=$4
    vector3=$5
    DR=$6
    ep=$7
    gnn=$8
    if [ ! -f ./model/megrapt/${dataset_name}/hyperparameter/${dataset_name}_${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt ]
    then
      echo "Training ${dataset_name}_${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
      python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${training_prx}/ --gnn-operator ${gnn} --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --plot --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --save ./model/megrapt/${dataset_name}/hyperparameter/${dataset_name}_${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt > logs/${dataset_name}/hyperparameter/Training_${training_prx}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}_${date}.txt
    fi
    predict_model ${layer} ${LR} ${vector1} ${vector2} ${vector3} ${DR} ${ep} ${Threshold}
}


mkdir -p model/megrapt/${dataset_name}/hyperparameter/
Threshold=0.4
ep=1000

for layer in {1,2,3};do
  DR=0
  LR=0.001
  train_model ${layer} ${LR} 64 32 16 ${DR} ${ep} rgcn
  train_model ${layer} ${LR} 64 64 32 ${DR} ${ep} rgcn
  train_model ${layer} ${LR} 128 92 64 ${DR} ${ep} rgcn
  for LR in {0.1,0.01,0.0001};do
    train_model ${layer} ${LR} 128 92 64 ${DR} ${ep} rgcn
  done
  LR=0.001
  for DR in {0.25,0.5};do
    train_model ${layer} ${LR} 128 92 64 ${DR} ${ep} rgcn
  done
done


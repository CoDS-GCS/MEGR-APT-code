#!/bin/sh

date=$1
output_prx=$2
predict=$3
dataset=$4 
dataset_name=$5 
Threshold=$6

train_model () {
    layer=$1
    LR=$2
    vector1=$3
    vector2=$4
    vector3=$5
    DR=$6
    ep=$7
    gnn=$8

    echo "Training ${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/experiments/${output_prx}/ --gnn-operator ${gnn} --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --plot --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --save ./model/simgnn/${dataset_name}_${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt > logs/${dataset_name}/compare_with_simgnn/${dataset_name}_${output_prx}${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}_${date}.txt
}
predict_model () {
    layer=$1
    LR=$2
    vector1=$3
    vector2=$4
    vector3=$5
    DR=$6
    ep=$7
    gnn=$8
    Threshold=$9
    
    echo "Predicting ${dataset_name}_${layer}rgcn_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}"
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/${predict}/ --gnn-operator ${gnn} --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --plot --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --log-similarity --threshold ${Threshold} --load ./model/simgnn/${dataset_name}_${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt > logs/${dataset_name}/compare_with_simgnn/${dataset_name}_${predict}_${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}_${date}.txt  
    python -u ./src/main.py --dataset ${dataset} --dataset-path ./dataset/${dataset_name}/${predict}/ --gnn-operator ${gnn} --embedding-layers ${layer} --learning-rate ${LR} --dropout ${DR} --epochs ${ep} --plot --filters-1 ${vector1} --filters-2 ${vector2} --filters-3 ${vector3} --tensor-neurons ${vector3} --predict --predict-folder raw/torch_prediction/ --plot-thresholds --load ./model/simgnn/${dataset_name}_${layer}${gnn}_Lr${LR}_Dr${DR}_${vector1}-${vector2}-${vector3}_${ep}.pt 
}

dataset=DARPA_OPTC
dataset_name=darpa_optc
train_model 3 0.001 64 32 16 0 10000 gcn

# SimGNN Parameters
predict_model 3 0.001 64 32 16 0 10000 gcn ${Threshold}


# dataset=DARPA_CADETS
# dataset_name=darpa_tc3
# train_model 2 0.001 128 92 64 0 1000 gcn

# dataset=DARPA_THEIA
# dataset_name=darpa_theia
# train_model 2 0.001 64 64 32 0.5 1000 gcn

#Best paramters for Trace based on MEGR-APT
# train_model 1 0.0001 128 92 64 0 1000 gcn
# predict_model 1 0.0001 128 92 64 0 1000 gcn ${Threshold}

# # Best parameters for THEIA based on MEGR-APT
# predict_model 2 0.001 64 64 32 0.5 1000 gcn ${Threshold}

# # Best parameters for CADETS based on MEGR-APT
# predict_model 2 0.001 128 92 64 0 1000 gcn ${Threshold}

# # Best parameters for OpTC based on MEGR-APT
# predict_model 1 0.001 64 64 32 0.5 1000 gcn ${Threshold}





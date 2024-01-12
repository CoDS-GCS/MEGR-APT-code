#!/bin/sh
date=$(date +'%d_%m_%Y')
echo "Available Hosts (cadets, theia, trace, optc)"
read -p "Enter the host name:" dataset
read -p "Enter the stardog dataset name:" stardogDataseet
read -p "Enter the stardog username:" stardogUserName
read -p "Enter the stardog password:" stardogpassword
read -p "Enter the turtle provenance graphs folder path:" PG_path
mkdir -p logs/${dataset}/
load_graph () {
   graph_name=$1
   echo ${graph_name}.ttl >> logs/${dataset}/loading_${dataset}_provenance_graph_${date}.txt
   stardog data add ${stardogDataseet} ${PG_path}/${graph_name}.ttl -u ${stardogUserName} -p ${stardogpassword} >> logs/${dataset}/loading_${dataset}_provenance_graph_${date}.txt

}

if [[ "$dataset" == "optc" ]]
then
  load_graph attack_SysClient0358
  load_graph attack_SysClient0501
  load_graph attack_SysClient0051
  load_graph attack_SysClient0201

  load_graph benign_SysClient0501
  load_graph benign_SysClient0051
  load_graph benign_SysClient0201
  load_graph benign_SysClient0358
elif [[ "$dataset" == "cadets" ]]
then
  load_graph attack_BSD_1_provenance_graph
  load_graph attack_BSD_2_provenance_graph
  load_graph attack_BSD_3_4_provenance_graph
  load_graph benign_BSD_provenance_graph
elif [[ "$dataset" == "theia" ]]
then
  load_graph attack_Linux_1_2_provenance_graph_v2
  load_graph benign_Linux_provenance_graph_v2
elif [[ "$dataset" == "trace" ]]
then
  load_graph attack_Linux_4_provenance_graph
  load_graph benign_TRACE_provenance_graph
  for part in {1..8};do
    load_graph attack_Linux_3_provenance_graph_part${part}
  done
else
  echo "Undefined dataset"
fi

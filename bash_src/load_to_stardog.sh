#!/bin/sh
date=$(date +'%d_%m_%Y')
echo "Available Hosts (cadets, theia, trace, optc)"
read -p "Enter the host name:" dataset
read -p "Enter the stardog dataset name:" stardogDataseet
read -p "Enter the stardog port:" stardogPort
read -p "Enter the turtle provenance graphs folder path:" PG_path

load_graph () {
   graph_name=$1
   echo ${graph_name}.ttl >> logs/${dataset}/loading_${dataset}_provenance_graph_${date}.txt
   stardog data add --server-side -- http://localhost:${stardogPort}/${stardogDataseet} ${PG_path}/${graph_name}.ttl > logs/${dataset}/loading_${dataset}_provenance_graph_${date}.txt
}

##DARPA OpTC
load_graph attack_SysClient0358
#load_graph attack_SysClient0501
#load_graph attack_SysClient0051
#load_graph attack_SysClient0201
#
#load_graph benign_SysClient0501
#load_graph benign_SysClient0051
#load_graph benign_SysClient0201
#load_graph benign_SysClient0358


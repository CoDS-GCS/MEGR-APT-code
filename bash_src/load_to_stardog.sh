#!/bin/sh
date=$(date +'%d_%m_%Y')
echo "Available Hosts (cadets, theia, trace, optc)"
read -p "Enter the host name:" dataset
read -p "Enter the stardog dataset name:" stardogDataseet
read -p "Enter the turtle provenance graph path name:" PG_path
read -p "Enter the stardog port:" stardogPort
load_graph () {
   graph_name=$1
   echo ${graph_name}.ttl >> logs/${dataset}/loading_${dataset}_provenance_graph_${date}.txt
   stardog data add --server-side -- http://localhost:${stardogPort}/${stardogDataseet} ${PG_path} > logs/${dataset}/loading_${dataset}_provenance_graph_${date}.txt

}



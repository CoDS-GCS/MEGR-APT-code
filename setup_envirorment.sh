#!/bin/sh
echo "create virtual environment and pip install requirements"
sudo apt-get install gcc libpq-dev
sudo apt-get install python3.8 python3.8-dev python3.8-distutils python3.8-venv
sudo apt-get install graphviz graphviz-dev
sudo apt install htop screen nano vim git
conda create --name envmegrapt  python=3.8
conda activate envmegrapt
pip3 install -r requirements.txt
pip install torch-sparse==0.6.13 torch-geometric==2.0.4 torch-cluster==1.6.0 torch-scatter==2.0.9 torch-spline-conv==1.2.1 torchaudio==0.11.0 torchvision==0.12.0 -f https://data.pyg.org/whl/torch-1.11.0+cpu.html

echo "install jupyter and export environment"
pip3 install jupyterlab
pip3 install --upgrade jupyter_core jupyter_client
python -m ipykernel install --user --name=envmegrapt



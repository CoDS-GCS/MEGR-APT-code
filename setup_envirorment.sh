#!/bin/sh
echo "create virtual environment and pip install requirements"
sudo apt-get install gcc libpq-dev
apt-get install python3.8 python3.8-dev python3.8-distutils python3.8-venv
sudo apt-get install graphviz graphviz-dev
apt install htop screen nano vim git
apt install python3-virtualenv
virtualenv --python=python3.8 envmegrapt
source envmegrapt/bin/activate
pip3 install -r requirements.txt
pip3 install -r torch_requirements.txt

echo "install jupyter and export environment"
pip3 install jupyterlab
pip3 install --upgrade jupyter_core jupyter_client
python -m ipykernel install --user --name=envmegrapt

echo "setup stardog"

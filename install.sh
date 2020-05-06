#!/bin/sh
# Install dependencies and download D&C-Clustering-poc to $HOME

sudo apt-get update
sudo apt-get install -y gcc cmake python3 python3-pip python-dev unzip clamav libclamunrar9
sudo pip3 install filetype pillow pefile

currentDir=$(pwd)
mkdir $HOME/.dac-tools
cd $HOME/.dac-tools

echo "Installing DetectItEasy"
wget https://github.com/horsicq/DIE-engine/releases/download/2.05/die_lin64_portable_2.05.tar.gz -O die_lin64_portable.tar.gz
gzip -d die_lin64_portable.tar.gz
tar -xf die_lin64_portable.tar
rm die_lin64_portable.tar
sudo echo -e '#!/bin/sh' "\n$HOME/.dac-tools/die_lin64_portable/diec.sh " '"$@"' | sudo tee /usr/local/bin/diec
sudo chmod +x /usr/local/bin/diec

echo "Installing tlsh and the tlsh python class"
wget https://github.com/trendmicro/tlsh/archive/master.zip -O master.zip
unzip master.zip
cd tlsh-master
./make.sh
cd py_ext/
python3 ./setup.py build
sudo python3 ./setup.py install

cd $HOME/.dac-tools
echo "Installing pefile-extract-icon python class"
git clone https://github.com/ntnu-rgb/pefile-extract-icon.git
cd pefile-extract-icon
sudo python3 setup.py install

echo "Installing ClamAV"
sudo service clamav-freshclam stop
sudo systemctl disable clamav-freshclam
sudo rm /var/lib/clamav/*
sudo echo -e "rule pass\n{\n\tcondition:\n\t\tfalse\n}" | sudo tee /var/lib/clamav/pass.yar

cd $HOME
git clone git@github.com:57ur14/divide-and-conquer-poc.git
cd divide-and-conquer-poc
cp example-config.ini config.ini
# Generate a random 32-character key
key=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)
echo "key = $key" >> config.ini
echo "Please edit config.ini to suit your preferences"

cd $currentDir

#!/bin/sh
# Install dependencies and download DAC-clustering-PoC to current working directory

sudo apt-get update
sudo apt-get install -y gcc cmake python3 python3-pip python-dev unzip clamav libclamunrar9
pip3 install --user filetype pillow pefile

# Install DetectItEasy to $HOME/.bin/die_lin64_portable/
mkdir -p $HOME/.bin/
wget https://github.com/horsicq/DIE-engine/releases/download/2.05/die_lin64_portable_2.05.tar.gz -O die_lin64_portable.tar.gz
gzip -d die_lin64_portable.tar.gz
tar -xf die_lin64_portable.tar -C $HOME/.bin/
rm die_lin64_portable.tar
# "diec" (DetectItEasy console) must be located in a $PATH directory.
sudo echo -e '#!/bin/sh' "\n$HOME/.bin/die_lin64_portable/diec.sh " '"$@"' | sudo tee /usr/local/bin/diec
sudo chmod +x /usr/local/bin/diec

# Install TLSH with the TLSH Python module to $HOME/.bin/tlsh-master/
wget https://github.com/trendmicro/tlsh/archive/master.zip -O master.zip
unzip master.zip -d $HOME/.bin/
$HOME/.bin/tlsh-master/make.sh
python3 $HOME/.bin/tlsh-master/py_ext/setup.py build
python3 $HOME/.bin/tlsh-master/py_ext/setup.py install --user

# Install pefile-extract-icon
git clone https://github.com/ntnu-rgb/pefile-extract-icon.git
python3 ./pefile-extract-icon/setup.py install --user

# Disable the ClamAV service, delete signature database and create an empty one
sudo service clamav-freshclam stop
sudo systemctl disable clamav-freshclam
sudo rm /var/lib/clamav/*
sudo echo -e "rule pass\n{\n\tcondition:\n\t\tfalse\n}" | sudo tee /var/lib/clamav/pass.yar

# Clone this repo
git clone https://github.com/57ur14/DAC-clustering-PoC.git
cd DAC-clustering-PoC

# Copy example config
cp example-config.ini config.ini

# Generate a random 32-character key to use for the sockets
key=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)
echo "key = $key" >> config.ini

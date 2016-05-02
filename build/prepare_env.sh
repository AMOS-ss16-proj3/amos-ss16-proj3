#!/bin/bash
set -ue

echo "preparing build environment"
sudo apt-get -qy install wireshark-dev

echo "preparing latest Wireshark soucecode"
wget https://www.wireshark.org/download/src/wireshark-2.0.2.tar.bz2
tar xf wireshark-2.0.2.tar.bz2
mv wireshark-2.0.2 wireshark

echo "copying plugin-source to wireshark directory"
cp -R ./src/plugins/doip ./wireshark/plugins/doip/ 

echo "configuring wireshark environment"
cp -R ./src/plugins/Custom.* ./wireshark/plugins/
cd ./wireshark && bash ./autogen.sh && cd ~-
cd ./wireshark && ./configure --enable-wireshark=no && cd ~-


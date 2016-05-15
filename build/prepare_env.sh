#!/bin/bash
set -ue

echo "preparing build environment"
if  ! command -v wireshark > /dev/null
then
    sudo apt-get -qy install wireshark-dev
fi

echo "preparing latest Wireshark soucecode"
if [ ! -d wireshark ]
then
    if [ ! -f wireshark-2.0.2.tar.bz2 ]
    then
        URL=https://www.wireshark.org/download/src/wireshark-2.0.2.tar.bz2
        wget ${URL}
    fi

    tar xf wireshark-2.0.2.tar.bz2
    mv wireshark-2.0.2 wireshark
fi

echo "copying plugin-source to wireshark directory"
cp -R ./src/plugins/doip/ ./wireshark/plugins/

echo "configuring wireshark environment"
cp -R ./src/plugins/Custom.* ./wireshark/plugins/
cd ./wireshark && bash ./autogen.sh && cd ~-
cd ./wireshark && ./configure --enable-wireshark=no && cd ~-


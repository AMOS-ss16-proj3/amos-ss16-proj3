#!/bin/bash

#
# Copyright 2017 The Open Source Research Group,
#                University of Erlangen-Nürnberg
#
# Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE, Version 3.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.gnu.org/licenses/gpl.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -ue

echo "preparing build environment"
if  ! command -v wireshark > /dev/null
then
    #sudo apt-get -qy install wireshark-dev
    sudo apt-get -qy install autoconf \
        automake \
        autotools-dev \
        cdbs \
        debhelper \
        libglib2.0-dev \
        libpcap0.8-dev \
        libtool \
        omniidl \
        python \
        python-ply \
        python2.7 \
        snacc
fi

echo "preparing latest Wireshark soucecode"
if [ ! -d wireshark1 ]
then
    if [ ! -f wireshark-1.12.11.tar.bz2 ]
    then
        URL=https://www.wireshark.org/download/src/all-versions/wireshark-1.12.11.tar.bz2
        wget ${URL}
    fi

    tar xf wireshark-1.12.11.tar.bz2
    mv wireshark-1.12.11 wireshark1
fi

if [ ! -d wireshark2 ]
then
    if [ ! -f wireshark-2.0.2.tar.bz2 ]
    then
        URL=https://www.wireshark.org/download/src/all-versions/wireshark-2.0.2.tar.bz2
        wget ${URL}
    fi

    tar xf wireshark-2.0.2.tar.bz2
    mv wireshark-2.0.2 wireshark2
fi

echo "copying plugin-source to wireshark directory"
cp -R ./src/plugins/doip/ ./wireshark1/plugins/
cp -R ./src/plugins/doip/ ./wireshark2/plugins/

echo "configuring wireshark environment"
cp -R ./src/plugins/Custom.* ./wireshark1/plugins/
cp -R ./src/plugins/Custom.* ./wireshark2/plugins/
cd ./wireshark1 && bash ./autogen.sh && cd ~-
cd ./wireshark2 && bash ./autogen.sh && cd ~-
cd ./wireshark1 && ./configure --enable-wireshark=no && cd ~-
cd ./wireshark2 && ./configure --enable-wireshark=no && cd ~-
#cd ./wireshark && ./configure --enable-wireshark=no CFLAGS=-DNDEBUG && cd ~-


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


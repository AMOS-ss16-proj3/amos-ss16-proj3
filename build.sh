#!/bin/bash

set -ue

if [ -f ~/.wireshark/plugins/doip.so ]
then
    rm ~/.wireshark/plugins/doip.so
fi

build/prepare_env.sh
build/plugin.sh
build/install_plugin.sh


if [ -f ~/.wireshark/plugins/doip.so ]
then
    echo "SUCCESS"
else
    echo "FAILURE"
fi


#!/bin/bash
set -ue

echo 'preparing docker'
mkdir -p ./docker/plugins

echo 'copying plugin to docker'
cp ./wireshark/plugins/doip/.libs/doip.so ./docker/plugins/




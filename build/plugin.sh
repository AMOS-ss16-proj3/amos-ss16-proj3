#!/bin/bash
set -ue

echo "compiling doip-plugin"
make -C ./wireshark/plugins/doip


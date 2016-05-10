#!/bin/bash
set -ue

mkdir --parents ~/.wireshark/plugins
cp ./wireshark/plugins/doip/.libs/doip.so ~/.wireshark/plugins/


[![Build Status](https://travis-ci.org/AMOS-ss16-proj3/amos-ss16-proj3.svg?branch=master)](https://travis-ci.org/AMOS-ss16-proj3/amos-ss16-proj3)

# amos-ss16-proj3: A Wireshark Plugin for Monitoring In-car Communication

Our objective is to write a [wireshark](https://wireshark.org) plugin which displays [DoIP](https://de.wikipedia.org/wiki/DoIP) network traffic.  
The protocol is defined in ISO 13400-2.

The plugin can be build both for Windows and Linux-based operating systems.
For further details see below

## Linux



### Requirements
- [apt](https://en.wikipedia.org/wiki/Advanced_Packaging_Tool) (if not available, the scripts in section _Compiling_ have to be adapted)

### Compiling
Execute following scripts in this order:
1. clone the project
2. enter the project directory
1. execute *bash build/prepare_env.sh*
2. execute *bash build/plugin.sh*

As a result there will be a shared-object file as ./wireshark/plugins/doip/.libs.

### Install
Copy ./wireshark/plugins/doip/.libs/doip.so to your wireshark plugin directory (e.g. ~/.wireshark/plugins)



## Windows

*TODO*


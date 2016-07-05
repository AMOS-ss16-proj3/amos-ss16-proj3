#!/usr/bin/python

#
# Copyright 2016 The Open Source Research Group,
#                University of Erlangen-Nuernberg
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

import socket

#msg =bytearray([2,0xfd,0x80,1,0,0,0,0,6,0x0e,0x80,0xe4,0,0x3e,0x80])
msg =bytearray([2,0xfd,0,4,0,0,0,0x20,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x17,0x16,0xb4,0xb5,0x2f,0xce,0x0e,0x38,0xb4,0xb5,0x2f,0xce,0x0e,0x38,0
])


client_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_b.bind(("localhost", 13400))

client_a.sendto(msg, ("localhost", 13400))


data, addr = server_b.recvfrom(1024)
print "receiving at: ", addr
srcport = addr[1]

client_a.close()
server_b.close()

server_a.bind(("localhost", srcport))
client_b.sendto(msg, ("localhost", srcport))

client_b.close()
server_a.close()


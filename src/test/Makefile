

# Copyright 2016 The Open Source Research Group,
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

CFLAGS = `pkg-config --cflags glib-2.0`
W = -Wall -Werror
MOCKDIR = ./mock
PLUGINDIR = ../plugins/doip
HEADER_DIRS = -I. -I$(MOCKDIR)

CC = gcc $(W) $(CFLAGS) $(HEADER_DIRS) -g

BIN = ./bin

CUNIT = -lcunit

RM = rm -rf

all: $(BIN)/doip-test

clean: ; \
    $(RM) tvbuff.o tvbmock.o doip-header.o test-doip-header.o $(BIN)/doip-test

$(BIN): ; \
    mkdir --parents $(BIN)

tvbuff.o: $(MOCKDIR)/epan/tvbuff.c $(MOCKDIR)/epan/tvbuff.h ; \
    $(CC) -c $(MOCKDIR)/epan/tvbuff.c -o $@

tvbmock.o: tvbuff.o $(MOCKDIR)/tvb-mock.c $(MOCKDIR)/tvb-mock.h ; \
    $(CC) -c $(MOCKDIR)/tvb-mock.c -o $@

doip-header.o: $(PLUGINDIR)/doip-header.c $(PLUGINDIR)/doip-header.h ; \
    $(CC) -c $(PLUGINDIR)/doip-header.c -o $@

test: tvbuff.o doip-header.o tvbmock.o test.c; \
    $(CC) $^ -o $@

test-doip-header.o: test-doip-header.c ; \
    $(CC) -c $(CUNIT) $^ -o $@

$(BIN)/doip-test: $(BIN) doip-test.c doip-header.o test-doip-header.o tvbuff.o tvbmock.o  ; \
    $(CC) doip-test.c doip-header.o test-doip-header.o tvbuff.o tvbmock.o $(CUNIT) -o $@


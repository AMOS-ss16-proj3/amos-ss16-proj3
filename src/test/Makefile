
CFLAGS = `pkg-config --cflags glib-2.0`
W = -Wall -Werror
MOCKDIR = ./mock
PLUGINDIR = ../plugins/doip
HEADER_DIRS = -I. -I$(MOCKDIR)

CC = gcc $(W) $(CFLAGS) $(HEADER_DIRS) -g

CUNIT = -lcunit

RM = rm -rf

all: doip-test

clean: ; \
    $(RM) tvbuff.o tvbmock.o doip-header.o test-doip-header.o doip-test

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

doip-test: doip-test.c doip-header.o test-doip-header.o tvbuff.o tvbmock.o  ; \
    $(CC) $(CUNIT) doip-test.c doip-header.o test-doip-header.o tvbuff.o tvbmock.o  -o $@


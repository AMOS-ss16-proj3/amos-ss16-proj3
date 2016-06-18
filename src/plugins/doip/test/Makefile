
CFLAGS = `pkg-config --cflags glib-2.0`
W = -Wall -Werror
CC = gcc $(W) $(CFLAGS) -g
MOCKDIR = ./mock

RM = rm -rf

all: test

clean: ; \
    $(RM) ./test $(MOCKDIR)tvbuff.o $(MOCKDIR)/tvbmock.o

$(MOCKDIR)/tvbuff.o: $(MOCKDIR)/epan/tvbuff.c $(MOCKDIR)/epan/tvbuff.h ; \
    $(CC) -c $(MOCKDIR)/epan/tvbuff.c -o $@

$(MOCKDIR)/tvbmock.o: $(MOCKDIR)/tvbuff.o $(MOCKDIR)/tvb-mock.c $(MOCKDIR)/tvb-mock.h ; \
    $(CC) -c $(MOCKDIR)/tvb-mock.c -I$(MOCKDIR) -o $@

doip-header.o: doip-header.c doip-header.h ; \
    $(CC) -c doip-header.c -I$(MOCKDIR) -o $@

test: $(MOCKDIR)/tvbuff.o doip-header.o $(MOCKDIR)/tvbmock.o test.c; \
    $(CC) $^ -I$(MOCKDIR) -o $@





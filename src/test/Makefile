
CFLAGS = `pkg-config --cflags glib-2.0`
W = -Wall -Werror
MOCKDIR = ./mock
HEADER_DIRS = -I. -I$(MOCKDIR)

CC = gcc $(W) $(CFLAGS) $(HEADER_DIRS) -g

CUNIT = -lcunit

RM = rm -rf

all: test-doip-header

clean: ; \
    $(RM) ./test tvbuff.o tvbmock.o

tvbuff.o: $(MOCKDIR)/epan/tvbuff.c $(MOCKDIR)/epan/tvbuff.h ; \
    $(CC) -c $(MOCKDIR)/epan/tvbuff.c -o $@

tvbmock.o: tvbuff.o $(MOCKDIR)/tvb-mock.c $(MOCKDIR)/tvb-mock.h ; \
    $(CC) -c $(MOCKDIR)/tvb-mock.c -o $@

doip-header.o: doip-header.c doip-header.h ; \
    $(CC) -c doip-header.c -o $@


test: tvbuff.o doip-header.o tvbmock.o test.c; \
    $(CC) $^ -o $@

test-doip-header: test-doip-header.c doip-header.o tvbuff.o tvbmock.o  ; \
    $(CC) $(CUNIT) $^ -o $@

#gcc test-doip-header.c -I./mock `pkg-config --cflags glib-2.0` ./doip-header.o ./mock/tvbuff.o ./mock/tvbmock.o -lcunit -g


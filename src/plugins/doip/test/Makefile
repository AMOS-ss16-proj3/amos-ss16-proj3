
CFLAGS = `pkg-config --cflags glib-2.0`
CC = gcc -Wall -Werror $(CFLAGS)
MOCKDIR = ./mock


all: test

tvbuff.o: $(MOCKDIR)/epan/tvbuff.c $(MOCKDIR)/epan/tvbuff.h ; \
    $(CC) -c $(MOCKDIR)/epan/tvbuff.c -o $(MOCKDIR)/$@

test: $(MOCKDIR)/tvbuff.o test.c; \
    $(CC) $^ -I$(MOCKDIR) -o $@




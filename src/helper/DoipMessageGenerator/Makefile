
#COMPILER  = /local/java-1.8/bin/javac
COMPILER = javac
DEBUG = -g
RM = rm -rf

SRCDIR = src
PACKAGE = amos/doip/helper
BINDIR = bin

SRCFILES = $(SRCDIR)/$(PACKAGE)/*.java 

all: ; \
    $(COMPILER) $(DEBUG) -sourcepath $(SRCDIR) -d $(BINDIR) $(SRCFILES)

clean: ; \
    $(RM) $(BINDIR)/*





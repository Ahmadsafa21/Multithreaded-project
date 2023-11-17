CC = gcc
DEBUG = -g
DEFINES = 
CFLAGS = $(DEBUG)	-Wextra -Wshadow -Wunreachable-code \
					-Wredundant-decls -Wmissing-declarations \
					-Wold-style-definition -Wmissing-prototypes \
					-Wdeclaration-after-statement -Wno-return-local-addr \
					-Wunsafe-loop-optimizations -Wuninitialized \
					-Wno-unused-parameter $(DEFINES)
PROG1 = thread_crypt
PROG2 = 
PROG3 = 
PROG4 = 
PROGS = $(PROG1) $(PROG2) $(PROG3) $(PROG4)

INCLUDES = thread_crypt.h

all : $(PROGS)

$(PROG1): $(PROG1).o
	$(CC) $(CFLAGS) -o $@ $^

$(PROG1).o: $(PROG1).c $(INCLUDES)
	$(CC) $(CFLAGS) -c $<

clean cls:
	rm -f $(PROGS) *.o *~ \#*

tar:
	tar cvfa thread_crypt_${LOGNAME}.tar.gz *.[ch] [mM]akefile

git get gat:
	if [ ! -d .git ] ; then git init; fi
	git add *.[ch] ?akefile
	git commit -m"git on with it"

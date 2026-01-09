CC=gcc
INCDIRS=-I.
OPT=-O0
CFLAGS=-Wall -Wextra -g -pthread $(INCDIRS) $(OPT)
LDLIBS=-lm


CFILES=ping.c traceroute.c  discovery.c
OBJECTS=ping.o traceroute.o discovery.o

BINARY=myping mytrace mydiscovery
.PHONY: all clean
all: $(BINARY)

myping: ping.o
	$(CC) $(CFLAGS) -o myping ping.o $(LDLIBS)

mytrace: traceroute.o
	$(CC) $(CFLAGS) -o traceroute traceroute.o $(LDLIBS)

mydiscovery: discovery.o
	$(CC) $(CFLAGS) -o discovery discovery.o $(LDLIBS)
%.o:%.c 
	$(CC) $(CFLAGS) -c -o $@ $^ $(LDLIBS)



clean:
	rm -rf $(BINARY) $(OBJECTS)
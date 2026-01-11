CC=gcc
INCDIRS=-I.
OPT=-O0
CFLAGS=-Wall -Wextra -g -pthread $(INCDIRS) $(OPT)
LDLIBS=-lm


CFILES=ping.c traceroute.c port_scanning.c discovery.c
OBJECTS=ping.o traceroute.o port_scanning.o discovery.o

BINARY=ping traceroute discovery port_scanning
.PHONY: all clean
all: $(BINARY)

myping: ping.o
	$(CC) $(CFLAGS) -o ping ping.o $(LDLIBS)

mytrace: traceroute.o
	$(CC) $(CFLAGS) -o traceroute traceroute.o $(LDLIBS)

mydiscovery: discovery.o
	$(CC) $(CFLAGS) -o discovery discovery.o $(LDLIBS)

myport_scanning: port_scanning.o
	$(CC) $(CFLAGS) -o port_scanning port_scanning.o $(LDLIBS)

%.o:%.c 
	$(CC) $(CFLAGS) -c -o $@ $^ $(LDLIBS)



clean:
	rm -rf $(BINARY) $(OBJECTS)
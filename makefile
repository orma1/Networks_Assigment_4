CC=gcc
INCDIRS=-I.
OPT=-O0
CFLAGS=-Wall -Wextra -g -pthread $(INCDIRS) $(OPT)
LDLIBS=-lm


CFILES=ping.c
OBJECTS=ping.o

BINARY=myping
.PHONY: all clean traceroute
all: $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o:%.c 
	$(CC) $(CFLAGS) -c -o $@ $^ $(LDLIBS)

traceroute: mytrace
mytrace: traceroute.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -rf $(BINARY) $(OBJECTS)
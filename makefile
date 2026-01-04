CC=gcc
INCDIRS=-I.
OPT=-O0
CFLAGS=-Wall -Wextra -g -pthread $(INCDIRS) $(OPT)
LDLIBS=-lm


CFILES=ping.c
OBJECTS=ping.o

BINARY=myping

all: $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o:%.c 
	$(CC) $(CFLAGS) -c -o $@ $^ $(LDLIBS)

clean:
	rm -rf $(BINARY) $(OBJECTS)
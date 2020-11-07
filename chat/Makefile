###################################################
#
# Makefile
# Simple TCP/IP communication using sockets
#
# Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
#
###################################################

CC = gcc

CRYPTODEVDIR=$(HOME)/cryptodev/cryptodev-linux-1.9

CFLAGS = -Wall -I$(CRYPTODEVDIR)
CFLAGS += -g
# CFLAGS += -O2 -fomit-frame-pointer -finline-functions

LIBS = 

DEPS = socket-common.h crypto.h read-write.h socket-func.h
OBJ = client-server.o crypto.o read-write.o socket-func.o
BINS = client-server

all: $(BINS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LIBS)

client-server: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o *~ $(BINS)

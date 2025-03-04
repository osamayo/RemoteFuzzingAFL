CC=gcc

PREFIX   ?= /usr/local
BIN_PATH  = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH  = $(PREFIX)/share/doc/afl

CFLAGS+=-g
# CFLAGS+=-fsanitize=address
CFLAGS+=-I ../AFL++/include ../AFL++/src/afl-forkserver.c ../AFL++/src/afl-common.c ../AFL++/src/afl-performance.c  ../AFL++/src/afl-sharedmem.c ../AFL++/src/afl-remotefuzzing.c  -DWORD_SIZE_64=1 -DBIN_PATH=\"$(BIN_PATH)\" -DAFL_PATH=\"$(HELPER_PATH)\"
all: client
	

client:	 client.c bitmap.c
	$(CC) $(CFLAGS) -I ../AFL++/include bitmap.c client.c -o client

# server:	testserver.c
# 	$(CC) -I ../AFL++/include ../AFL++/src/afl-remotefuzzing.c testserver.c -o server

clean:
	rm server client

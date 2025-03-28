CC=gcc

PREFIX   ?= /usr/local
BIN_PATH  = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH  = $(PREFIX)/share/doc/afl

CFLAGS+=-g
# CFLAGS+=-fsanitize=address
CFLAGS+=-I ../AFL++/include/  ../AFL++/src/afl-remotefuzzing.c 
all: proxy 

	
proxy: proxy.c 
	$(CC) $(CFLAGS) -m32 -I ../AFL++/include/  proxy.c -o proxy

clean:
	rm *.o proxy serial

CC=gcc

PREFIX   ?= /usr/local
BIN_PATH  = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH  = $(PREFIX)/share/doc/afl

CFLAGS+=-g
# CFLAGS+=-fsanitize=address
CFLAGS+=-I ../AFL++/include/  ../AFL++/src/afl-remotefuzzing.c 
all: proxy serial

	
serial: ./Serial/rs232.c main.c
	$(CC) $(CFLAGS) -I ./Serial/ ./Serial/rs232.c main.c -o serial 

proxy: proxy.c ./Serial/rs232.c
	$(CC) $(CFLAGS) -m32 -I ../AFL++/include/ -I ./Serial ./Serial/rs232.c  proxy.c -o proxy

clean:
	rm *.o proxy serial

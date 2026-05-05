CC       = gcc
CFLAGS   = -Wall -Wextra -Werror -g -O2 -std=c11 -D_GNU_SOURCE
CFLAGS  += $(shell pkg-config --cflags openssl libcurl sqlite3 libcjson libmicrohttpd)
LDFLAGS  = $(shell pkg-config --libs openssl libcurl sqlite3 libcjson libmicrohttpd) -lzstd -lm

COMMON   = src/db.c src/zfs.c src/storage.c src/pipeline.c

all: zep-air zep-air-serve

zep-air: src/main.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

zep-air-serve: src/serve.c src/storage.c src/db.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f zep-air zep-air-serve

.PHONY: all clean

CC       = gcc
CFLAGS   = -Wall -Wextra -Werror -g -O2 -std=c11 -D_GNU_SOURCE
CFLAGS  += $(shell pkg-config --cflags openssl libcurl sqlite3 libcjson libmicrohttpd)
LDFLAGS  = $(shell pkg-config --libs openssl libcurl sqlite3 libcjson libmicrohttpd) -lzstd -lm
SERV_LDFLAGS = $(LDFLAGS) $(shell pkg-config --libs gnutls)

COMMON   = src/db.c src/zfs.c src/storage.c src/pipeline.c src/http.c

all: zep-air zep-air-serve zep-air-admin

zep-air: src/main.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

zep-air-serve: src/serve.c src/storage.c src/db.c src/zstream.c src/auth.c
	$(CC) $(CFLAGS) -o $@ $^ $(SERV_LDFLAGS)

zep-air-admin: src/admin.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f zep-air zep-air-serve zep-air-admin

install: all
	cp zep-air zep-air-serve zep-air-admin /usr/local/bin/

.PHONY: all clean install

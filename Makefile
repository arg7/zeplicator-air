CC       = gcc
CFLAGS   = -Wall -Wextra -Werror -g -O0 -std=c11 -D_GNU_SOURCE -fsanitize=address -fno-omit-frame-pointer -Wno-format-truncation
CFLAGS  += $(shell pkg-config --cflags openssl libcurl sqlite3 libcjson libmicrohttpd)
LDFLAGS  = $(shell pkg-config --libs openssl libcurl sqlite3 libcjson libmicrohttpd) -lzstd -lm -fsanitize=address
SERV_LDFLAGS = $(LDFLAGS) $(shell pkg-config --libs gnutls) -fsanitize=address

ifdef RELEASE
  CFLAGS   := -Wall -Wextra -Werror -g -O2 -std=c11 -D_GNU_SOURCE
  CFLAGS  += $(shell pkg-config --cflags openssl libcurl sqlite3 libcjson libmicrohttpd)
  LDFLAGS  = $(shell pkg-config --libs openssl libcurl sqlite3 libcjson libmicrohttpd) -lzstd -lm
  SERV_LDFLAGS = $(LDFLAGS) $(shell pkg-config --libs gnutls)
endif

COMMON   = src/db.c src/zfs.c src/pipeline.c src/http.c src/audit.c

all: zep-air zep-air-serve zep-air-admin zep-stream-ff

zep-air: src/main.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lutil

zep-air-serve: src/serve.c src/db.c src/zstream.c src/auth.c src/audit.c
	$(CC) $(CFLAGS) -o $@ $^ $(SERV_LDFLAGS)

zep-air-admin: src/admin.c src/db.c src/audit.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

zep-stream-ff: src/stream-ff.c src/audit.c
	$(CC) -Wall -Wextra -Werror -g -O2 -std=c11 -D_GNU_SOURCE -o $@ $^

clean:
	rm -f zep-air zep-air-serve zep-air-admin zep-stream-ff

install: all
	install -m 755 zep-air zep-air-serve zep-air-admin zep-stream-ff /usr/local/bin/

.PHONY: all clean install

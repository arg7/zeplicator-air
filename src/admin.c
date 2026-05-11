/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "common.h"
#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>

static char g_server[512];
static char g_cert_path[ZEP_MAX_PATH];
static char g_key_path[ZEP_MAX_PATH];
static char g_ca_path[ZEP_MAX_PATH];
static char g_key_password[128];
static char g_db_path[ZEP_MAX_PATH];
static int  g_has_server = 0;
static int  g_verbose = 0;

struct curl_buf {
    char *data;
    size_t len;
};

static size_t curl_write_cb(void *ptr, size_t sz, size_t nmemb, void *user) {
    struct curl_buf *buf = (struct curl_buf *)user;
    size_t total = sz * nmemb;
    char *nd = realloc(buf->data, buf->len + total + 1);
    if (!nd) return 0;
    buf->data = nd;
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static CURL *curl_init(struct curl_buf *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, g_cert_path);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, g_key_path);
    curl_easy_setopt(curl, CURLOPT_CAINFO, g_ca_path);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    if (g_key_password[0])
        curl_easy_setopt(curl, CURLOPT_KEYPASSWD, g_key_password);
    if (g_verbose) curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    return curl;
}

/* === WebSocket Client === */

#define WS_MAGIC "258EAFA5-E914-47DA-95CA-5AB5AC88212E"
#define WS_CHUNK (16380)
#define WS_SUBCHUNK (128 * 1024)
#define WS_FRAME_MAX (WS_SUBCHUNK + 14)
#define WS_OP_TEXT  0x01
#define WS_OP_BIN   0x02
#define WS_OP_EOF   0x03
#define WS_OP_EXIT  0x04
#define WS_OP_CLOSE 0x08
#define WS_OP_PING  0x09
#define WS_OP_PONG  0x0A

typedef struct {
    int sock;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
} ws_conn_t;

static size_t ws_build_frame(unsigned char *buf, size_t buf_size,
                              unsigned char opcode, const unsigned char *payload, size_t payload_len) {
    size_t header_len = 2;
    if (payload_len >= 126) header_len += payload_len < 65536 ? 2 : 8;
    if (buf_size < header_len + payload_len) return 0;
    buf[0] = 0x80 | opcode;
    if (payload_len < 126) {
        buf[1] = (unsigned char)payload_len;
    } else if (payload_len < 65536) {
        buf[1] = 126;
        buf[2] = (unsigned char)((payload_len >> 8) & 0xFF);
        buf[3] = (unsigned char)(payload_len & 0xFF);
    } else {
        buf[1] = 127;
        for (int i = 0; i < 8; i++)
            buf[2 + i] = (unsigned char)((payload_len >> (56 - i * 8)) & 0xFF);
    }
    memcpy(buf + header_len, payload, payload_len);
    return header_len + payload_len;
}

static ssize_t ws_ssl_read(ws_conn_t *wc, void *buf, size_t len) {
    if (wc->ssl) {
        int n = SSL_read(wc->ssl, buf, (int)len);
        if (n <= 0 && g_verbose) {
            int err = SSL_get_error(wc->ssl, n);
            fprintf(stderr, "ws: SSL_read error=%d\n", err);
        }
        return n;
    }
    return recv(wc->sock, buf, len, 0);
}

static ssize_t ws_ssl_write(ws_conn_t *wc, const void *buf, size_t len) {
    if (wc->ssl) {
        ssize_t total = 0;
        while ((size_t)total < len) {
            int n = SSL_write(wc->ssl, (const char *)buf + total, (int)(len - (size_t)total));
            if (n <= 0) return total > 0 ? total : -1;
            total += n;
        }
        return total;
    }
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(wc->sock, (const char *)buf + total, len - total, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            return total > 0 ? (ssize_t)total : -1;
        }
        if (n == 0) return total > 0 ? (ssize_t)total : -1;
        total += (size_t)n;
    }
    return (ssize_t)total;
}

static ssize_t ws_recv_frame(ws_conn_t *wc, unsigned char *out, size_t out_size,
                              unsigned char *opcode_out) {
    unsigned char hdr[14];
    ssize_t n = ws_ssl_read(wc, hdr, 2);
    if (g_verbose)
        fprintf(stderr, "ws: recv hdr n=%zd\n", n);
    if (n < 2) return -1;

    uint64_t payload_len = hdr[1] & 0x7F;
    size_t extra = 0;
    if (payload_len == 126) extra = 2;
    else if (payload_len == 127) extra = 8;

    if (extra > 0) {
        n = ws_ssl_read(wc, hdr + 2, extra);
        if (n < (ssize_t)extra) return -1;
        if (payload_len == 126)
            payload_len = (hdr[2] << 8) | hdr[3];
        else {
            payload_len = 0;
            for (int i = 0; i < 8; i++)
                payload_len = (payload_len << 8) | hdr[2 + i];
        }
    }

    if (g_verbose)
        fprintf(stderr, "ws: recv payload_len=%lu\n", (unsigned long)payload_len);
    if (payload_len > out_size) return -1;
    if (payload_len == 0) {
        *opcode_out = hdr[0] & 0x0F;
        return 0;
    }

    ssize_t total = 0;
    while ((size_t)total < payload_len) {
        n = ws_ssl_read(wc, out + total, payload_len - (size_t)total);
        if (n <= 0) return -1;
        total += n;
    }
    *opcode_out = hdr[0] & 0x0F;
    return (ssize_t)payload_len;
}

static int ws_send_frame_ssl(ws_conn_t *wc, unsigned char opcode,
                              const unsigned char *payload, size_t payload_len) {
    unsigned char frame[WS_FRAME_MAX + 14];
    size_t flen = ws_build_frame(frame, sizeof(frame), opcode, payload, payload_len);
    if (flen == 0) return -1;
    return ws_ssl_write(wc, frame, flen) > 0 ? 0 : -1;
}

static ws_conn_t *ws_connect(const char *server_url, const char *path) {
    /* Parse URL: https://host:port */
    int use_tls = 1;
    char host[512] = {0};
    int port = 443;
    const char *scheme = server_url;
    if (strncmp(scheme, "https://", 8) == 0) { scheme += 8; }
    else if (strncmp(scheme, "http://", 7) == 0) { use_tls = 0; port = 80; scheme += 7; }

    const char *colon = strchr(scheme, ':');
    const char *slash = strchr(scheme, '/');
    if (colon && (!slash || colon < slash)) {
        size_t hl = (size_t)(colon - scheme);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, scheme, hl);
        port = atoi(colon + 1);
    } else if (slash) {
        size_t hl = (size_t)(slash - scheme);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, scheme, hl);
    } else {
        size_t sl = strlen(scheme);
        if (sl >= sizeof(host)) sl = sizeof(host) - 1;
        memcpy(host, scheme, sl);
    }

    if (g_verbose)
        fprintf(stderr, "ws: connecting to %s:%d%s (%s)\n", host, port, path,
                use_tls ? "TLS" : "plain");

    /* Resolve host */
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        fprintf(stderr, "ws: cannot resolve %s\n", host);
        return NULL;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return NULL; }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        if (g_verbose) fprintf(stderr, "ws: connect failed\n");
        close(sock); freeaddrinfo(res); return NULL;
    }
    freeaddrinfo(res);

    /* TLS */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    if (use_tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { close(sock); return NULL; }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_use_certificate_file(ctx, g_cert_path, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx); close(sock); return NULL;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, g_key_path, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx); close(sock); return NULL;
        }
        if (g_ca_path[0]) SSL_CTX_load_verify_locations(ctx, g_ca_path, NULL);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            if (g_verbose) fprintf(stderr, "ws: SSL_connect failed\n");
            SSL_free(ssl); SSL_CTX_free(ctx); close(sock); return NULL;
        }
        if (g_verbose) fprintf(stderr, "ws: TLS connected\n");
    }

    /* WebSocket handshake */
    unsigned char key_bytes[16];
    char key_b64[32];
    for (int i = 0; i < 16; i++) key_bytes[i] = (unsigned char)(rand() & 0xFF);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, key_bytes, 16);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    snprintf(key_b64, sizeof(key_b64), "%.*s", (int)(bptr->length - 1), bptr->data);
    BIO_free_all(b64);

    char req[2048];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n", path, host, port, key_b64);

    if (ssl)
        SSL_write(ssl, req, (int)strlen(req));
    else
        send(sock, req, strlen(req), MSG_NOSIGNAL);
    if (g_verbose) fprintf(stderr, "ws: sent handshake request\n");

    /* Read response */
    char resp_buf[1024];
    int resp_len = 0;
    for (;;) {
        int n;
        if (ssl)
            n = SSL_read(ssl, resp_buf + resp_len, sizeof(resp_buf) - resp_len - 1);
        else
            n = (int)recv(sock, resp_buf + resp_len, sizeof(resp_buf) - resp_len - 1, 0);
        if (g_verbose) fprintf(stderr, "ws: read returned %d\n", n);
        if (n <= 0) {
            if (g_verbose) fprintf(stderr, "ws: read error\n");
            if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
            close(sock); return NULL;
        }
        resp_len += n;
        resp_buf[resp_len] = '\0';
        if (strstr(resp_buf, "\r\n\r\n")) break;
        if (resp_len >= (int)sizeof(resp_buf) - 1) break;
    }
    if (g_verbose) fprintf(stderr, "ws: got response: %.*s\n", resp_len, resp_buf);

    if (strstr(resp_buf, "101") == NULL) {
        fprintf(stderr, "ws: handshake failed: %.*s\n", resp_len, resp_buf);
        if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
        close(sock); return NULL;
    }

    ws_conn_t *wc = calloc(1, sizeof(*wc));
    wc->sock = sock;
    wc->ssl = ssl;
    wc->ssl_ctx = ctx;
    return wc;
}

static void ws_close(ws_conn_t *wc) {
    if (!wc) return;
    if (wc->sock >= 0) {
        shutdown(wc->sock, SHUT_WR);
        close(wc->sock);
    }
    if (wc->ssl) SSL_free(wc->ssl);
    if (wc->ssl_ctx) SSL_CTX_free(wc->ssl_ctx);
    free(wc);
}

static int do_post(const char *path, const char *json_body) {
    struct curl_buf resp = {0};
    CURL *curl = curl_init(&resp);
    if (!curl) return 1;

    char *url = NULL;
    if (asprintf(&url, "%s%s", g_server, path) < 0) { curl_easy_cleanup(curl); return 1; }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);

    if (rc != CURLE_OK) {
        fprintf(stderr, "curl error: %s\n", curl_easy_strerror(rc));
        free(resp.data);
        return 1;
    }
    if (http_code != 200) {
        fprintf(stderr, "HTTP %ld: %s\n", http_code, resp.data ? resp.data : "");
        free(resp.data);
        return 1;
    }
    if (resp.data) printf("%s\n", resp.data);
    free(resp.data);
    return 0;
}

static int do_get(const char *path) {
    struct curl_buf resp = {0};
    CURL *curl = curl_init(&resp);
    if (!curl) return 1;

    char *url = NULL;
    if (asprintf(&url, "%s%s", g_server, path) < 0) { curl_easy_cleanup(curl); return 1; }
    curl_easy_setopt(curl, CURLOPT_URL, url);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    free(url);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        fprintf(stderr, "curl error: %s\n", curl_easy_strerror(rc));
        free(resp.data);
        return 1;
    }
    if (http_code != 200) {
        fprintf(stderr, "HTTP %ld\n", http_code);
        free(resp.data);
        return 1;
    }
    if (resp.data) printf("%s\n", resp.data);
    free(resp.data);
    return 0;
}

static int do_delete(const char *path) {
    struct curl_buf resp = {0};
    CURL *curl = curl_init(&resp);
    if (!curl) return 1;

    char *url = NULL;
    if (asprintf(&url, "%s%s", g_server, path) < 0) { curl_easy_cleanup(curl); return 1; }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    free(url);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        fprintf(stderr, "curl error: %s\n", curl_easy_strerror(rc));
        free(resp.data);
        return 1;
    }
    if (http_code != 200) {
        fprintf(stderr, "HTTP %ld\n", http_code);
        free(resp.data);
        return 1;
    }
    if (resp.data) printf("%s\n", resp.data);
    free(resp.data);
    return 0;
}

static char *read_file_str(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[r] = '\0';
    while (r > 0 && (buf[r-1] == '\n' || buf[r-1] == '\r')) buf[--r] = '\0';
    return buf;
}

static int json_escape(const char *src, char *dst, size_t dst_len) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_len - 1; i++) {
        switch (src[i]) {
            case '"':  if (j+1 < dst_len) { dst[j++] = '\\'; dst[j++] = '"';  } break;
            case '\\': if (j+1 < dst_len) { dst[j++] = '\\'; dst[j++] = '\\'; } break;
            case '\n': if (j+1 < dst_len) { dst[j++] = '\\'; dst[j++] = 'n';  } break;
            case '\r': if (j+1 < dst_len) { dst[j++] = '\\'; dst[j++] = 'r';  } break;
            case '\t': if (j+1 < dst_len) { dst[j++] = '\\'; dst[j++] = 't';  } break;
            default:   dst[j++] = src[i]; break;
        }
    }
    dst[j] = '\0';
    return (int)j;
}

static int cmd_join(int argc, char *argv[]) {
    char *role = NULL, *node = NULL, *cert_file = NULL;
    char *cluster = NULL, *map = NULL;

    static struct option opts[] = {
        {"role",    required_argument, 0, 'r'},
        {"node",    required_argument, 0, 'n'},
        {"cert",    required_argument, 0, 'c'},
        {"cluster", required_argument, 0, 'l'},
        {"map",     required_argument, 0, 'm'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "+r:n:c:l:m:", opts, NULL)) != -1) {
        switch (opt) {
            case 'r': role = optarg; break;
            case 'n': node = optarg; break;
            case 'c': cert_file = optarg; break;
            case 'l': cluster = optarg; break;
            case 'm': map = optarg; break;
        }
    }
    if (!role || !node || !cert_file) {
        fprintf(stderr, "Usage: zep-air-admin join --role master|client --node <name> --cert <cert.crt> [--cluster <name>] [--map <mappings>]\n");
        return 1;
    }
    if (strcmp(role, "master") != 0 && strcmp(role, "client") != 0) {
        fprintf(stderr, "Role must be 'master' or 'client'\n");
        return 1;
    }

    char *pem = read_file_str(cert_file);
    if (!pem) return 1;

    char *esc = malloc(strlen(pem) * 2 + 1);
    if (!esc) { free(pem); return 1; }
    json_escape(pem, esc, strlen(pem) * 2 + 1);

    char *map_esc = NULL;
    if (map) {
        map_esc = malloc(strlen(map) * 2 + 1);
        if (map_esc) json_escape(map, map_esc, strlen(map) * 2 + 1);
    }

    char *body = NULL;
    if (asprintf(&body,
        "{\"cn\":\"%s\",\"role\":\"%s\",\"pem\":\"%s\",\"cluster\":\"%s\",\"mapping\":\"%s\"}",
        node, role, esc,
        cluster ? cluster : "",
        map_esc ? map_esc : "") < 0) {
        free(pem); free(esc); free(map_esc); return 1;
    }
    free(pem); free(esc); free(map_esc);

    int rc = do_post("/v1/admin/nodes", body);
    free(body);
    return rc;
}

static int cmd_cluster(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: zep-air-admin cluster <set|get|delete> [args]\n");
        return 1;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "set") == 0) {
        char *file = NULL;
        static struct option opts[] = {
            {"file", required_argument, 0, 'f'},
            {0, 0, 0, 0}
        };
        int opt;
        while ((opt = getopt_long(argc, argv, "f:", opts, NULL)) != -1) {
            if (opt == 'f') file = optarg;
        }
        if (!file) {
            fprintf(stderr, "Usage: zep-air-admin cluster set --file <cluster.json>\n");
            return 1;
        }
        char *json = read_file_str(file);
        if (!json) return 1;
        char *esc = malloc(strlen(json) * 2 + 1);
        if (!esc) { free(json); return 1; }
        json_escape(json, esc, strlen(json) * 2 + 1);
        char *body = NULL;
        if (asprintf(&body, "%s", json) < 0) { free(json); free(esc); return 1; }
        free(json); free(esc);
        int rc = do_post("/v1/admin/clusters", body);
        free(body);
        return rc;
    }

    if (strcmp(sub, "get") == 0) {
        char *name = NULL;
        for (int i = 2; i < argc; i++) {
            if (argv[i][0] != '-') { name = argv[i]; break; }
        }
        char path[512];
        if (name) snprintf(path, sizeof(path), "/v1/admin/clusters/%s", name);
        else snprintf(path, sizeof(path), "/v1/admin/clusters");
        return do_get(path);
    }

    if (strcmp(sub, "delete") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: zep-air-admin cluster delete <name>\n");
            return 1;
        }
        char path[512];
        snprintf(path, sizeof(path), "/v1/admin/clusters/%s", argv[2]);
        return do_delete(path);
    }

    fprintf(stderr, "Unknown cluster subcommand: %s\n", sub);
    return 1;
}

static int cmd_suspend(int argc, char *argv[]) {
    const char *target = "";
    int has_opt = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--master") == 0)  { target = "master"; has_opt = 1; }
        else if (strcmp(argv[i], "--clients") == 0) { target = "clients"; has_opt = 1; }
        else if (strcmp(argv[i], "--node") == 0 && i + 1 < argc) {
            target = argv[++i]; has_opt = 1;
        }
    }
    char path[512];
    if (has_opt) snprintf(path, sizeof(path), "/v1/admin/suspend/%s", target);
    else snprintf(path, sizeof(path), "/v1/admin/suspend");
    return do_get(path);
}

static int cmd_resume(int argc, char *argv[]) {
    const char *target = "";
    int has_opt = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--master") == 0)  { target = "master"; has_opt = 1; }
        else if (strcmp(argv[i], "--clients") == 0) { target = "clients"; has_opt = 1; }
        else if (strcmp(argv[i], "--node") == 0 && i + 1 < argc) {
            target = argv[++i]; has_opt = 1;
        }
    }
    char path[512];
    if (has_opt) snprintf(path, sizeof(path), "/v1/admin/resume/%s", target);
    else snprintf(path, sizeof(path), "/v1/admin/resume");
    return do_get(path);
}

static int cmd_promote(int argc, char *argv[]) {
    const char *node = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--node") == 0 && i + 1 < argc) node = argv[++i];
    }
    if (!node) { fprintf(stderr, "Usage: zep-air-admin promote --node <CN>\n"); return 1; }
    char path[512];
    snprintf(path, sizeof(path), "/v1/admin/promote/%s", node);
    return do_get(path);
}

static int cmd_rollback(int argc, char *argv[]) {
    const char *snap = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--snap") == 0 && i + 1 < argc) snap = argv[++i];
    }
    if (!snap) { fprintf(stderr, "Usage: zep-air-admin rollback --snap <name>\n"); return 1; }
    char path[512];
    snprintf(path, sizeof(path), "/v1/admin/rollback/%s", snap);
    return do_get(path);
}

static int cmd_admin_config(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: zep-air-admin config <list|get|set|rm> [key] [value]\n");
        return 1;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "list") == 0)
        return do_get("/v1/admin/config");

    if (argc < 3) { fprintf(stderr, "Missing key\n"); return 1; }
    const char *key = argv[2];

    if (strcmp(sub, "get") == 0) {
        char path[512];
        snprintf(path, sizeof(path), "/v1/admin/config/%s", key);
        return do_get(path);
    }

    if (strcmp(sub, "set") == 0) {
        if (argc < 4) { fprintf(stderr, "Missing value\n"); return 1; }
        char *esc = malloc(strlen(argv[3]) * 2 + 1);
        if (!esc) return 1;
        json_escape(argv[3], esc, strlen(argv[3]) * 2 + 1);
        char *body = NULL;
        if (asprintf(&body, "{\"value\":\"%s\"}", esc) < 0) { free(esc); return 1; }
        free(esc);
        char path[512];
        snprintf(path, sizeof(path), "/v1/admin/config/%s", key);
        int rc = do_post(path, body);
        free(body);
        return rc;
    }

    if (strcmp(sub, "rm") == 0) {
        char path[512];
        snprintf(path, sizeof(path), "/v1/admin/config/%s", key);
        return do_delete(path);
    }

    fprintf(stderr, "Unknown: %s\n", sub);
    return 1;
}

static int cmd_admin_snap(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: zep-air-admin snap <create|destroy> --name <name>\n");
        return 1;
    }
    const char *sub = argv[1];
    const char *name = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) name = argv[++i];
    }
    if (!name) { fprintf(stderr, "Missing --name\n"); return 1; }
    char path[512];
    if (strcmp(sub, "create") == 0)
        snprintf(path, sizeof(path), "/v1/admin/snap/%s", name);
    else if (strcmp(sub, "destroy") == 0)
        snprintf(path, sizeof(path), "/v1/admin/unsnap/%s", name);
    else { fprintf(stderr, "Unknown: %s\n", sub); return 1; }
    return do_get(path);
}

static ws_conn_t *g_pipe_wc;
static volatile sig_atomic_t g_winch_flag;

static void pipe_winch_handler(int sig) {
    (void)sig;
    g_winch_flag = 1;
}

static void format_size(char *buf, size_t bufsz, uint64_t bytes) {
    const char *units[] = {"B", "K", "M", "G", "T"};
    int ui = 0;
    double v = (double)bytes;
    while (v >= 1024.0 && ui < 4) { v /= 1024.0; ui++; }
    if (ui == 0) snprintf(buf, bufsz, "%lluB", (unsigned long long)bytes);
    else snprintf(buf, bufsz, "%.1f%s", v, units[ui]);
}

static void format_elapsed(char *buf, size_t bufsz, double secs) {
    int m = (int)(secs / 60.0);
    int s = (int)secs % 60;
    snprintf(buf, bufsz, "%02d:%02d", m, s);
}

static int cmd_pipe(int argc, char *argv[]) {
    const char *node = NULL;
    int interactive = 0;
    size_t pipe_chunk = WS_CHUNK;
    int cmd_start = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--node") == 0 && i + 1 < argc)
            node = argv[++i];
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0)
            interactive = 1;
        else if (strcmp(argv[i], "--chunk") == 0 && i + 1 < argc) {
            long val = atol(argv[++i]);
            if (val > 0) pipe_chunk = (size_t)val;
        }
        else if (strcmp(argv[i], "--") == 0) {
            cmd_start = i + 1;
            break;
        } else if (argv[i][0] != '-') {
            cmd_start = i;
            break;
        }
    }

    if (cmd_start < 0 || cmd_start >= argc) {
        fprintf(stderr, "Usage: zep-air-admin pipe [--chunk N] [--node CN] [-i] <command...>\n"
                        "  --chunk N    WS frame payload size in bytes (default: %u)\n"
                        "  --node CN    Target node (default: auto-select)\n"
                        "  -v           Show bandwidth tick and final summary on stderr\n"
                        "  -i, --interactive  Allocate PTY, raw terminal (for shells)\n"
                        "\nExamples:\n"
                        "  zep-air-admin pipe zfs send -R tank-prod/data\n"
                        "  zep-air-admin pipe -i --node foo bash\n"
                        "  zep-air-admin pipe \"zfs send tank/data | zstd -c | mbuffer -q -m 4G\" > backup.zfs\n"
                        "  zfs send tank/data | zstd -c | mbuffer | zep-air-admin pipe \"mbuffer | zstd -d | zfs recv vault/data\"\n", WS_CHUNK);
        return 1;
    }

    char cmd_buf[4096] = {0};
    for (int i = cmd_start; i < argc; i++) {
        if (i > cmd_start) strncat(cmd_buf, " ", sizeof(cmd_buf) - strlen(cmd_buf) - 1);
        strncat(cmd_buf, argv[i], sizeof(cmd_buf) - strlen(cmd_buf) - 1);
    }

    const char *target_node = node;
    if (!target_node) {
        fprintf(stderr, "pipe: --node required for WS pipe\n");
        return 1;
    }

    char ws_path[1024];
    char cmd_encoded[800] = {0};
    int ei = 0;
    for (int ci = 0; cmd_buf[ci] && ei < (int)sizeof(cmd_encoded) - 4; ci++) {
        unsigned char c = (unsigned char)cmd_buf[ci];
        if (c == ' ') { cmd_encoded[ei++] = '+'; }
        else if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') { cmd_encoded[ei++] = c; }
        else { ei += snprintf(cmd_encoded + ei, sizeof(cmd_encoded) - ei, "%%%02X", c); }
    }

    snprintf(ws_path, sizeof(ws_path),
             "/v1/ws/pipe?node=%s&command=%s%s",
             target_node, cmd_encoded,
             interactive ? "&interactive=1" : "");

    if (g_verbose)
        fprintf(stderr, "pipe: opening WebSocket to %s\n", target_node);

    ws_conn_t *wc = ws_connect(g_server, ws_path);
    if (!wc) {
        fprintf(stderr, "pipe: WebSocket connect failed\n");
        return 1;
    }

    /* Interactive terminal setup */
    struct termios orig_term;
    int interactive_tty = 0;
    if (interactive && isatty(STDIN_FILENO)) {
        if (tcgetattr(STDIN_FILENO, &orig_term) == 0) {
            struct termios raw = orig_term;
            cfmakeraw(&raw);
            raw.c_cc[VMIN] = 1;
            raw.c_cc[VTIME] = 0;
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
            interactive_tty = 1;

            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = pipe_winch_handler;
            sigaction(SIGWINCH, &sa, NULL);

            g_pipe_wc = wc;

            struct winsize ws;
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
                char rmsg[128];
                int rlen = snprintf(rmsg, sizeof(rmsg),
                    "{\"action\":\"resize\",\"rows\":%d,\"cols\":%d}", ws.ws_row, ws.ws_col);
                ws_send_frame_ssl(wc, WS_OP_TEXT, (unsigned char *)rmsg, (size_t)rlen);
            }
        }
    }

    /* Full-duplex pipe: stdin→WS, WS→stdout/stderr */
    uint64_t sent = 0, rcvd_stdout = 0, rcvd_stderr = 0;
    int stdin_done = 0;
    int ws_done = 0;
    int remote_exit = 1;
    time_t start_time = time(NULL);

    unsigned char *ws_buf = malloc(WS_FRAME_MAX);
    unsigned char *out = malloc(WS_SUBCHUNK);
    if (!ws_buf || !out) { free(ws_buf); free(out); ws_close(wc); goto pipe_cleanup; }

    unsigned char *inbuf = malloc(pipe_chunk);
    if (!inbuf) { free(ws_buf); free(out); ws_close(wc); goto pipe_cleanup; }

    time_t pipe_start = time(NULL);
    time_t tick_prev = pipe_start;
    uint64_t tick_in_prev = 0, tick_out_prev = 0;

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;
        FD_SET(wc->sock, &rfds); if (wc->sock > maxfd) maxfd = wc->sock;
        if (!stdin_done) { FD_SET(STDIN_FILENO, &rfds); if (STDIN_FILENO > maxfd) maxfd = STDIN_FILENO; }

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        int ssl_pending = (wc->ssl && SSL_pending(wc->ssl) > 0);

        if (sel < 0 && errno != EINTR) break;

        if (g_winch_flag && g_pipe_wc) {
            g_winch_flag = 0;
            struct winsize ws;
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
                char rmsg[128];
                int rlen = snprintf(rmsg, sizeof(rmsg),
                    "{\"action\":\"resize\",\"rows\":%d,\"cols\":%d}", ws.ws_row, ws.ws_col);
                ws_send_frame_ssl(g_pipe_wc, WS_OP_TEXT, (unsigned char *)rmsg, (size_t)rlen);
            }
        }

        if (stdin_done && !ws_done && time(NULL) - start_time > 30) {
            if (g_verbose) fprintf(stderr, "pipe: timeout waiting for remote response\n");
            break;
        }
        if (!stdin_done) start_time = time(NULL);

        if (sel > 0 || ssl_pending) {
            if (!stdin_done && FD_ISSET(STDIN_FILENO, &rfds)) {
                ssize_t nr = read(STDIN_FILENO, inbuf, pipe_chunk);
                if (nr > 0) {
                    if (ws_send_frame_ssl(wc, WS_OP_BIN, inbuf, (size_t)nr) < 0) { ws_done = 1; break; }
                    sent += (uint64_t)nr;
                } else if (nr == 0) {
                    ws_send_frame_ssl(wc, WS_OP_EOF, NULL, 0);
                    stdin_done = 1;
                } else if (errno != EAGAIN) {
                    ws_send_frame_ssl(wc, WS_OP_EOF, NULL, 0);
                    stdin_done = 1;
                }
            }

            if (FD_ISSET(wc->sock, &rfds) || ssl_pending) {
                ssize_t n = ws_recv_frame(wc, out, WS_SUBCHUNK, &ws_buf[0]);
                if (n < 0) { ws_done = 1; break; }
                unsigned char op = ws_buf[0] & 0x0F;
                if (op == WS_OP_CLOSE) { ws_done = 1; break; }
                if (op == WS_OP_PING) {
                    ws_send_frame_ssl(wc, WS_OP_PONG, out, (size_t)n);
                    continue;
                }
                if (op == WS_OP_PONG) continue;
                if (op == WS_OP_BIN) {
                    fwrite(out, 1, (size_t)n, stdout); fflush(stdout);
                    rcvd_stdout += (uint64_t)n;
                }
                if (op == WS_OP_TEXT) {
                    fwrite(out, 1, (size_t)n, stderr); fflush(stderr);
                    rcvd_stderr += (uint64_t)n;
                }
                if (op == WS_OP_EOF) {
                }
                if (op == WS_OP_EXIT && n == 1) {
                    remote_exit = (int)out[0];
                }
            }
        }

        if (g_verbose && !interactive_tty && isatty(STDERR_FILENO)) {
            time_t now = time(NULL);
            if (now > tick_prev) {
                double dt = difftime(now, tick_prev);
                if (dt < 0.1) dt = 0.1;
                uint64_t cur_in = sent + rcvd_stderr;
                uint64_t cur_out = rcvd_stdout;
                char i_sz[32], i_bw[32], o_sz[32], o_bw[32], tel[16];
                format_size(i_sz, sizeof(i_sz), cur_in);
                format_size(i_bw, sizeof(i_bw), (uint64_t)((double)(cur_in - tick_in_prev) / dt));
                format_size(o_sz, sizeof(o_sz), cur_out);
                format_size(o_bw, sizeof(o_bw), (uint64_t)((double)(cur_out - tick_out_prev) / dt));
                format_elapsed(tel, sizeof(tel), difftime(now, pipe_start));
                fprintf(stderr, "\rpipe(%s) [in: %s (%s/s) | out: %s (%s/s)]    ",
                        tel, i_sz, i_bw, o_sz, o_bw);
                fflush(stderr);
                tick_in_prev = cur_in;
                tick_out_prev = cur_out;
                tick_prev = now;
            }
        }

        if (ws_done) break;
    }

    free(inbuf);
    free(ws_buf); free(out);

    /* Send CLOSE to server (only if server didn't close first) */
    if (!ws_done) {
        ws_send_frame_ssl(wc, WS_OP_CLOSE, NULL, 0);
        usleep(100000);
    }
    ws_close(wc);

    if (g_verbose) {
        double elapsed = difftime(time(NULL), pipe_start);
        if (elapsed < 0.1) elapsed = 0.1;
        uint64_t cur_in = sent + rcvd_stderr;
        uint64_t cur_out = rcvd_stdout;
        char i_sz[32], i_bw[32], o_sz[32], o_bw[32], tel[16];
        format_size(i_sz, sizeof(i_sz), cur_in);
        format_size(i_bw, sizeof(i_bw), (uint64_t)((double)cur_in / elapsed));
        format_size(o_sz, sizeof(o_sz), cur_out);
        format_size(o_bw, sizeof(o_bw), (uint64_t)((double)cur_out / elapsed));
        format_elapsed(tel, sizeof(tel), elapsed);
        fprintf(stderr, "\rpipe(%s) [in: %s (%s/s) | out: %s (%s/s)] exit: %d\n",
                tel, i_sz, i_bw, o_sz, o_bw, remote_exit);
    }

pipe_cleanup:
    if (interactive_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_term);
        g_pipe_wc = NULL;
    }
    return remote_exit;
}

static int cmd_list_nodes(int argc, char *argv[]) {
    (void)argc; (void)argv;
    return do_get("/v1/admin/nodes");
}

static int cmd_remove_node(int argc, char *argv[]) {
    if (argc < 1) {
        fprintf(stderr, "Usage: zep-air-admin remove-node <cn>\n");
        return 1;
    }
    char path[1024];
    snprintf(path, sizeof(path), "/v1/admin/nodes/%s", argv[1]);
    return do_delete(path);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "zep-air-admin v%s — Zep Air cluster administrator\n"
        "\n"
        "Usage: %s <command> [options]\n"
        "\n"
        "Commands:\n"
        "  cluster      Manage cluster definitions\n"
        "  join         Register a master or client node\n"
        "  list-nodes   List registered nodes\n"
        "  remove-node  Remove a node\n"
        "  suspend      Pause replication (--master, --clients, --node)\n"
        "  resume       Resume replication\n"
        "  promote      Promote client to master (--node CN)\n"
        "  rollback     Cluster rollback to snapshot (--snap NAME)\n"
        "  pipe         Full-duplex pipe through the server (stdin/stdout/stderr → node)\n"
        "  snap         Manual snapshot create/destroy (--name NAME)\n"
        "  config       Server config get/set/list/rm\n"
        "\n"
        "Global options:\n"
        "  --server, -s URL   Server URL (default: https://master.zep.lan:8443)\n"
        "  --cert, -c FILE    Admin client certificate (PEM)\n"
        "  --key, -k FILE     Admin client key (PEM)\n"
        "  --ca, -C FILE      CA certificate (PEM)\n"
        "  --db, -d FILE      Local config DB (reads server/cert/key/ca defaults)\n"
        "  --password, -P PASS  Password for encrypted key\n"
        "  --verbose, -v      Verbose output\n"
        "\n"
        "Join options:\n"
        "  --role master|client  Node role\n"
        "  --node NAME           Node CN (must match cert CN)\n"
        "  --cert FILE           Node certificate (PEM)\n",
        ZEP_VERSION, prog);
}

int main(int argc, char *argv[]) {
    const char *argv2[64];
    int argc2 = 0;

    for (int i = 0; i < argc && argc2 < 63; i++) {
        if (strcmp(argv[i], "join") == 0 ||
            strcmp(argv[i], "list-nodes") == 0 ||
            strcmp(argv[i], "remove-node") == 0 ||
            strcmp(argv[i], "cluster") == 0 ||
            strcmp(argv[i], "suspend") == 0 ||
            strcmp(argv[i], "resume") == 0 ||
            strcmp(argv[i], "promote") == 0 ||
            strcmp(argv[i], "rollback") == 0 ||
            strcmp(argv[i], "snap") == 0 ||
            strcmp(argv[i], "pipe") == 0 ||
            strcmp(argv[i], "config") == 0) {
            argv2[argc2++] = argv[i];
            for (int j = i + 1; j < argc && argc2 < 63; j++)
                argv2[argc2++] = argv[j];
            break;
        }
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            snprintf(g_server, sizeof(g_server), "%s", argv[++i]);
            g_has_server = 1;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            snprintf(g_server, sizeof(g_server), "%s", argv[++i]);
            g_has_server = 1;
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            snprintf(g_cert_path, sizeof(g_cert_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            snprintf(g_cert_path, sizeof(g_cert_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            snprintf(g_key_path, sizeof(g_key_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            snprintf(g_key_path, sizeof(g_key_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            snprintf(g_ca_path, sizeof(g_ca_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-C") == 0 && i + 1 < argc) {
            snprintf(g_ca_path, sizeof(g_ca_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            snprintf(g_key_password, sizeof(g_key_password), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
            snprintf(g_key_password, sizeof(g_key_password), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            snprintf(g_db_path, sizeof(g_db_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            snprintf(g_db_path, sizeof(g_db_path), "%s", argv[++i]);
        } else {
            argv2[argc2++] = argv[i];
        }
    }
    argv2[argc2] = NULL;

    if (g_db_path[0]) {
        sqlite3 *db = NULL;
        if (sqlite3_open(g_db_path, &db) == SQLITE_OK && db) {
            char buf[ZEP_MAX_PATH] = {0};
            if (!g_has_server){if (db_config_get(db, "server_url", buf, sizeof(buf)) == ZEP_ERR_OK) snprintf(g_server,   sizeof(g_server),   "%s", buf); }
            if (!g_cert_path[0]){if (db_config_get(db, "cert_path",  buf, sizeof(buf)) == ZEP_ERR_OK) snprintf(g_cert_path, sizeof(g_cert_path), "%s", buf); }
            if (!g_key_path[0]){if (db_config_get(db, "key_path",   buf, sizeof(buf)) == ZEP_ERR_OK) snprintf(g_key_path,  sizeof(g_key_path),  "%s", buf); }
            if (!g_ca_path[0]){if (db_config_get(db, "ca_path",    buf, sizeof(buf)) == ZEP_ERR_OK) snprintf(g_ca_path,   sizeof(g_ca_path),   "%s", buf); }
            if (!g_key_password[0]){if(db_config_get(db, "key_password",buf,sizeof(buf))==ZEP_ERR_OK)snprintf(g_key_password,sizeof(g_key_password),"%s",buf);}
            sqlite3_close(db);
        }
    }
    if (!g_server[0])
        snprintf(g_server, sizeof(g_server), "https://master.zep.lan:8443");

    if (argc2 < 2) { usage(argv2[0]); return 1; }

    const char *cmd = argv2[1];
    char **sub_argv = (char **)argv2 + 1;
    int sub_argc = argc2 - 1;

    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage(argv2[0]); return 0;
    }
    if (!g_cert_path[0] || !g_key_path[0] || !g_ca_path[0]) {
        if (!g_cert_path[0] || !g_ca_path[0]) {
            fprintf(stderr, "error: --cert and --ca are required\n");
            return 1;
        }
        if (!g_key_path[0])
            snprintf(g_key_path, sizeof(g_key_path), "%s", g_cert_path);
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    int rc = 1;
    if (strcmp(cmd, "join") == 0)   rc = cmd_join(sub_argc, sub_argv);
    else     if (strcmp(cmd, "suspend") == 0)  rc = cmd_suspend(sub_argc, sub_argv);
    else if (strcmp(cmd, "resume") == 0)   rc = cmd_resume(sub_argc, sub_argv);
    else if (strcmp(cmd, "promote") == 0)  rc = cmd_promote(sub_argc, sub_argv);
    else if (strcmp(cmd, "rollback") == 0) rc = cmd_rollback(sub_argc, sub_argv);
    else if (strcmp(cmd, "pipe") == 0)     rc = cmd_pipe(sub_argc, sub_argv);
    else if (strcmp(cmd, "snap") == 0)     rc = cmd_admin_snap(sub_argc, sub_argv);
    else if (strcmp(cmd, "config") == 0)   rc = cmd_admin_config(sub_argc, sub_argv);
    else if (strcmp(cmd, "cluster") == 0)  rc = cmd_cluster(sub_argc, sub_argv);
    else if (strcmp(cmd, "list-nodes") == 0) rc = cmd_list_nodes(sub_argc, sub_argv);
    else if (strcmp(cmd, "remove-node") == 0) rc = cmd_remove_node(sub_argc, sub_argv);
    else { fprintf(stderr, "Unknown command: %s\n", cmd); usage(argv2[0]); }

    curl_global_cleanup();
    return rc;
}

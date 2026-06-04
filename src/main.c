/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "common.h"
#include "db.h"
#include "zfs.h"
#include "pipeline.h"
#include "http.h"
#include "audit.h"
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <pty.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <pthread.h>

static char g_db_path[ZEP_MAX_PATH] = "zep-air.db";
static pthread_t g_ws_tid;
static volatile int g_daemon_running = 1;
static volatile sig_atomic_t g_ws_shutdown = 0;
static volatile sig_atomic_t g_ws_exited = 0;

static void daemon_signal_handler(int sig) {
    (void)sig;
    g_daemon_running = 0;
    g_ws_shutdown = 1;
}

static void ws_sigterm_handler(int sig) {
    (void)sig;
    g_ws_shutdown = 1;
}

/* === WebSocket Pipe Client (node side) === */

#define WS_NODE_MAGIC "258EAFA5-E914-47DA-95CA-5AB5AC88212E"
#define WS_NODE_FRAME_MAX (128 * 1024)
#define WS_NODE_OP_TEXT  0x01
#define WS_NODE_OP_BIN   0x02
#define WS_NODE_OP_EOF   0x03
#define WS_NODE_OP_EXIT  0x04
#define WS_NODE_OP_CLOSE 0x08
#define WS_NODE_OP_PING  0x09
#define WS_NODE_OP_PONG  0x0A

int g_resume_req_pipe[2] = {-1, -1};
int g_resume_resp_pipe[2] = {-1, -1};
static pthread_mutex_t g_resume_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
    char guid[ZEP_MAX_GUID_LEN];
    char token[ZEP_MAX_LINE];
    char fs[ZEP_MAX_PATH];
    int ready;
} g_resume_req;

int g_pull_ws_req_pipe[2] = {-1, -1};
int g_pull_ws_resp_pipe[2] = {-1, -1};
static pthread_mutex_t g_pull_ws_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
    char guid[ZEP_MAX_GUID_LEN];
    char local_guid[ZEP_MAX_GUID_LEN];
    char fs[ZEP_MAX_PATH];
    int ready;
} g_pull_ws_req;

int g_push_ws_req_pipe[2] = {-1, -1};
int g_push_ws_resp_pipe[2] = {-1, -1};
static pthread_mutex_t g_push_ws_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
    char guid[ZEP_MAX_GUID_LEN];
    char base_guid[ZEP_MAX_GUID_LEN];
    char snapshot[ZEP_MAX_SNAPSHOT_NAME];
    char label[64];
    char cluster_fs[512];
    uint64_t stream_size;
    char resume_token[ZEP_MAX_LINE];
    int ready;
} g_push_ws_req;

struct ws_node_conn {
    int sock;
    SSL *ssl;
};

static int ws_node_read(struct ws_node_conn *c, void *buf, int len) {
    if (c->ssl) return SSL_read(c->ssl, buf, len);
    return (int)recv(c->sock, buf, (size_t)len, 0);
}

static int ws_node_write(struct ws_node_conn *c, const void *buf, int len) {
    if (c->ssl) return SSL_write(c->ssl, buf, len);
    ssize_t n = send(c->sock, buf, (size_t)len, MSG_NOSIGNAL);
    return (int)n;
}

static void ws_node_disconnect(struct ws_node_conn *c) {
    if (!c) return;
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->sock >= 0) { close(c->sock); c->sock = -1; }
}

static size_t ws_node_build_frame(unsigned char *buf, size_t buf_size,
                                    unsigned char opcode, const unsigned char *payload, size_t payload_len) {
    size_t header_len = 2 + 4; /* 2 byte header + 4 byte mask */
    if (payload_len >= 126) header_len += payload_len < 65536 ? 2 : 8;
    if (buf_size < header_len + payload_len) return 0;
    buf[0] = 0x80 | opcode;
    if (payload_len < 126) {
        buf[1] = 0x80 | (unsigned char)payload_len;
    } else if (payload_len < 65536) {
        buf[1] = 0x80 | 126;
        buf[2] = (unsigned char)((payload_len >> 8) & 0xFF);
        buf[3] = (unsigned char)(payload_len & 0xFF);
    } else {
        buf[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++)
            buf[2 + i] = (unsigned char)((payload_len >> (56 - i * 8)) & 0xFF);
    }
    size_t mask_offset = header_len - 4;
    unsigned char mask[4];
    for (int i = 0; i < 4; i++) mask[i] = (unsigned char)(rand() % 256);
    memcpy(buf + mask_offset, mask, 4);
    for (size_t i = 0; i < payload_len; i++)
        buf[header_len + i] = payload[i] ^ mask[i % 4];
    return header_len + payload_len;
}

static const char *ws_opname(unsigned char op) {
    switch (op) {
        case WS_NODE_OP_PING: return "PING";
        case WS_NODE_OP_PONG: return "PONG";
        case WS_NODE_OP_CLOSE: return "CLOSE";
        case WS_NODE_OP_TEXT: return "TEXT";
        case WS_NODE_OP_BIN:  return "BIN";
        case WS_NODE_OP_EOF:  return "EOF";
        case WS_NODE_OP_EXIT: return "EXIT";
        default: return "???";
    }
}

static ssize_t ws_node_recv_frame(struct ws_node_conn *c, unsigned char *out, size_t out_size,
                                   unsigned char *opcode_out) {
    unsigned char hdr[14];
    int n = ws_node_read(c, hdr, 2);
    if (n < 2) return -1;

    uint64_t payload_len = hdr[1] & 0x7F;
    size_t extra = 0;
    if (payload_len == 126) extra = 2;
    else if (payload_len == 127) extra = 8;

    if (extra > 0) {
        n = ws_node_read(c, hdr + 2, (int)extra);
        if (n < (int)extra) return -1;
        if (payload_len == 126)
            payload_len = (hdr[2] << 8) | hdr[3];
        else {
            payload_len = 0;
            for (int i = 0; i < 8; i++)
                payload_len = (payload_len << 8) | hdr[2 + i];
        }
    }

    if (payload_len > out_size) return -1;
    if (payload_len == 0) {
        *opcode_out = hdr[0] & 0x0F;
        if ((*opcode_out) == WS_NODE_OP_PING || (*opcode_out) == WS_NODE_OP_PONG) {
            zep_log_debug( "ws-node: RX %s (%02x) 0B\n", ws_opname(*opcode_out), *opcode_out);
        }
        return 0;
    }

    ssize_t total = 0;
    while ((size_t)total < payload_len) {
        n = ws_node_read(c, out + total, (int)(payload_len - (size_t)total));
        if (n <= 0) return -1;
        total += n;
    }
    *opcode_out = hdr[0] & 0x0F;
    if ((*opcode_out) == WS_NODE_OP_PING || (*opcode_out) == WS_NODE_OP_PONG) {
        zep_log_debug( "ws-node: RX %s (%02x) %zuB\n", ws_opname(*opcode_out), *opcode_out, (size_t)payload_len);
    }
    return (ssize_t)payload_len;
}

static int ws_node_send_frame(struct ws_node_conn *c, unsigned char opcode,
                               const unsigned char *payload, size_t payload_len) {
    unsigned char frame[WS_NODE_FRAME_MAX + 14];
    size_t flen = ws_node_build_frame(frame, sizeof(frame), opcode, payload, payload_len);
    if (flen == 0) { zep_log( "ws-node: build_frame failed\n"); return -1; }
    int ret = ws_node_write(c, frame, (int)flen);
    zep_log_debug( "ws-node: TX %s (%02x) %zuB\n",
        ws_opname(opcode), opcode, flen);
    if (ret <= 0) {
        zep_log( "ws-node: write error errno=%d\n", errno);
        return -1;
    }
    return 0;
}

static int ws_node_connect(struct ws_node_conn *c, const char *server_url, const char *cert_path,
                              const char *key_path, const char *ca_path,
                              const char *key_password, const char *path) {
    if (!c) return -1;
    memset(c, 0, sizeof(*c));
    c->sock = -1;
    int use_tls = 0;
    char host[512] = {0};
    int port = 80;
    const char *scheme = server_url;
    if (strncmp(scheme, "https://", 8) == 0) { use_tls = 1; port = 443; scheme += 8; }
    else if (strncmp(scheme, "http://", 7) == 0) { scheme += 7; }

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

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return -1; }
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    { struct timeval tv = { .tv_sec = 90, .tv_usec = 0 }; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }

    c->sock = sock;

    SSL_CTX *ssl_ctx = NULL;
    if (use_tls) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) { ws_node_disconnect(c); return -1; }
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return -1;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return -1;
        }
        if (ca_path && ca_path[0]) SSL_CTX_load_verify_locations(ssl_ctx, ca_path, NULL);
        if (key_password && key_password[0])
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *)key_password);

        c->ssl = SSL_new(ssl_ctx);
        SSL_set_fd(c->ssl, sock);
        if (SSL_connect(c->ssl) <= 0) {
            SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return -1;
        }
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }

    /* WS handshake */
    unsigned char nonce[16];
    for (int i = 0; i < 16; i++) nonce[i] = (unsigned char)(rand() % 256);
    char nonce_b64[32];
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, nonce, 16);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    snprintf(nonce_b64, sizeof(nonce_b64), "%.*s", (int)(bptr->length - 1), bptr->data);
    BIO_free_all(b64);

    char req[2048];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n", path, host, port, nonce_b64);

    if (ws_node_write(c, req, (int)strlen(req)) <= 0) {
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        ws_node_disconnect(c); return -1;
    }

    char resp_buf[1024];
    int resp_len = 0;
    for (;;) {
        int n = ws_node_read(c, resp_buf + resp_len, (int)(sizeof(resp_buf) - resp_len - 1));
        if (n <= 0) { if (ssl_ctx) SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return -1; }
        resp_len += n;
        resp_buf[resp_len] = '\0';
        if (strstr(resp_buf, "\r\n\r\n")) break;
        if (resp_len >= (int)sizeof(resp_buf) - 1) break;
    }

    if (strstr(resp_buf, "101") == NULL) {
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        ws_node_disconnect(c); return -1;
    }

    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    return 0;
}

static void *ws_node_pipe_thread(void *arg);
int pipeline_pull_ws(const zep_config_t *cfg, const http_config_t *http_cfg,
                     const char *fs, const char *donor,
                     const char *remote_guid, const char *local_guid,
                     sqlite3 *db);
int pipeline_push_ws(const zep_config_t *cfg, const char *fs,
                      const char *label, const char *cluster_fs,
                      sqlite3 *db, const char *ext_resume_token);
int pipeline_push_ws_explicit(const zep_config_t *cfg, const char *snap_name,
                               const char *cluster_fs, const char *label,
                               sqlite3 *db, const char *ext_resume_token);

static void *ws_node_pipe_thread(void *arg) {
    zep_config_t *cfg = (zep_config_t *)arg;
    if (!cfg) return NULL;

    char stderr_log[512];
    snprintf(stderr_log, sizeof(stderr_log), "/var/lib/zep-air/home/%s/zep-recv-err.log", cfg->node_name);

    prctl(PR_SET_PDEATHSIG, SIGTERM);

    struct sigaction sa = {0};
    sa.sa_handler = ws_sigterm_handler;
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);

    unsigned char out_buf[WS_NODE_FRAME_MAX];
    unsigned char buf_buf[1];
    unsigned char *out = out_buf;
    unsigned char *buf = buf_buf;

    for (;;) {
        if (g_ws_shutdown) break;
        char ws_path[256];
        snprintf(ws_path, sizeof(ws_path), "/v1/ws/node?cn=%s", cfg->node_name);

        zep_log_debug( "ws-node: connecting to %s%s\n", cfg->server_url, ws_path);

        struct ws_node_conn conn_data;
        struct ws_node_conn *conn = &conn_data;
        if (ws_node_connect(conn, cfg->server_url, cfg->cert_path, cfg->key_path,
                            cfg->ca_path, cfg->key_password, ws_path) != 0) {
            zep_log_debug( "ws-node: connect failed, retrying in 5s\n");
            sleep(5);
            continue;
        }
        /* Send snapshot discovery to server */
        if (cfg->node_name[0] && cfg->cluster[0] && cfg->mapping[0]) {
            /* Collect snapshots for each mapped filesystem */
            cJSON *snaps = cJSON_CreateArray();
            const char *mp = cfg->mapping;
            while (mp && *mp) {
                while (*mp==' '||*mp=='\t') mp++;
                if (!*mp) break;
                const char *colon = strchr(mp, ':');
                if (!colon) break;
                size_t cflen = (size_t)(colon - mp);
                char cfs_buf[512];
                if (cflen >= sizeof(cfs_buf)) cflen = sizeof(cfs_buf) - 1;
                memcpy(cfs_buf, mp, cflen);
                cfs_buf[cflen] = '\0';
                const char *start = colon + 1;
                while (*start==' ') start++;
                const char *end = strchr(start, ',');
                if (!end) end = start + strlen(start);
                const char *paren = strchr(start, '(');
                size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
                char local_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
                memcpy(local_fs, start, n);
                local_fs[n] = '\0';

                /* Get snapshots for this filesystem */
                char cmd[1024];
                snprintf(cmd, sizeof(cmd),
                    "zfs list -Hp -t snap -o name,guid '%s'", local_fs);
                FILE *fp = popen(cmd, "r");
                if (fp) {
                    char line[ZEP_MAX_SNAPSHOT_NAME];
                    char prev_guid[ZEP_MAX_GUID_LEN] = {0};
                    while (fgets(line, sizeof(line), fp)) {
                        size_t sl = strlen(line);
                        while (sl > 0 && (line[sl-1] == '\n' || line[sl-1] == '\r'))
                            line[--sl] = '\0';
                        if (!line[0]) continue;
                        char *at = strchr(line, '@');
                        if (!at) continue;
                        /* Check cluster prefix: snapshot format is fs@cluster-label-ts */
                        size_t clen = strlen(cfg->cluster);
                        if (sl <= clen + 1 || at[1+clen] != '-' || strncmp(at+1, cfg->cluster, clen) != 0)
                            continue;
                        char *d1 = at + 1 + clen;
                        /* d1 points to '-' after cluster name, skip it */
                        if (d1[0] == '-') d1++;
                        char *d2 = strchr(d1, '-');
                        char label[64] = {0};
                        if (d2) {
                            size_t ll = (size_t)(d2 - d1);
                            if (ll >= sizeof(label)) ll = sizeof(label) - 1;
                            memcpy(label, d1, ll);
                            label[ll] = '\0';
                        }
                        /* Skip snapshots without a proper label (cluster must be followed by label then timestamp) */
                        if (!label[0]) continue;
                        /* Validate timestamp format after label: YYYYMMDD-hhmmss */
                        if (d2) {
                            const char *ts = d2 + 1;
                            int ok = 1;
                            for (int i = 0; i < 8 && ok; i++)
                                if (ts[i] < '0' || ts[i] > '9') ok = 0;
                            if (ts[8] != '-') ok = 0;
                            for (int i = 9; i < 15 && ok; i++)
                                if (ts[i] < '0' || ts[i] > '9') ok = 0;
                            if (ts[15] != '\0' && ts[15] != '\t') ok = 0;
                            if (!ok) continue;
                        }
                        char guid[ZEP_MAX_GUID_LEN] = {0};
                        char *tab = strchr(line, '\t');
                        if (tab) {
                            *tab = '\0';
                            snprintf(guid, sizeof(guid), "%s", tab + 1);
                        }
                        if (guid[0]) {
                            cJSON *sn = cJSON_CreateObject();
                            cJSON_AddStringToObject(sn, "guid", guid);
                            cJSON_AddStringToObject(sn, "snapshot", line);
                            cJSON_AddStringToObject(sn, "label", label);
                            cJSON_AddStringToObject(sn, "base_guid", prev_guid);
                            cJSON_AddItemToArray(snaps, sn);
                            snprintf(prev_guid, sizeof(prev_guid), "%s", guid);
                        }
                    }
                    int rc = pclose(fp);
                    audit_log("snap_list", "zfs", cmd,
                        WIFEXITED(rc) ? WEXITSTATUS(rc) : -128);
                }
                /* Move to next mapping */
                const char *comma = strchr(colon, ',');
                mp = comma ? comma + 1 : colon + strlen(colon);
            }
            int snap_count = cJSON_GetArraySize(snaps);
            if (snap_count > 0) {
                cJSON *discovery = cJSON_CreateObject();
                cJSON_AddStringToObject(discovery, "action", "discovery");
                cJSON_AddItemToObject(discovery, "snaps", snaps);
                char *dj = cJSON_PrintUnformatted(discovery);
                cJSON_Delete(discovery);
                if (dj) {
                    zep_log("ws-node: sending discovery %d snaps\n", snap_count);
                    ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                        (unsigned char *)dj, strlen(dj));
                    free(dj);
                }
            } else {
                cJSON_Delete(snaps);
            }
        }

        /* Wait for pipe task or resume request */

        for (;;) {
            fd_set rfds;
            FD_ZERO(&rfds);
            int ws_fd = conn->sock;
            FD_SET(ws_fd, &rfds);
            FD_SET(g_resume_req_pipe[0], &rfds);
            int maxfd = ws_fd > g_resume_req_pipe[0] ? ws_fd : g_resume_req_pipe[0];
        if (g_pull_ws_req_pipe[0] >= 0) {
                 FD_SET(g_pull_ws_req_pipe[0], &rfds);
                 if (g_pull_ws_req_pipe[0] > maxfd) maxfd = g_pull_ws_req_pipe[0];
             }
             if (g_push_ws_req_pipe[0] >= 0) {
                 FD_SET(g_push_ws_req_pipe[0], &rfds);
                 if (g_push_ws_req_pipe[0] > maxfd) maxfd = g_push_ws_req_pipe[0];
             }
            int ssl_pending = (conn->ssl && SSL_pending(conn->ssl) > 0);
            struct timeval tv = { .tv_sec = ssl_pending ? 0 : 60,
                                  .tv_usec = 0 };
            int sel = select(maxfd + 1, &rfds, NULL, NULL,
                             ssl_pending ? &tv : NULL);
            if (sel < 0) {
                if (errno == EINTR) continue;
                break;
            }

            if (sel == 0 && !ssl_pending) continue;

            if (FD_ISSET(g_resume_req_pipe[0], &rfds)) {
                char dummy;
                (void)!read(g_resume_req_pipe[0], &dummy, 1);
                pthread_mutex_lock(&g_resume_lock);
                char rguid[ZEP_MAX_GUID_LEN];
                char rtoken[ZEP_MAX_LINE];
                char rfs[ZEP_MAX_PATH];
                snprintf(rguid, sizeof(rguid), "%s", g_resume_req.guid);
                snprintf(rtoken, sizeof(rtoken), "%s", g_resume_req.token);
                snprintf(rfs, sizeof(rfs), "%s", g_resume_req.fs);
                g_resume_req.ready = 0;
                pthread_mutex_unlock(&g_resume_lock);

zep_log_debug("ws-node: pull_resume guid=%s token=%.20s... fs=%s\n",
                            rguid, rtoken, rfs);

                char *req_json = NULL;
                if (asprintf(&req_json,
                    "{\"action\":\"pull_resume\","
                    "\"guid\":\"%s\",\"token\":\"%s\"}",
                    rguid, rtoken) < 0) {
                    char res = 1;
                    (void)!write(g_resume_resp_pipe[1], &res, 1);
                    break;
                }
                ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                  (unsigned char *)req_json, strlen(req_json));
                free(req_json);

             FILE *recv_fp = NULL;
                char _rrecv_cmd[4096] = {0};
                if (rfs[0]) {
                    char rcmd2[4096];
                    int rn = 0;
                    if (cfg->pull_unzip_cmd[0]) {
                        rn += snprintf(rcmd2 + rn, sizeof(rcmd2) - (size_t)rn,
                            "%s", cfg->pull_unzip_cmd);
                    } else if (cfg->pull_buf_cmd[0]) {
                        rn += snprintf(rcmd2 + rn, sizeof(rcmd2) - (size_t)rn,
                            "cat");
                    }
                    if (cfg->pull_buf_cmd[0]) {
                        if (rn > 0)
                            rn += snprintf(rcmd2 + rn, sizeof(rcmd2) - (size_t)rn, " | ");
                        rn += snprintf(rcmd2 + rn, sizeof(rcmd2) - (size_t)rn,
                            "%s", cfg->pull_buf_cmd);
                    }
                    if (rn > 0) {
                        rn += snprintf(rcmd2 + rn, sizeof(rcmd2) - (size_t)rn, " | ");
                    }
                    rn += snprintf(rcmd2 + rn, sizeof(rcmd2) - (size_t)rn,
                        "zfs recv %s%s-F -s -u '%s'",
                        cfg->recv_options[0] ? cfg->recv_options : "",
                        cfg->recv_options[0] ? " " : "",
                        rfs);
                    snprintf(_rrecv_cmd, sizeof(_rrecv_cmd), "%s", rcmd2);
                    recv_fp = popen(rcmd2, "w");
if ((g_logging & LOG_LEVEL_DEBUG) && recv_fp)
                         zep_log_debug("ws-node: opened recv pipe for resume fs=%s\n", rfs);
                }

                int ws_err = 0;
                for (;;) {
                    ssize_t rn = ws_node_recv_frame(conn, out,
                        WS_NODE_FRAME_MAX, &buf[0]);
                    if (rn < 0) { ws_err = 1; break; }
                    unsigned char op = buf[0] & 0x0F;
                    if (op == WS_NODE_OP_CLOSE) { ws_err = 1; break; }
                    if (op == WS_NODE_OP_PING) {
                        zep_log_debug( "ws-node: <- PING\n");
                        ws_node_send_frame(conn, WS_NODE_OP_PONG,
                                          out, (size_t)rn);
                        continue;
                    }
                    if (op == WS_NODE_OP_PONG) continue;
                    if (op == WS_NODE_OP_BIN && rn > 0 && recv_fp) {
                        if (fwrite(out, 1, (size_t)rn, recv_fp) != (size_t)rn) {
zep_log_debug("ws-node: recv fwrite failed\n");
                            ws_err = 1;
                            break;
                        }
                        continue;
                    }
                    if (op == WS_NODE_OP_EOF) break;
                    if (op == WS_NODE_OP_EXIT) break;
                }

                int recv_rc = 0;
                if (recv_fp) {
                    recv_rc = pclose(recv_fp);
                    audit_log("recv", "zfs", _rrecv_cmd, WIFEXITED(recv_rc) ? WEXITSTATUS(recv_rc) : -128);
 zep_log_debug("ws-node: recv pipe closed rc=%d\n", recv_rc);
                }

                char result = (ws_err || recv_rc != 0) ? 1 : 0;
                (void)!write(g_resume_resp_pipe[1], &result, 1);
                break;
            }

            if (g_pull_ws_req_pipe[0] >= 0 && FD_ISSET(g_pull_ws_req_pipe[0], &rfds)) {
                char dummy;
                (void)!read(g_pull_ws_req_pipe[0], &dummy, 1);
                pthread_mutex_lock(&g_pull_ws_lock);
                char pguid[ZEP_MAX_GUID_LEN];
                char plguid[ZEP_MAX_GUID_LEN];
                char pfs[ZEP_MAX_PATH];
                snprintf(pguid, sizeof(pguid), "%s", g_pull_ws_req.guid);
                snprintf(plguid, sizeof(plguid), "%s", g_pull_ws_req.local_guid);
                snprintf(pfs, sizeof(pfs), "%s", g_pull_ws_req.fs);
                g_pull_ws_req.ready = 0;
                pthread_mutex_unlock(&g_pull_ws_lock);

                zep_log("ws-node: pull_ws guid=%s local_guid=%s fs=%s\n",
                    pguid, plguid, pfs);

                char *req_json = NULL;
                if (asprintf(&req_json,
                    "{\"action\":\"pull\",\"guid\":\"%s\",\"local_guid\":\"%s\"}",
                    pguid, plguid) < 0) {
                    char res = 1;
                    (void)!write(g_pull_ws_resp_pipe[1], &res, 1);
                    continue;
                }
                if (ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                       (unsigned char *)req_json, strlen(req_json)) < 0) {
                    zep_log("ws-node: pull_ws send failed\n");
                    free(req_json);
                    char res = 1;
                    (void)!write(g_pull_ws_resp_pipe[1], &res, 1);
                    continue;
                }
                free(req_json);

                FILE *recv_fp = NULL;
                char _prcmd[2048] = {0};
                if (pfs[0]) {
                    char rcmd2[2048];
                    snprintf(rcmd2, sizeof(rcmd2), "zfs recv -F -s -u '%s'", pfs);
                    snprintf(_prcmd, sizeof(_prcmd), "%s", rcmd2);
                    recv_fp = popen(rcmd2, "w");
                    zep_log_debug("ws-node: pull_ws opened recv pipe fs=%s\n", pfs);
                }

                int p_ws_err = 0;
                for (;;) {
                    ssize_t rn = ws_node_recv_frame(conn, out,
                        WS_NODE_FRAME_MAX, &buf[0]);
                    if (rn < 0) { p_ws_err = 1; break; }
                    unsigned char op = buf[0] & 0x0F;
                    if (op == WS_NODE_OP_CLOSE) { p_ws_err = 1; break; }
                    if (op == WS_NODE_OP_PING) {
                        ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)rn);
                        continue;
                    }
                    if (op == WS_NODE_OP_PONG) continue;
                    if (op == WS_NODE_OP_BIN && rn > 0 && recv_fp) {
                        if (fwrite(out, 1, (size_t)rn, recv_fp) != (size_t)rn) {
                            zep_log("ws-node: pull_ws fwrite failed\n");
                            p_ws_err = 1;
                            break;
                        }
                        continue;
                    }
                    if (op == WS_NODE_OP_EOF) break;
                    if (op == WS_NODE_OP_EXIT) break;
                }

             int recv_rc = 0;
                if (recv_fp) {
                    recv_rc = pclose(recv_fp);
                    audit_log("recv", "zfs", _prcmd, WIFEXITED(recv_rc) ? WEXITSTATUS(recv_rc) : -128);
                    zep_log_debug("ws-node: pull_ws recv pipe closed rc=%d\n", recv_rc);
                }

                char pres = (p_ws_err || recv_rc != 0) ? 1 : 0;
                (void)!write(g_pull_ws_resp_pipe[1], &pres, 1);
                continue;
            }

            if (g_push_ws_req_pipe[0] >= 0 && FD_ISSET(g_push_ws_req_pipe[0], &rfds)) {
                char dummy;
                (void)!read(g_push_ws_req_pipe[0], &dummy, 1);
                pthread_mutex_lock(&g_push_ws_lock);
                char pguid[ZEP_MAX_GUID_LEN], pbg[ZEP_MAX_GUID_LEN], psnap[ZEP_MAX_SNAPSHOT_NAME];
                char plbl[64], pcfs[512], prt[ZEP_MAX_LINE];
                uint64_t pss = 0;
                snprintf(pguid, sizeof(pguid), "%s", g_push_ws_req.guid);
                snprintf(pbg, sizeof(pbg), "%s", g_push_ws_req.base_guid);
                snprintf(psnap, sizeof(psnap), "%s", g_push_ws_req.snapshot);
                snprintf(plbl, sizeof(plbl), "%s", g_push_ws_req.label);
                snprintf(pcfs, sizeof(pcfs), "%s", g_push_ws_req.cluster_fs);
                snprintf(prt, sizeof(prt), "%s", g_push_ws_req.resume_token);
                pss = g_push_ws_req.stream_size;
                g_push_ws_req.ready = 0;
                pthread_mutex_unlock(&g_push_ws_lock);

                zep_log("ws-node: push_ws guid=%s snap=%s\n", pguid, psnap);

                /* Open zfs send pipe */
                FILE *send_fp = NULL;
                char _pscmd[8192];
                {
                    char scmd[8192];
                if (prt[0]) {
                            int sc_n = snprintf(scmd, sizeof(scmd),
                                "set -o pipefail; exec zfs send -t '%s'",
                                prt);
                            if (sc_n > 0 && sc_n < (int)sizeof(scmd) && cfg->push_buf_cmd[0]) {
                                sc_n += snprintf(scmd + sc_n, sizeof(scmd) - (size_t)sc_n,
                                    " | %s", cfg->push_buf_cmd);
                            }
                            if (sc_n > 0 && sc_n < (int)sizeof(scmd) && cfg->push_zip_cmd[0]) {
                                sc_n += snprintf(scmd + sc_n, sizeof(scmd) - (size_t)sc_n,
                                    " | %s", cfg->push_zip_cmd);
                            }
                            if (sc_n > 0 && sc_n < (int)sizeof(scmd) && cfg->debug_inject_zfs_pipeline_cmd[0]) {
                                sc_n += snprintf(scmd + sc_n, sizeof(scmd) - (size_t)sc_n,
                                    " | %s", cfg->debug_inject_zfs_pipeline_cmd);
                            }
                        } else {
                          snprintf(scmd, sizeof(scmd),
                              "set -o pipefail; exec zfs send %s '%s'%s%s%s%s%s%s",
                              cfg->send_options[0] ? cfg->send_options : "",
                              psnap,
                              cfg->push_buf_cmd[0] ? " | " : "",
                              cfg->push_buf_cmd[0] ? cfg->push_buf_cmd : "",
                              cfg->push_zip_cmd[0] ? " | " : "",
                              cfg->push_zip_cmd[0] ? cfg->push_zip_cmd : "",
                              cfg->debug_inject_zfs_pipeline_cmd[0] ? " | " : "",
                              cfg->debug_inject_zfs_pipeline_cmd[0] ? cfg->debug_inject_zfs_pipeline_cmd : "");
                     }
                  send_fp = popen(scmd, "r");
                     zep_log_debug("ws-node: push_ws opened send pipe cmd=%s\n", scmd);
                     snprintf(_pscmd, sizeof(_pscmd), "%s", scmd);
                }

              /* Send push request metadata */
                 char push_req[8192];
                 if (prt[0]) {
                     snprintf(push_req, sizeof(push_req),
                         "{\"action\":\"push\",\"guid\":\"%s\",\"base_guid\":\"%s\","
                         "\"snapshot\":\"%s\",\"label\":\"%s\",\"cluster_fs\":\"%s\","
                         "\"stream_size\":%lu,\"resume_token\":\"%s\"}",
                         pguid, pbg, psnap, plbl, pcfs, (unsigned long)pss, prt);
                 } else {
                     snprintf(push_req, sizeof(push_req),
                         "{\"action\":\"push\",\"guid\":\"%s\",\"base_guid\":\"%s\","
                         "\"snapshot\":\"%s\",\"label\":\"%s\",\"cluster_fs\":\"%s\","
                         "\"stream_size\":%lu}",
                         pguid, pbg, psnap, plbl, pcfs, (unsigned long)pss);
                 }
                if (ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                    (unsigned char *)push_req, strlen(push_req)) < 0) {
                    zep_log("ws-node: push_ws send failed\n");
                    if (send_fp) {
                        int ck = pclose(send_fp);
                        audit_log("push_send", "zfs", _pscmd,
                            WIFEXITED(ck) ? WEXITSTATUS(ck) : -128);
                    }
                    char pres = 1;
                    (void)!write(g_push_ws_resp_pipe[1], &pres, 1);
                    continue;
                }

                /* Stream pipe data as BIN frames, multiplexed with server WS frames */
                int push_ws_err = 0;
                int server_done = 0;
                int resume_skipped = 0;
                unsigned char *pipe_buf = malloc(WS_NODE_FRAME_MAX);
                int pipe_eof = 0;

                for (;;) {
                    fd_set rfds;
                    FD_ZERO(&rfds);
                    FD_SET(ws_fd, &rfds);
                    int maxfd = ws_fd;
                    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
                    if (!server_done) {
                        int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
                        if (sel < 0 && errno != EINTR) { push_ws_err = 1; break; }

                        if (FD_ISSET(ws_fd, &rfds)) {
                            ssize_t rn = ws_node_recv_frame(conn, out,
                                WS_NODE_FRAME_MAX, &buf[0]);
                            if (rn < 0) { push_ws_err = 1; break; }
                            unsigned char op = buf[0] & 0x0F;
                            if (op == WS_NODE_OP_CLOSE) { push_ws_err = 1; break; }
                            if (op == WS_NODE_OP_PING) {
                                ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)rn);
                                continue;
                            }
                            if (op == WS_NODE_OP_PONG) continue;
                            if (op == WS_NODE_OP_TEXT && rn > 0 && !resume_skipped) {
                                out[rn] = '\0';
                                cJSON *resp = cJSON_Parse((char *)out);
                                if (resp) {
                                    cJSON *res = cJSON_GetObjectItem(resp, "resume");
                                    if (res && cJSON_IsTrue(res)) {
                                        cJSON *off = cJSON_GetObjectItem(resp, "offset");
                                        if (off && cJSON_IsNumber(off) && send_fp && !pipe_eof) {
                                            long skip = (long)off->valuedouble;
                                            char discard[65536];
                                            long skipped = 0;
                                            while (skipped < skip) {
                                                size_t nr = fread(discard, 1, sizeof(discard), send_fp);
                                                if (nr == 0) break;
                                                skipped += nr;
                                            }
                                            zep_log("push_ws: resuming from offset %ld\n", skip);
                                        }
                                    }
                                    resume_skipped = 1;
                                    cJSON_Delete(resp);
                                }
                                continue;
                            }
                            if (op == WS_NODE_OP_EXIT || op == WS_NODE_OP_EOF) { server_done = 1; break; }
                        }
                    }

                    /* Stream pipe data as BIN frames to server */
                    if (!server_done && send_fp && !pipe_eof) {
                        size_t nr = fread(pipe_buf, 1, WS_NODE_FRAME_MAX, send_fp);
                        if (nr > 0) {
                            if (ws_node_send_frame(conn, WS_NODE_OP_BIN, pipe_buf, nr) < 0) {
                                push_ws_err = 1; break;
                            }
                        } else {
                            pipe_eof = 1;
                        }
                    }

                    /* If pipe is done and server is done, exit */
                    if (server_done && pipe_eof) break;
                    /* If pipe is done, just wait for server DONE */
                    if (pipe_eof && !server_done) continue;
                    /* If pipe has data, keep sending */
                    if (!pipe_eof) continue;
                    /* Default: spin */
                }
                free(pipe_buf);

           /* Close pipe and check exit code */
                if (send_fp) {
                    int send_rc = pclose(send_fp);
                    audit_log("push_send", "zfs", _pscmd, WIFEXITED(send_rc) ? WEXITSTATUS(send_rc) : -128);
                    zep_log_debug("ws-node: push_ws send pipe closed rc=%d\n", send_rc);
                    if (!server_done) {
                        unsigned char ex = (unsigned char)(WIFEXITED(send_rc) && WEXITSTATUS(send_rc) == 0 ? 0 : 1);
                        ws_node_send_frame(conn, WS_NODE_OP_EXIT, &ex, 1);
                        ws_node_send_frame(conn, WS_NODE_OP_EOF, NULL, 0);
                    }
                }

                /* server_done was set by the main loop above */
                char pres = (push_ws_err || server_done != 1) ? 1 : 0;
                (void)!write(g_push_ws_resp_pipe[1], &pres, 1);
                continue;
            }

            if (!FD_ISSET(ws_fd, &rfds) && !ssl_pending) continue;

            ssize_t n = ws_node_recv_frame(conn, out, WS_NODE_FRAME_MAX, &buf[0]);
            unsigned char opcode = buf[0] & 0x0F;

            if (n < 0) { zep_log_debug( "ws-node: recv error n=%zd op=%02x, reconnecting\n", n, opcode); break; }
            if (opcode == WS_NODE_OP_CLOSE) { zep_log_debug( "ws-node: close n=%zd\n", n); break; }
            if (opcode == WS_NODE_OP_PING) { zep_log_debug( "ws-node: <- PING\n"); ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)n); continue; }
            if (opcode == WS_NODE_OP_PONG) continue;
            if (opcode == WS_NODE_OP_EOF) continue;
            if (opcode == WS_NODE_OP_EXIT) continue;

            if ((opcode == WS_NODE_OP_TEXT || opcode == WS_NODE_OP_BIN) && n > 0) {
                out[n] = '\0';
                cJSON *task = cJSON_Parse((char *)out);
                if (task) {
                    cJSON *action = cJSON_GetObjectItem(task, "action");
                    cJSON *command = cJSON_GetObjectItem(task, "command");
                    if (action && command && cJSON_IsString(action) && cJSON_IsString(command)) {
                        if (strcmp(action->valuestring, "pipe") == 0) {
                            const char *cmd_str = command->valuestring;
                            char *cmd_copy = strdup(cmd_str);
                            char *argv_buf[128];
                            int argc2 = 0;
                            int has_pipe = 0;
                            if (cmd_copy) {
                                char *p = cmd_copy;
                                while (*p && argc2 < 127) {
                                    while (*p == ' ' || *p == '\t') p++;
                                    if (!*p) break;
                                    char *start = p;
                                    if (*p == '\'' || *p == '"') {
                                        char q = *p++;
                                        start = p;
                                        while (*p && *p != q) p++;
                                        if (*p) *p++ = '\0';
                                    } else {
                                        while (*p && *p != ' ' && *p != '\t') p++;
                                        if (*p) *p++ = '\0';
                                    }
                                    if (strcmp(start, "|") == 0) has_pipe = 1;
                                    argv_buf[argc2++] = start;
                                }
                            }
                            argv_buf[argc2] = NULL;
                            if (argc2 == 0) { free(cmd_copy); cJSON_Delete(task); continue; }

                            cJSON *interactive = cJSON_GetObjectItem(task, "interactive");
                            int is_interactive = (interactive && cJSON_IsTrue(interactive));

                            if (is_interactive) {
                                int pty_master;
                                pid_t pid = forkpty(&pty_master, NULL, NULL, NULL);
                                if (pid < 0) {
                                    free(cmd_copy);
                                    zep_log( "ws-node: forkpty() failed\n");
                                    cJSON_Delete(task);
                                    continue;
                                }

                                if (pid == 0) {
                                    if (has_pipe)
                                        execl("/bin/sh", "sh", "-c", cmd_str, (char *)NULL);
                                    else
                                        execvp(argv_buf[0], argv_buf);
                                    dprintf(STDERR_FILENO, "exec: %s\n", strerror(errno));
                                    _exit(1);
                                }

                                free(cmd_copy);
                                fcntl(pty_master, F_SETFL, fcntl(pty_master, F_GETFL) | O_NONBLOCK);

                                int pty_alive = 1;
                                int ws_alive = 1;

                                zep_log_debug( "ws-node: interactive pipe started: %s pid=%d\n", cmd_str, (int)pid);

                                int ws_fd = conn->sock;
                                int ws_flags = fcntl(ws_fd, F_GETFL, 0);
                                fcntl(ws_fd, F_SETFL, ws_flags | O_NONBLOCK);

                                while (ws_alive && pty_alive) {
                                    fd_set rfds;
                                    FD_ZERO(&rfds);
                                    int maxfd = -1;
                                    FD_SET(pty_master, &rfds);
                                    if (pty_master > maxfd) maxfd = pty_master;
                                    FD_SET(ws_fd, &rfds);
                                    if (ws_fd > maxfd) maxfd = ws_fd;

                                    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
                                    int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
                                    int ssl_pending = (conn->ssl && SSL_pending(conn->ssl) > 0);

                                    if (sel < 0 && errno != EINTR) break;

                                    if (sel > 0 || ssl_pending) {
                                        if (pty_alive && FD_ISSET(pty_master, &rfds)) {
                                            ssize_t nr = read(pty_master, out, WS_NODE_FRAME_MAX);
                                            if (nr > 0) {
                                                if (ws_node_send_frame(conn, WS_NODE_OP_BIN, out, (size_t)nr) < 0)
                                                    ws_alive = 0;
                                            } else if (nr <= 0) {
                                                pty_alive = 0;
                                            }
                                        }

                                        if (ws_alive && (FD_ISSET(ws_fd, &rfds) || ssl_pending)) {
                                            unsigned char peek[1];
                                            int r = (int)recv(ws_fd, peek, 1, MSG_PEEK | MSG_DONTWAIT);
                                            if (r == 0) { ws_alive = 0; break; }
                                            if (r > 0 || ssl_pending) {
                                                ssize_t rn = ws_node_recv_frame(conn, out, WS_NODE_FRAME_MAX, &buf[0]);
                                                if (rn < 0) { ws_alive = 0; break; }
                                                unsigned char op = buf[0] & 0x0F;

                                                if (op == WS_NODE_OP_CLOSE) { ws_alive = 0; break; }
                                                if (op == WS_NODE_OP_PING) { zep_log_debug( "ws-node: <- PING\n"); ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)rn); continue; }
                                                if (op == WS_NODE_OP_PONG) continue;
                                                if (op == WS_NODE_OP_EOF) continue;

                                                if (op == WS_NODE_OP_TEXT) {
                                                    out[rn] = '\0';
                                                    cJSON *msg = cJSON_Parse((char *)out);
                                                    if (msg) {
                                                        cJSON *act = cJSON_GetObjectItem(msg, "action");
                                                        if (act && cJSON_IsString(act) && strcmp(act->valuestring, "resize") == 0) {
                                                            cJSON *rows = cJSON_GetObjectItem(msg, "rows");
                                                            cJSON *cols = cJSON_GetObjectItem(msg, "cols");
                                                            if (cJSON_IsNumber(rows) && cJSON_IsNumber(cols)) {
                                                                struct winsize ws;
                                                                ws.ws_row = (unsigned short)rows->valueint;
                                                                ws.ws_col = (unsigned short)cols->valueint;
                                                                ws.ws_xpixel = 0;
                                                                ws.ws_ypixel = 0;
                                                                 ioctl(pty_master, TIOCSWINSZ, &ws);
                                                                 kill(pid, SIGWINCH);
                                                        }
                                                        }
                                                        cJSON_Delete(msg);
                                                    }
                                                    continue;
                                                }

                                                if (op == WS_NODE_OP_BIN && pty_alive) {
                                                    ssize_t w = write(pty_master, out, (size_t)rn);
                                                    if (w < 0 && errno != EAGAIN)
                                                        pty_alive = 0;
                                                }
                                            }
                                        }
                                    }
                                }

                                fcntl(ws_fd, F_SETFL, ws_flags);
                                close(pty_master);
                                int status = 0;
                                waitpid(pid, &status, 0);
                                zep_log_debug( "ws-node: interactive pipe done, child exit=%d\n", WEXITSTATUS(status));
                                {
                                    unsigned char exit_byte = (unsigned char)WEXITSTATUS(status);
                                    ws_node_send_frame(conn, WS_NODE_OP_EXIT, &                                exit_byte, 1);
                                }
                                continue;
                            }

                            int stdin_pipe[2], stdout_pipe[2], stderr_pipe[2];
                            if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
                                zep_log( "ws-node: pipe() failed\n");
                                cJSON_Delete(task);
                                continue;
                            }

                            pid_t pid = fork();
                            if (pid < 0) {
                                free(cmd_copy);
                                zep_log( "ws-node: fork() failed\n");
                                close(stdin_pipe[0]); close(stdin_pipe[1]);
                                close(stdout_pipe[0]); close(stdout_pipe[1]);
                                close(stderr_pipe[0]); close(stderr_pipe[1]);
                                cJSON_Delete(task);
                                continue;
                            }

                            if (pid == 0) {
                                close(stdin_pipe[1]);
                                close(stdout_pipe[0]);
                                close(stderr_pipe[0]);
                                dup2(stdin_pipe[0], STDIN_FILENO);
                                dup2(stdout_pipe[1], STDOUT_FILENO);
                                dup2(stderr_pipe[1], STDERR_FILENO);
                                close(stdin_pipe[0]);
                                close(stdout_pipe[1]);
                                close(stderr_pipe[1]);
                                if (has_pipe) {
                                    execl("/bin/sh", "sh", "-c", cmd_str, (char *)NULL);
                                    dprintf(STDERR_FILENO, "exec: /bin/sh: %s\n", strerror(errno));
                                } else {
                                    execvp(argv_buf[0], argv_buf);
                                    dprintf(STDERR_FILENO, "exec: %s: %s\n", argv_buf[0], strerror(errno));
                                }
                                _exit(1);
                            }

                            free(cmd_copy);
                            close(stdin_pipe[0]);
                            close(stdout_pipe[1]);
                            close(stderr_pipe[1]);
                            int child_stdin = stdin_pipe[1];
                            int child_stdout = stdout_pipe[0];
                            int child_stderr = stderr_pipe[0];
                            fcntl(child_stdin, F_SETFL, fcntl(child_stdin, F_GETFL) | O_NONBLOCK);

                            int child_stdin_open = 1;
                            int child_stdout_open = 1;
                            int child_stderr_open = 1;
                            int ws_alive = 1;
                            unsigned char *pending_data = NULL;
                            ssize_t pending_len = 0;

                            zep_log_debug( "ws-node: pipe started: %s pid=%d\n", cmd_str, (int)pid);

                            int ws_fd = conn->sock;
                            int ws_flags = fcntl(ws_fd, F_GETFL, 0);
                            fcntl(ws_fd, F_SETFL, ws_flags | O_NONBLOCK);

                            while (ws_alive && (child_stdout_open || child_stderr_open || pending_len > 0)) {
                                fd_set rfds, wfds;
                                FD_ZERO(&rfds);
                                FD_ZERO(&wfds);
                                int maxfd = -1;
                                if (child_stdout_open) { FD_SET(child_stdout, &rfds); if (child_stdout > maxfd) maxfd = child_stdout; }
                                if (child_stderr_open) { FD_SET(child_stderr, &rfds); if (child_stderr > maxfd) maxfd = child_stderr; }
                                if (pending_len == 0) { FD_SET(ws_fd, &rfds); if (ws_fd > maxfd) maxfd = ws_fd; }
                                if (child_stdin_open && pending_len > 0) {
                                    FD_SET(child_stdin, &wfds);
                                    if (child_stdin > maxfd) maxfd = child_stdin;
                                }

                                struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
                                int sel = select(maxfd + 1, &rfds, &wfds, NULL, &tv);
                                int ssl_pending = (conn->ssl && SSL_pending(conn->ssl) > 0);

                                if (sel < 0 && errno != EINTR) break;

                                if (sel > 0 || ssl_pending) {
                                    if (pending_len > 0 && FD_ISSET(child_stdin, &wfds)) {
                                        ssize_t w = write(child_stdin, pending_data, (size_t)pending_len);
                                        if (w > 0) {
                                            memmove(pending_data, pending_data + w, (size_t)(pending_len - w));
                                            pending_len -= w;
                                            if (pending_len == 0) { free(pending_data); pending_data = NULL; }
                                        } else if (w < 0 && errno != EAGAIN) {
                                            free(pending_data); pending_data = NULL; pending_len = 0;
                                            close(child_stdin); child_stdin_open = 0;
                                        }
                                    }

                                    if (pending_len == 0 && (FD_ISSET(ws_fd, &rfds) || ssl_pending)) {
                                        unsigned char peek[1];
                                        int r = (int)recv(ws_fd, peek, 1, MSG_PEEK | MSG_DONTWAIT);
                                        if (r == 0) { ws_alive = 0; break; }
                                        if (r > 0 || ssl_pending) {
                                            ssize_t rn = ws_node_recv_frame(conn, out, WS_NODE_FRAME_MAX, &buf[0]);
                                            if (rn < 0) { ws_alive = 0; break; }
                                            unsigned char op = buf[0] & 0x0F;
                                            if (op == WS_NODE_OP_CLOSE) { ws_alive = 0; break; }
                                            if (op == WS_NODE_OP_EOF) {
                                                if (child_stdin_open) { close(child_stdin); child_stdin_open = 0; }
                                                continue;
                                            }
                                            if (op == WS_NODE_OP_EXIT) continue;
                                            if (op == WS_NODE_OP_PING) { zep_log_debug( "ws-node: <- PING\n"); ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)rn); continue; }
                                            if (op == WS_NODE_OP_PONG) continue;
                                            if (op == WS_NODE_OP_BIN && child_stdin_open) {
                                                ssize_t w = write(child_stdin, out, (size_t)rn);
                                                if (w > 0) {
                                                    if (w < rn) {
                                                        pending_data = malloc((size_t)(rn - w));
                                                        if (pending_data) {
                                                            memcpy(pending_data, out + w, (size_t)(rn - w));
                                                            pending_len = rn - w;
                                                        }
                                                    }
                                                } else if (errno == EAGAIN) {
                                                    pending_data = malloc((size_t)rn);
                                                    if (pending_data) {
                                                        memcpy(pending_data, out, (size_t)rn);
                                                        pending_len = rn;
                                                    }
                                                } else {
                                                    close(child_stdin); child_stdin_open = 0;
                                                }
                                            }
                                        }
                                    }

                                    if (child_stdout_open && FD_ISSET(child_stdout, &rfds)) {
                                        ssize_t nr = read(child_stdout, out, WS_NODE_FRAME_MAX);
                                        if (nr > 0) {
                                            if (ws_node_send_frame(conn, WS_NODE_OP_BIN, out, (size_t)nr) < 0)
                                                ws_alive = 0;
                                        } else if (nr <= 0) {
                                            ws_node_send_frame(conn, WS_NODE_OP_EOF, NULL, 0);
                                            close(child_stdout);
                                            child_stdout_open = 0;
                                        }
                                    }

                                    if (child_stderr_open && FD_ISSET(child_stderr, &rfds)) {
                                        ssize_t nr = read(child_stderr, out, WS_NODE_FRAME_MAX);
                                        if (nr > 0) {
                                            if (ws_node_send_frame(conn, WS_NODE_OP_TEXT, out, (size_t)nr) < 0)
                                                ws_alive = 0;
                                        } else if (nr <= 0) {
                                            ws_node_send_frame(conn, WS_NODE_OP_EOF, NULL, 0);
                                            close(child_stderr);
                                            child_stderr_open = 0;
                                        }
                                    }
                                }
                            }

                            fcntl(ws_fd, F_SETFL, ws_flags);

                            free(pending_data);
                            if (child_stdin_open) { close(child_stdin); child_stdin_open = 0; }
                            if (child_stdout_open) { close(child_stdout); child_stdout_open = 0; }
                            if (child_stderr_open) { close(child_stderr); child_stderr_open = 0; }

                            int status = 0;
                            waitpid(pid, &status, 0);
                            zep_log_debug( "ws-node: pipe done, child exit=%d\n", WEXITSTATUS(status));
                            {
                                unsigned char exit_byte = (unsigned char)WEXITSTATUS(status);
                                ws_node_send_frame(conn, WS_NODE_OP_EXIT, &                                exit_byte, 1);
                            }
                            continue;
                         }
                     }
                     /* Handle pull: server sends assembled.zfs, client receives via zfs recv */
                     if (action && cJSON_IsString(action) &&
                         strcmp(action->valuestring, "pull") == 0) {
                         cJSON *guid_j = cJSON_GetObjectItem(task, "guid");
                         cJSON *snap_j = cJSON_GetObjectItem(task, "snapshot");
                         cJSON *cfs_j = cJSON_GetObjectItem(task, "cluster_fs");
                         if (guid_j && cJSON_IsString(guid_j) && snap_j && cJSON_IsString(snap_j)) {
                             zep_log("ws-node: RX pull guid=%s snap=%s\n",
                                     guid_j->valuestring, snap_j->valuestring);

                             /* Resolve cluster_fs -> local_fs from mapping */
                             const char *cfs = cfs_j && cJSON_IsString(cfs_j) ? cfs_j->valuestring : "";
                             char local_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};

                             if (cfs[0]) {
                                 const char *mp2 = cfg->mapping;
                                 while (mp2 && *mp2) {
                                     while (*mp2==' '||*mp2=='\t') mp2++;
                                     if (!*mp2) break;
                                     const char *colon = strchr(mp2, ':');
                                     if (!colon) break;
                                     size_t cflen = (size_t)(colon - mp2);
                                     char cfs_buf[512];
                                     if (cflen >= sizeof(cfs_buf)) cflen = sizeof(cfs_buf) - 1;
                                     memcpy(cfs_buf, mp2, cflen);
                                     cfs_buf[cflen] = '\0';
                                     if (strcmp(cfs_buf, cfs) == 0) {
                                         const char *start = colon + 1;
                                         while (*start==' ') start++;
                                         const char *end = strchr(start, ',');
                                         if (!end) end = start + strlen(start);
                                         const char *paren = strchr(start, '(');
                                         size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
                                         if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
                                         memcpy(local_fs, start, n);
                                         local_fs[n] = '\0';
                                         break;
                                     }
                                     const char *comma = strchr(colon, ',');
                                     mp2 = comma ? comma + 1 : colon + strlen(colon);
                                 }
                             }

                             if (!local_fs[0]) {
                                 zep_log("ws-node: pull: mapping lookup failed for cfs=%s\n", cfs);
                                 cJSON_Delete(task);
                                 continue;
                             }

                                char recv_cmd[4096];
                                int rn2 = 0;
                                if (cfg->pull_unzip_cmd[0]) {
                                    rn2 += snprintf(recv_cmd + rn2, sizeof(recv_cmd) - (size_t)rn2,
                                        "%s", cfg->pull_unzip_cmd);
                                } else if (cfg->pull_buf_cmd[0]) {
                                    rn2 += snprintf(recv_cmd + rn2, sizeof(recv_cmd) - (size_t)rn2,
                                        "cat");
                                }
                                if (cfg->pull_buf_cmd[0]) {
                                    if (rn2 > 0)
                                        rn2 += snprintf(recv_cmd + rn2, sizeof(recv_cmd) - (size_t)rn2, " | ");
                                    rn2 += snprintf(recv_cmd + rn2, sizeof(recv_cmd) - (size_t)rn2,
                                        "%s", cfg->pull_buf_cmd);
                                }
                                if (rn2 > 0) {
                                    rn2 += snprintf(recv_cmd + rn2, sizeof(recv_cmd) - (size_t)rn2, " | ");
                                }
                                rn2 += snprintf(recv_cmd + rn2, sizeof(recv_cmd) - (size_t)rn2,
                                    "zfs recv %s%s-F -s -u '%s' 2>%s",
                                    cfg->recv_options[0] ? cfg->recv_options : "",
                                    cfg->recv_options[0] ? " " : "",
                                    local_fs, stderr_log);

                               FILE *recv_fp = popen(recv_cmd, "w");
                               zep_log("ws-node: pull recv_cmd=%s fp=%p\n", recv_cmd, (void*)recv_fp);

                              int pull_exit_code = -1;

                              /* Receive BIN frames from server */
                              for (;;) {
                                  ssize_t rn = ws_node_recv_frame(conn, out,
                                      WS_NODE_FRAME_MAX, &buf[0]);
                                  if (rn < 0) break;
                                  unsigned char op = buf[0] & 0x0F;
                                  if (op == WS_NODE_OP_CLOSE) break;
                                  if (op == WS_NODE_OP_PING) {
                                      ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)rn);
                                      continue;
                                  }
                                  if (op == WS_NODE_OP_PONG) continue;
                                  if (op == WS_NODE_OP_BIN && rn > 0 && recv_fp) {
                                      if (fwrite(out, 1, (size_t)rn, recv_fp) != (size_t)rn) {
                                          zep_log("ws-node: pull recv fwrite failed\n");
                                          break;
                                      }
                                      continue;
                                  }
                                  if (op == WS_NODE_OP_EXIT && rn == 1) {
                                      pull_exit_code = (int)out[0];
                                  }
                                  if (op == WS_NODE_OP_EOF) break;
                              }

                              int recv_rc = 0;
                              if (recv_fp) {
                                  recv_rc = pclose(recv_fp);
                                  pull_exit_code = WIFEXITED(recv_rc) ? WEXITSTATUS(recv_rc) : 1;
                                  zep_log("ws-node: pull recv pipe closed rc=%d\n", recv_rc);
                              }

                              if (pull_exit_code != 0) {
                                   FILE *ef = fopen(stderr_log, "r");
                                   if (ef) {
                                       char ebuf[1024] = {0};
                                       size_t nr = fread(ebuf, 1, sizeof(ebuf) - 1, ef);
                                       fclose(ef);
                                       if (nr > 0) {
                                           while (nr > 0 && (ebuf[nr-1]=='\n'||ebuf[nr-1]=='\r'))
                                               ebuf[--nr] = '\0';
                                           zep_log("ws-node: pull recv stderr: %s\n", ebuf);
                                       }
                                  }
                              }

                              /* Send ACK back to server */
                              char ack_json[4096] = {0};
                              int ack_n = 0;
                              char resume_token_buf[512] = {0};
                              char stderr_buf[512] = {0};
                              if (pull_exit_code != 0 && local_fs[0]) {
                                  /* Try to get resume token */
                                  char tok_cmd[2048];
                                  snprintf(tok_cmd, sizeof(tok_cmd),
                                      "zfs get -Hp -o value receive_resume_token '%s' 2>/dev/null",
                                      local_fs);
                                  FILE *tp = popen(tok_cmd, "r");
                                  if (tp) {
                                      if (fgets(resume_token_buf, sizeof(resume_token_buf), tp)) {
                                          size_t tl = strlen(resume_token_buf);
                                          while (tl > 0 && (resume_token_buf[tl-1]=='\n'||resume_token_buf[tl-1]=='\r'))
                                              resume_token_buf[--tl] = '\0';
                                       if (resume_token_buf[0] && strcmp(resume_token_buf, "-") != 0) {
                                            zep_log("ws-node: pull got resume_token=%.40s...\n", resume_token_buf);
                                        } else {
                                            resume_token_buf[0] = '\0';
                                        }
                                      }
                                      pclose(tp);
                                  }
                                  /* Read stderr from zfs recv */
                                   FILE *ef = fopen(stderr_log, "r");
                                  if (ef) {
                                      (void)!fread(stderr_buf, 1, sizeof(stderr_buf) - 1, ef);
                                      fclose(ef);
                                      size_t sl = strlen(stderr_buf);
                                      while (sl > 0 && (stderr_buf[sl-1]=='\n'||stderr_buf[sl-1]=='\r'))
                                          stderr_buf[--sl] = '\0';
                                  }
                              }

                              if (resume_token_buf[0]) {
                                  ack_n = snprintf(ack_json, sizeof(ack_json),
                                      "{\"action\":\"pull_ack\",\"guid\":\"%s\",\"exit_code\":%d,\"resume_token\":\"%s\"}",
                                      guid_j->valuestring, pull_exit_code, resume_token_buf);
                              } else if (stderr_buf[0]) {
                                  ack_n = snprintf(ack_json, sizeof(ack_json),
                                      "{\"action\":\"pull_ack\",\"guid\":\"%s\",\"exit_code\":%d,\"stderr\":\"%s\"}",
                                      guid_j->valuestring, pull_exit_code, stderr_buf);
                              } else {
                                  ack_n = snprintf(ack_json, sizeof(ack_json),
                                      "{\"action\":\"pull_ack\",\"guid\":\"%s\",\"exit_code\":%d}",
                                      guid_j->valuestring, pull_exit_code);
                              }
                             if (ack_n > 0) {
                                 ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                     (unsigned char *)ack_json, (size_t)ack_n);
                                 zep_log("ws-node: pull ack sent: %s\n", ack_json);
                             }
                         }
                         cJSON_Delete(task);
                         continue;
                     }
                     /* Handle pull_resume: server sends resumed data */
                     if (action && cJSON_IsString(action) &&
                         strcmp(action->valuestring, "pull_resume") == 0) {
                         cJSON *guid_j = cJSON_GetObjectItem(task, "guid");
                         if (guid_j && cJSON_IsString(guid_j)) {
                             zep_log("ws-node: RX pull_resume guid=%s\n", guid_j->valuestring);

                             /* Resolve local_fs from mapping */
                              char local_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                             char resolved_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                             const char *mp2 = cfg->mapping;
                             while (mp2 && *mp2) {
                                 while (*mp2==' '||*mp2=='\t') mp2++;
                                 if (!*mp2) break;
                                 const char *colon = strchr(mp2, ':');
                                 if (!colon) break;
                                 size_t cflen = (size_t)(colon - mp2);
                                 char cfs_buf[512];
                                 if (cflen >= sizeof(cfs_buf)) cflen = sizeof(cfs_buf) - 1;
                                 memcpy(cfs_buf, mp2, cflen);
                                 cfs_buf[cflen] = '\0';
                                 const char *start = colon + 1;
                                 while (*start==' ') start++;
                                 const char *end = strchr(start, ',');
                                 if (!end) end = start + strlen(start);
                                 const char *paren = strchr(start, '(');
                                 size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
                                 if (n >= sizeof(resolved_fs)) n = sizeof(resolved_fs) - 1;
                                 memcpy(resolved_fs, start, n);
                                 resolved_fs[n] = '\0';
                                 if (cfs_buf[0]) {
                                     snprintf(local_fs, sizeof(local_fs), "%s", resolved_fs);
                                     break;
                                 }
                                 const char *comma = strchr(colon, ',');
                                 mp2 = comma ? comma + 1 : colon + strlen(colon);
                             }

                              char recv_cmd[4096];
                              int rn3 = 0;
                              if (cfg->pull_unzip_cmd[0]) {
                                  rn3 += snprintf(recv_cmd + rn3, sizeof(recv_cmd) - (size_t)rn3,
                                      "%s", cfg->pull_unzip_cmd);
                              } else if (cfg->pull_buf_cmd[0]) {
                                  rn3 += snprintf(recv_cmd + rn3, sizeof(recv_cmd) - (size_t)rn3,
                                      "cat");
                              }
                              if (cfg->pull_buf_cmd[0]) {
                                  if (rn3 > 0)
                                      rn3 += snprintf(recv_cmd + rn3, sizeof(recv_cmd) - (size_t)rn3, " | ");
                                  rn3 += snprintf(recv_cmd + rn3, sizeof(recv_cmd) - (size_t)rn3,
                                      "%s", cfg->pull_buf_cmd);
                              }
                              if (rn3 > 0) {
                                  rn3 += snprintf(recv_cmd + rn3, sizeof(recv_cmd) - (size_t)rn3, " | ");
                              }
                              rn3 += snprintf(recv_cmd + rn3, sizeof(recv_cmd) - (size_t)rn3,
                                  "zfs recv %s%s-F -s -u '%s' 2>%s",
                                  cfg->recv_options[0] ? cfg->recv_options : "",
                                  cfg->recv_options[0] ? " " : "",
                                  local_fs, stderr_log);

                               FILE *recv_fp = popen(recv_cmd, "w");
                                zep_log("ws-node: pull_resume recv_cmd=%s fp=%p\n", recv_cmd, (void*)recv_fp);

                               int pull_exit_code = -1;

                               for (;;) {
                                   ssize_t rn = ws_node_recv_frame(conn, out,
                                       WS_NODE_FRAME_MAX, &buf[0]);
                                   if (rn < 0) break;
                                   unsigned char op = buf[0] & 0x0F;
                                   if (op == WS_NODE_OP_CLOSE) break;
                                  if (op == WS_NODE_OP_PING) {
                                      ws_node_send_frame(conn, WS_NODE_OP_PONG, out, (size_t)rn);
                                      continue;
                                  }
                                  if (op == WS_NODE_OP_PONG) continue;
                                  if (op == WS_NODE_OP_BIN && rn > 0 && recv_fp) {
                                       if (fwrite(out, 1, (size_t)rn, recv_fp) != (size_t)rn) {
                                           zep_log("ws-node: pull_resume recv fwrite failed\n");
                                           break;
                                       }
                                      continue;
                                  }
                                  if (op == WS_NODE_OP_EXIT && rn == 1) {
                                      pull_exit_code = (int)out[0];
                                  }
                                  if (op == WS_NODE_OP_EOF) break;
                              }

                              int recv_rc = 0;
                              if (recv_fp) {
                                  recv_rc = pclose(recv_fp);
                                  pull_exit_code = WIFEXITED(recv_rc) ? WEXITSTATUS(recv_rc) : 1;
                                  zep_log("ws-node: pull_resume recv pipe closed rc=%d\n", recv_rc);
                              }

                             if (pull_exit_code != 0) {
                                   FILE *ef = fopen(stderr_log, "r");
                                   if (ef) {
                                       char ebuf[1024] = {0};
                                       size_t nr = fread(ebuf, 1, sizeof(ebuf) - 1, ef);
                                       fclose(ef);
                                       if (nr > 0) {
                                           while (nr > 0 && (ebuf[nr-1]=='\n'||ebuf[nr-1]=='\r'))
                                               ebuf[--nr] = '\0';
                                          zep_log("ws-node: pull_resume recv stderr: %s\n", ebuf);
                                      }
                                  }
                              }

                             char ack_json[4096];
                             int ack_n = snprintf(ack_json, sizeof(ack_json),
                                 "{\"action\":\"pull_ack\",\"guid\":\"%s\",\"exit_code\":%d}",
                                 guid_j->valuestring, pull_exit_code);
                             if (ack_n > 0) {
                                 ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                     (unsigned char *)ack_json, (size_t)ack_n);
                                 zep_log("ws-node: pull_resume ack sent\n");
                             }
                         }
                         cJSON_Delete(task);
                         continue;
                     }
                     /* Handle create_snap: create ZFS snapshot, report GUID back */
                     if (action && cJSON_IsString(action) &&
                         strcmp(action->valuestring, "create_snap") == 0) {
                        zep_log("ws-node: RX create_snap from server\n");
                        cJSON *cfs_j = cJSON_GetObjectItem(task, "cluster_fs");
                        cJSON *snap_j = cJSON_GetObjectItem(task, "snapshot");
                        cJSON *guid_j = cJSON_GetObjectItem(task, "guid");
                        if (cfs_j && cJSON_IsString(cfs_j) && snap_j && cJSON_IsString(snap_j) &&
                            guid_j && cJSON_IsString(guid_j)) {
                            const char *cfs = cfs_j->valuestring;
                            const char *snap = snap_j->valuestring;
                            const char *guid = guid_j->valuestring;

                            /* Resolve local filesystem from mapping */
                            const char *mp = cfg->mapping;
                            char local_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                            while (mp && *mp) {
                                while (*mp==' '||*mp=='\t') mp++;
                                if (!*mp) break;
                                const char *colon = strchr(mp, ':');
                                if (!colon) break;
                                size_t cflen = (size_t)(colon - mp);
                                char cfs_buf[512];
                                if (cflen >= sizeof(cfs_buf)) cflen = sizeof(cfs_buf) - 1;
                                memcpy(cfs_buf, mp, cflen);
                                cfs_buf[cflen] = '\0';
                                const char *start = colon + 1;
                                while (*start==' ') start++;
                                const char *end = strchr(start, ',');
                                if (!end) end = start + strlen(start);
                                const char *paren = strchr(start, '(');
                                size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
                                char resolved[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                if (n >= sizeof(resolved)) n = sizeof(resolved) - 1;
                                memcpy(resolved, start, n);
                                resolved[n] = '\0';
                                if (strcmp(cfs_buf, cfs) == 0) {
                                    snprintf(local_fs, sizeof(local_fs), "%s", resolved);
                                    break;
                                }
                                const char *comma = strchr(colon, ',');
                                mp = comma ? comma + 1 : colon + strlen(colon);
                            }

                            if (local_fs[0]) {
                                /* snap is cluster_fs@name — extract @name part for local fs */
                                const char *at = strchr(snap, '@');
                                char local_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                if (at) {
                                    snprintf(local_snap, sizeof(local_snap),
                                        "%s%s", local_fs, at);
                                } else {
                                    snprintf(local_snap, sizeof(local_snap),
                                        "%s@%s", local_fs, snap);
                                }
                                char cmd[4096];
                                snprintf(cmd, sizeof(cmd),
                                    "zfs snapshot -g 'guid' '%s'",
                                    local_snap);
                                zep_log("create_snap: %s\n", cmd);

                                /* Run snapshot command, capture stdout for guid */
                                FILE *fp = audit_popen(cmd);
                                char stdout_buf[64] = {0};
                                char real_guid[33] = {0};
                                char errbuf[256] = {0};
                                int exit_code = -1;
                                if (fp) {
                                    if (fgets(stdout_buf, (int)sizeof(stdout_buf), fp)) {
                                        size_t len = strlen(stdout_buf);
                                        while (len > 0 && (stdout_buf[len-1]=='\n'||stdout_buf[len-1]=='\r'))
                                            stdout_buf[--len] = '\0';
                                        if (stdout_buf[0]) {
                                            snprintf(real_guid, sizeof(real_guid), "%s", stdout_buf);
                                        }
                                    }
                                    exit_code = audit_popen_result(fp, errbuf, sizeof(errbuf));
                                    audit_log_err("create_snap", "zfs", cmd, exit_code, errbuf);
                                    zep_log("create_snap: rc=%d guid=%s\n",
                                        exit_code, real_guid);

                                    char resp[512];
                                    int rn = snprintf(resp, sizeof(resp),
                                        "{\"action\":\"create_snap\",\"guid\":\"%s\",\"rc\":%d}",
                                        real_guid[0] ? real_guid : guid, exit_code);
                                    ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                        (unsigned char *)resp, (size_t)rn);
                                } else {
                                    zep_log("create_snap: popen failed\n");
                                    char resp[256];
                                    int rn = snprintf(resp, sizeof(resp),
                                        "{\"action\":\"create_snap\",\"guid\":\"%s\",\"rc\":1}",
                                        guid);
                                    ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                        (unsigned char *)resp, (size_t)rn);
                                }
                            } else {
                                zep_log("create_snap: no mapping for %s\n", cfs);
                                char resp[256];
                                int rn = snprintf(resp, sizeof(resp),
                                    "{\"action\":\"create_snap\",\"rc\":1}");
                                ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                    (unsigned char *)resp, (size_t)rn);
                            }
                        }
                    }
                    /* Handle rotation: destroy excess ZFS snapshots */
                    if (action && cJSON_IsString(action) &&
                        strcmp(action->valuestring, "rotation") == 0) {
                        zep_log("ws-node: RX rotation from server\n");
                        cJSON *rotate = cJSON_GetObjectItem(task, "rotate");
                        cJSON *deleted = cJSON_CreateArray();
                        if (rotate && cJSON_IsArray(rotate)) {
                            cJSON *item;
                            cJSON_ArrayForEach(item, rotate) {
                                cJSON *g = cJSON_GetObjectItem(item, "guid");
                                cJSON *sn = cJSON_GetObjectItem(item, "snapshot");
                                cJSON *cf = cJSON_GetObjectItem(item, "cluster_fs");
                                if (!g || !sn || !cf) continue;

                                const char *at_sign = strchr(sn->valuestring, '@');
                                const char *at_name = at_sign ? at_sign : "";

                                const char *mp = cfg->mapping;
                                char local_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                while (mp && *mp) {
                                    while (*mp==' '||*mp=='\t') mp++;
                                    if (!*mp) break;
                                    const char *colon = strchr(mp, ':');
                                    if (!colon) break;
                                    size_t cflen = (size_t)(colon - mp);
                                    char cfs_buf[512] = {0};
                                    if (cflen >= sizeof(cfs_buf)) cflen = sizeof(cfs_buf) - 1;
                                    memcpy(cfs_buf, mp, cflen);
                                    const char *start = colon + 1;
                                    while (*start==' ') start++;
                                    const char *end = strchr(start, ',');
                                    if (!end) end = start + strlen(start);
                                    const char *paren = strchr(start, '(');
                                    size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
                                    char resolved[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                    if (n >= sizeof(resolved)) n = sizeof(resolved) - 1;
                                    memcpy(resolved, start, n);
                                    resolved[n] = '\0';
                                    if (strcmp(cfs_buf, cf->valuestring) == 0) {
                                        snprintf(local_fs, sizeof(local_fs), "%s", resolved);
                                        break;
                                    }
                                    const char *comma = strchr(colon, ',');
                                    mp = comma ? comma + 1 : colon + strlen(colon);
                                }

                                if (local_fs[0] && at_name[0]) {
                                    char dcmd[ZEP_MAX_SNAPSHOT_NAME * 2 + 64];
                                    snprintf(dcmd, sizeof(dcmd),
                                        "zfs destroy '%s%s'",
                                        local_fs, at_name);
                                    zep_log("rotation: %s\n", dcmd);
                                    int rc = system(dcmd);
                                    if (rc == 0)
                                        zep_log("rotation: destroyed %s\n",
                                            sn->valuestring);
                                    else
                                        zep_log("rotation: destroy rc=%d for %s\n",
                                            rc, sn->valuestring);
                                    cJSON_AddItemToArray(deleted,
                                        cJSON_CreateString(g->valuestring));
                                }
                            }
                        }
                        cJSON *ack_obj = cJSON_CreateObject();
                        cJSON_AddStringToObject(ack_obj, "action", "rotate-ack");
                        cJSON_AddItemToObject(ack_obj, "deleted", deleted);
                        cJSON_AddItemToObject(ack_obj, "remaining", cJSON_CreateArray());
                        char *ack_js = cJSON_PrintUnformatted(ack_obj);
                        cJSON_Delete(ack_obj);
                        ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                            (unsigned char *)ack_js, strlen(ack_js));
                        free(ack_js);
                    }
                    /* Handle push: stream zfs send to server */
                    if (action && cJSON_IsString(action) &&
                        strcmp(action->valuestring, "push") == 0) {
                        zep_log("ws-node: RX push from server\n");
                        cJSON *guid_j = cJSON_GetObjectItem(task, "guid");
                        cJSON *snap_j = cJSON_GetObjectItem(task, "snapshot");
                        cJSON *lbl_j = cJSON_GetObjectItem(task, "label");
                        cJSON *cfs_j = cJSON_GetObjectItem(task, "cluster_fs");
                        cJSON *bg_j = cJSON_GetObjectItem(task, "base_guid");
                        cJSON *rt_j = cJSON_GetObjectItem(task, "resume_token");
                        cJSON *bs_j = cJSON_GetObjectItem(task, "base_snap");
                        if (guid_j && cJSON_IsString(guid_j) &&
                            snap_j && cJSON_IsString(snap_j) &&
                            cfs_j && cJSON_IsString(cfs_j)) {
                            const char *pguid = guid_j->valuestring;
                            const char *psnap = snap_j->valuestring;
                            const char *plbl = lbl_j && cJSON_IsString(lbl_j) ? lbl_j->valuestring : "";
                            const char *pcfs = cfs_j->valuestring;
                            const char *pbg = (bg_j && cJSON_IsString(bg_j)) ? bg_j->valuestring : "";
                            const char *prt = (rt_j && cJSON_IsString(rt_j)) ? rt_j->valuestring : "";
                            const char *pbs = (bs_j && cJSON_IsString(bs_j)) ? bs_j->valuestring : "";

                            /* Resolve local snapshot name from mapping */
                            const char *mp = cfg->mapping;
                            char local_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
                            char local_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                            while (mp && *mp) {
                                while (*mp==' '||*mp=='\t') mp++;
                                if (!*mp) break;
                                const char *colon = strchr(mp, ':');
                                if (!colon) break;
                                size_t cflen = (size_t)(colon - mp);
                                char cfs_buf[512];
                                if (cflen >= sizeof(cfs_buf)) cflen = sizeof(cfs_buf) - 1;
                                memcpy(cfs_buf, mp, cflen);
                                cfs_buf[cflen] = '\0';
                                const char *start = colon + 1;
                                while (*start==' ') start++;
                                const char *end = strchr(start, ',');
                                if (!end) end = start + strlen(start);
                                const char *paren = strchr(start, '(');
                                size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
                                char resolved[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                if (n >= sizeof(resolved)) n = sizeof(resolved) - 1;
                                memcpy(resolved, start, n);
                                resolved[n] = '\0';
                                if (strcmp(cfs_buf, pcfs) == 0) {
                                    const char *at = strchr(psnap, '@');
                                    if (at) {
                                        snprintf(local_snap, sizeof(local_snap), "%s%s", resolved, at);
                                    } else {
                                        snprintf(local_snap, sizeof(local_snap), "%s@%s", resolved, psnap);
                                    }
                                    snprintf(local_fs, sizeof(local_fs), "%s", resolved);
                                    break;
                                }
                                const char *comma = strchr(colon, ',');
                                mp = comma ? comma + 1 : colon + strlen(colon);
                            }

                             if (local_snap[0]) {
                                      char send_cmd[4096];
                                       int is_resume_push = (prt && prt[0]);
                                       int n = 0;
                                       if (is_resume_push) {
                                            n += snprintf(send_cmd + n, sizeof(send_cmd) - (size_t)n,
                                                "zfs send -t '%s'", prt);
                                       } else if (pbs && pbs[0]) {
                                           n += snprintf(send_cmd + n, sizeof(send_cmd) - (size_t)n,
                                               "zfs send -i '%s' '%s'", pbs, local_snap);
                                       } else {
                                           n += snprintf(send_cmd + n, sizeof(send_cmd) - (size_t)n,
                                               "zfs send '%s'", local_snap);
                                       }
                                       if (cfg->send_options[0] && !is_resume_push) {
                                           n += snprintf(send_cmd + n, sizeof(send_cmd) - (size_t)n,
                                               " %s", cfg->send_options);
                                       }
                                       if (cfg->push_buf_cmd[0]) {
                                           n += snprintf(send_cmd + n, sizeof(send_cmd) - (size_t)n,
                                               " | %s", cfg->push_buf_cmd);
                                       }
                                       if (cfg->push_zip_cmd[0]) {
                                           n += snprintf(send_cmd + n, sizeof(send_cmd) - (size_t)n,
                                               " | %s", cfg->push_zip_cmd);
                                       }
                                       if (cfg->debug_inject_zfs_pipeline_cmd[0]) {
                                           n += snprintf(send_cmd + n, sizeof(send_cmd) - (size_t)n,
                                               " | %s", cfg->debug_inject_zfs_pipeline_cmd);
                                       }
                                     zep_log("push: %s (resume=%d)\n", send_cmd, is_resume_push);

                                     FILE *send_fp = popen(send_cmd, "r");
                                     if (send_fp) {
                                          char push_req[4096];
                                          int pn;
                                          if (is_resume_push) {
                                              pn = snprintf(push_req, sizeof(push_req),
                                                  "{\"action\":\"push\",\"guid\":\"%s\",\"base_guid\":\"%s\","
                                                  "\"snapshot\":\"%s\",\"label\":\"%s\",\"cluster_fs\":\"%s\","
                                                  "\"resume_token\":\"%s\"}",
                                                  pguid, pbg ? pbg : "", local_snap, plbl, pcfs, prt);
                                          } else {
                                              pn = snprintf(push_req, sizeof(push_req),
                                                  "{\"action\":\"push\",\"guid\":\"%s\",\"base_guid\":\"%s\","
                                                  "\"snapshot\":\"%s\",\"label\":\"%s\",\"cluster_fs\":\"%s\"}",
                                                  pguid, pbg ? pbg : "", local_snap, plbl, pcfs);
                                          }
                                         if (ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                             (unsigned char *)push_req, (size_t)pn) < 0) {
                                             zep_log("push: send request failed\n");
                                             int ck = pclose(send_fp);
                                             audit_log("push_send", "zfs", send_cmd,
                                                 WIFEXITED(ck) ? WEXITSTATUS(ck) : -128);
                                             char pres = 1;
                                             (void)!write(g_push_ws_resp_pipe[1], &pres, 1);
                                         } else {
                                             unsigned char *pipe_buf = malloc(WS_NODE_FRAME_MAX);
                                              int pipe_err = 0;
                                              int pipe_eof = 0;
                                              int resumed = 0;
                                              int ws_fd = conn->sock;
                                              while (1) {
                                                  fd_set rfds;
                                                  FD_ZERO(&rfds);
                                                  if (!pipe_eof && send_fp) {
                                                      FD_SET(fileno(send_fp), &rfds);
                                                  }
                                                  if (ws_fd >= 0) FD_SET(ws_fd, &rfds);
                                                  int maxfd = 0;
                                                  if (!pipe_eof && send_fp) {
                                                      int pipefd = fileno(send_fp);
                                                      maxfd = pipefd;
                                                  }
                                                  if (ws_fd >= 0 && ws_fd > maxfd) maxfd = ws_fd;
                                                  if (maxfd <= 0) break;
                                                  int sel = select(maxfd + 1, &rfds, NULL, NULL, NULL);
                                                  if (sel <= 0) continue;
                                                  if (!pipe_eof && send_fp && FD_ISSET(fileno(send_fp), &rfds)) {
                                                      size_t nr = fread(pipe_buf, 1, WS_NODE_FRAME_MAX, send_fp);
                                                      if (nr > 0) {
                                                          zep_log("push: sending BIN frame size=%zu\n", nr);
                                                          if (ws_node_send_frame(conn, WS_NODE_OP_BIN, pipe_buf, nr) < 0) {
                                                              pipe_err = 1; break;
                                                          }
                                                       } else {
                                                           pipe_eof = 1;
                                                           int ck = pclose(send_fp);
                                                           audit_log("push_send", "zfs", send_cmd,
                                                               WIFEXITED(ck) ? WEXITSTATUS(ck) : -128);
                                                           send_fp = NULL;
                                                           if (resumed) {
                                                               unsigned char ex = (unsigned char)(WIFEXITED(ck) && WEXITSTATUS(ck) == 0 ? 0 : 1);
                                                               zep_log("push: resumed pipeline EOF, sending EXIT rc=%d\n", (int)ex);
                                                               ws_node_send_frame(conn, WS_NODE_OP_EXIT, &ex, 1);
                                                              resumed = 0;
                                                              pipe_eof = 0;
                                                              continue;
                                                           } else {
                                                                unsigned char ex = (unsigned char)(WIFEXITED(ck) && WEXITSTATUS(ck) == 0 ? 0 : 1);
                                                                zep_log("push: pipeline EOF, sending EXIT rc=%d\n", (int)ex);
                                                                ws_node_send_frame(conn, WS_NODE_OP_EXIT, &ex, 1);
                                                                ws_node_send_frame(conn, WS_NODE_OP_EOF, NULL, 0);
                                                            }
                                                      }
                                                  }
                                                  if (ws_fd >= 0 && FD_ISSET(ws_fd, &rfds)) {
                                                       unsigned char ws_op;
                                                       unsigned char ws_out[WS_NODE_FRAME_MAX];
                                                       ssize_t rn = ws_node_recv_frame(conn, ws_out, sizeof(ws_out), &ws_op);
                                                       if (rn > 0) {
                                                           if (ws_op == WS_NODE_OP_TEXT && rn > 0) {
                                                                char *txt = (char *)ws_out;
                                                                txt[rn > WS_NODE_FRAME_MAX ? WS_NODE_FRAME_MAX - 1 : rn] = '\0';
                                                                if (strstr(txt, "\"action\":\"resume\"")) {
                                                                     zep_log("push: RX resume request, re-opening pipeline\n");
                                                                     fflush(stderr);
                                                                     send_fp = popen(send_cmd, "r");
                                                                     if (!send_fp) { pipe_err = 1; break; }
                                                                     pipe_eof = 0;
                                                                     resumed = 1;
                                                                     zep_log("push: pipeline re-opened, fd=%d\n", fileno(send_fp));
                                                                     fflush(stderr);
                                                                 }
                                                            } else if (ws_op == WS_NODE_OP_EXIT || ws_op == WS_NODE_OP_EOF) {
                                                                zep_log("push: received EXIT/EOF from server, stopping\n");
                                                                if (send_fp) {
                                                                    int ck = pclose(send_fp);
                                                                    audit_log("push_send", "zfs", send_cmd,
                                                                        WIFEXITED(ck) ? WEXITSTATUS(ck) : -128);
                                                                    send_fp = NULL;
                                                                }
                                                                break;
                                                           }
                                                       } else if (rn < 0) {
                                                           break;
                                                       }
                                                   }
                                              }
                                              int send_rc = 0;
                                             if (send_fp) {
                                                send_rc = pclose(send_fp);
                                                send_fp = NULL;
                                                audit_log("push_send", "zfs", send_cmd,
                                                    WIFEXITED(send_rc) ? WEXITSTATUS(send_rc) : -128);
                                                zep_log("push: pipe closed rc=%d\n", send_rc);
                                                unsigned char ex = (unsigned char)(send_rc == 0 ? 0 : 1);
                                                ws_node_send_frame(conn, WS_NODE_OP_EXIT, &ex, 1);
                                             }
                                             if (pipe_err) {
                                                 char pres = 1;
                                                 (void)!write(g_push_ws_resp_pipe[1], &pres, 1);
                                             }
                                             free(pipe_buf);
                                         }
                                     } else {
                                         zep_log("push: popen failed\n");
                                         char resp[256];
                                         int rn = snprintf(resp, sizeof(resp),
                                             "{\"action\":\"push\",\"guid\":\"%s\",\"rc\":1}", pguid);
                                         ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                             (unsigned char *)resp, (size_t)rn);
                                      }
                            } else {
                                zep_log("push: no mapping for %s\n", pcfs);
                                char resp[256];
                                int rn = snprintf(resp, sizeof(resp),
                                    "{\"action\":\"push\",\"rc\":1}");
                                ws_node_send_frame(conn, WS_NODE_OP_TEXT,
                                    (unsigned char *)resp, (size_t)rn);
                            }
                        }
                    }
                    cJSON_Delete(task);
                }
            }

            continue;
        }

        ws_node_disconnect(conn);
    }
    free(cfg);
    g_ws_exited = 1;
    return NULL;
}

static void usage(const char *prog) {
    zep_log(
        "Zeplicator Air v%s — air-gapped ZFS replication\n"
        "\n"
        "Usage: %s <command> [options]\n"
        "\n"
       "Commands:\n"
         "  cron    Connect to server via WebSocket, handle tasks & rotation\n"
         "  config  Manage configuration\n"
         "  status  Show replication status\n"
         "\n"
        "Config options:\n"
        "  set KEY VALUE          Set a configuration value\n"
        "  get KEY                Get a configuration value\n"
        "  list                   List all configuration\n"
        "  --db PATH              Database path (default: %s)\n"
        "\n"
        "Cron options:\n"
        "  --logging LEVELS   Comma-separated log levels: DEBUG,INFO,WARN,ERROR,AUDIT (default: INFO,WARN,ERROR)\n"
        "  --db PATH          Database path (default: %s)\n"
        "  --daemon, -d     Run as daemon (for cron)\n"
        "  --interval, -i N Poll interval in seconds (default: 60)\n"
        "\n"
        "Common config keys:\n"
        "  storage_root     Path to storage directory or mount\n"
        "  server_url       URL of zep-air-serve (for remote)\n"
        "  node_name        Name of this node\n"
        "  cert_path        Path to TLS client certificate\n"
        "  key_path         Path to TLS client key\n"
        "  ca_path          Path to CA certificate\n"
        "  key_password     Password for encrypted key\n"
        "  chunk_size       Max blob size in bytes (default: %d)\n",
        ZEP_VERSION, prog, g_db_path, g_db_path, g_db_path, g_db_path, g_db_path, ZEP_DEFAULT_CHUNK_SZ);
}
static int cmd_cron(int argc, char *argv[]) {
    int daemon_mode = 0;
    int interval = 60;

    static struct option opts[] = {
        {"daemon",  no_argument,       0, 'd'},
        {"interval", required_argument, 0, 'i'},
        {"db",       required_argument, 0, 'D'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "di:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'd': daemon_mode = 1; break;
            case 'i': interval = atoi(optarg); if (interval < 10) interval = 10; break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);
    zep_config_t cfg;
    db_config_load(db, &cfg);
    db_close(db);

    signal(SIGTERM, daemon_signal_handler);
    signal(SIGINT, daemon_signal_handler);
    signal(SIGHUP, daemon_signal_handler);

    /* Start WS pipe listener in daemon mode */
    if (daemon_mode && cfg.node_name[0]) {
        if (pipe(g_resume_req_pipe) < 0 || pipe(g_resume_resp_pipe) < 0) {
            zep_log( "cron: failed to create resume pipes\n");
        }
        if (pipe(g_pull_ws_req_pipe) < 0 || pipe(g_pull_ws_resp_pipe) < 0) {
            zep_log( "cron: failed to create pull_ws pipes\n");
        }
        if (pipe(g_push_ws_req_pipe) < 0 || pipe(g_push_ws_resp_pipe) < 0) {
            zep_log( "cron: failed to create push_ws pipes\n");
        }
        zep_config_t *tcfg = malloc(sizeof(*tcfg));
        if (tcfg) {
            memcpy(tcfg, &cfg, sizeof(*tcfg));
            pthread_create(&g_ws_tid, NULL, ws_node_pipe_thread, (void *)tcfg);
            pthread_detach(g_ws_tid);
            zep_log_debug( "cron: WS pipe listener started for %s\n", cfg.node_name);
        }
    }

    if (daemon_mode) {
        while (g_daemon_running) sleep(1);
        /* Wait for WS thread to exit cleanly */
        g_ws_shutdown = 1;
        for (int i = 0; i < 15 && !g_ws_exited; i++) sleep(1);
    }
    return 0;
}

static int cmd_config(int argc, char *argv[]) {
    if (argc < 2) {
        zep_log( "Usage: zep-air config <set|get|list> [args]\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    int rc = 0;
    const char *sub = argv[1];

    if (strcmp(sub, "set") == 0) {
        if (argc < 4) {
            zep_log( "Usage: zep-air config set KEY VALUE\n");
            rc = 1;
        } else {
            if (db_config_set(db, argv[2], argv[3]) != ZEP_ERR_OK) {
                zep_log( "Failed to set config\n");
                rc = 1;
            } else {
                printf("Set %s = %s\n", argv[2], argv[3]);
            }
        }
    } else if (strcmp(sub, "get") == 0) {
        if (argc < 3) {
            zep_log( "Usage: zep-air config get KEY\n");
            rc = 1;
        } else {
            char value[512] = {0};
            if (db_config_get(db, argv[2], value, sizeof(value)) != ZEP_ERR_OK) {
                printf("(not set)\n");
            } else {
                printf("%s\n", value);
            }
        }
    } else if (strcmp(sub, "list") == 0) {
        zep_config_t cfg;
        db_config_load(db, &cfg);
        printf("node_name    = %s\n", cfg.node_name[0] ? cfg.node_name : "(not set)");
        printf("storage_root = %s\n", cfg.storage_root[0] ? cfg.storage_root : "(not set)");
        printf("server_url   = %s\n", cfg.server_url[0] ? cfg.server_url : "(not set)");
        printf("cert_path    = %s\n", cfg.cert_path[0] ? cfg.cert_path : "(not set)");
        printf("key_path     = %s\n", cfg.key_path[0] ? cfg.key_path : "(not set)");
        printf("ca_path      = %s\n", cfg.ca_path[0] ? cfg.ca_path : "(not set)");
        printf("chunk_size   = %zu\n", cfg.chunk_size);
    } else if (strcmp(sub, "--help") == 0 || strcmp(sub, "-h") == 0) {
        printf("Usage: zep-air config <set|get|list> [args]\n");
    } else {
        zep_log( "Unknown config command: %s\n", sub);
        rc = 1;
    }

    db_close(db);
    return rc;
}

static int cmd_status(int argc, char *argv[]) {
    static struct option opts[] = {
        {"db",   required_argument, 0, 'D'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);
    zep_config_t cfg;
    db_config_load(db, &cfg);
    db_close(db);

    printf("=== Zeplicator Air Status ===\n");
    printf("Node:       %s\n", cfg.node_name[0] ? cfg.node_name : "(not set)");
    printf("Cluster:    %s\n", cfg.cluster[0] ? cfg.cluster : "(not set)");
    printf("Server:     %s\n", cfg.server_url[0] ? cfg.server_url : "(not set)");
    printf("Cert:       %s\n", cfg.cert_path[0] ? cfg.cert_path : "(not set)");
    printf("Mapping:    %s\n", cfg.mapping[0] ? cfg.mapping : "(not set)");
    printf("Chunk size: %zu\n", cfg.chunk_size);
    printf("\nPush/pull history is tracked on the server — no local snapshot DB.\n");
    return 0;
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    const char *argv2[64];
    int argc2 = 0;

    for (int i = 0; i < argc && argc2 < 63; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            i++;
            snprintf(g_db_path, sizeof(g_db_path), "%s", argv[i]);
        } else if (strcmp(argv[i], "--logging") == 0 && i + 1 < argc) {
            i++;
            g_logging = zep_log_parse_mask(argv[i]);
        } else if (strcmp(argv[i], "--audit-log") == 0 && i + 1 < argc) {
            i++;
            audit_init(argv[i]);
        } else {
            argv2[argc2++] = argv[i];
        }
    }
    argv2[argc2] = NULL;

    zep_log_init(g_db_path);

    if (argc2 < 2) {
        usage(argv2[0]);
        return 1;
    }

    const char *cmd = argv2[1];

    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage(argv2[0]);
        return 0;
    }

    char **sub_argv = (char **)argv2 + 1;
    int sub_argc = argc2 - 1;
    int rc = 1;

    if (strcmp(cmd, "cron") == 0)   rc = cmd_cron(sub_argc, sub_argv);
    else if (strcmp(cmd, "config") == 0) rc = cmd_config(sub_argc, sub_argv);
    else if (strcmp(cmd, "status") == 0) rc = cmd_status(sub_argc, sub_argv);
    else {
        zep_log( "Unknown command: %s\n", cmd);
        usage(argv2[0]);
    }

    return rc;
}

int pipeline_pull_ws(const zep_config_t *cfg, const http_config_t *http_cfg,
                     const char *fs, const char *donor,
                     const char *remote_guid, const char *local_guid,
                     sqlite3 *db) {
    (void)cfg; (void)http_cfg; (void)donor; (void)db;
    if (g_pull_ws_req_pipe[1] < 0) return 1;
    pthread_mutex_lock(&g_pull_ws_lock);
    snprintf(g_pull_ws_req.guid, sizeof(g_pull_ws_req.guid), "%s", remote_guid);
    snprintf(g_pull_ws_req.local_guid, sizeof(g_pull_ws_req.local_guid), "%s", local_guid ? local_guid : "");
    snprintf(g_pull_ws_req.fs, sizeof(g_pull_ws_req.fs), "%s", fs ? fs : "");
    g_pull_ws_req.ready = 1;
    pthread_mutex_unlock(&g_pull_ws_lock);

    (void)!write(g_pull_ws_req_pipe[1], "!", 1);

    char res;
    ssize_t r = read(g_pull_ws_resp_pipe[0], &res, 1);
    if (r == 1) return (int)res;
    return 1;
}

int pipeline_resume_request(const char *guid, const char *token, const char *fs) {
    if (g_resume_req_pipe[1] < 0) return 1;
    pthread_mutex_lock(&g_resume_lock);
    snprintf(g_resume_req.guid, sizeof(g_resume_req.guid), "%s", guid);
    snprintf(g_resume_req.token, sizeof(g_resume_req.token), "%s", token);
    snprintf(g_resume_req.fs, sizeof(g_resume_req.fs), "%s", fs ? fs : "");
    g_resume_req.ready = 1;
    pthread_mutex_unlock(&g_resume_lock);

    (void)!write(g_resume_req_pipe[1], "!", 1);

    char res;
    ssize_t r = read(g_resume_resp_pipe[0], &res, 1);
    if (r == 1) return (int)res;
    return 1;
}

int pipeline_push_ws(const zep_config_t *cfg, const char *fs,
                      const char *label, const char *cluster_fs,
                      sqlite3 *db, const char *ext_resume_token) {
      (void)cfg; (void)db;
      char snap_name[1024] = {0};
      char guid_str[ZEP_MAX_GUID_LEN] = {0};

      /* Find latest snapshot for this filesystem */
      char cmd[1024];
      snprintf(cmd, sizeof(cmd), "zfs list -Hp -t snapshot -o name,guid -S creation '%s'", fs);
      FILE *p = popen(cmd, "r");
      if (p) {
          char line[1024];
          while (fgets(line, sizeof(line), p)) {
              char *tab = strchr(line, '\t');
              if (!tab) continue;
              *tab = '\0';
              size_t fslen = strlen(fs);
              if (strncmp(line, fs, fslen) == 0 && line[fslen] == '@') {
                  char *g = tab + 1;
                  size_t gl = strlen(g);
                  while (gl > 0 && (g[gl-1]=='\n'||g[gl-1]=='\r')) g[--gl]='\0';
                  if (guid_str[0]) continue;
                  snprintf(guid_str, sizeof(guid_str), "%s", g);
                  snprintf(snap_name, sizeof(snap_name), "%s", line);
                  break;
              }
          }
          int rc = pclose(p);
          audit_log("snap_list", "zfs", cmd,
              WIFEXITED(rc) ? WEXITSTATUS(rc) : -128);
      }
      if (!guid_str[0]) {
          zep_log("push_ws: no snapshot guid found for fs=%s\n", fs);
          return 1;
      }

      /* Dispatch with found snapshot */
      (void)g_push_ws_req_pipe[1];
      pthread_mutex_lock(&g_push_ws_lock);
      snprintf(g_push_ws_req.guid, sizeof(g_push_ws_req.guid), "%s", guid_str);
      snprintf(g_push_ws_req.base_guid, sizeof(g_push_ws_req.base_guid), "%s", "");
      snprintf(g_push_ws_req.snapshot, sizeof(g_push_ws_req.snapshot), "%s", snap_name);
      snprintf(g_push_ws_req.label, sizeof(g_push_ws_req.label), "%s", label ? label : "");
      snprintf(g_push_ws_req.cluster_fs, sizeof(g_push_ws_req.cluster_fs), "%s", cluster_fs ? cluster_fs : "");
      g_push_ws_req.stream_size = 0;
      if (ext_resume_token && ext_resume_token[0])
          snprintf(g_push_ws_req.resume_token, sizeof(g_push_ws_req.resume_token), "%s", ext_resume_token);
      else
          g_push_ws_req.resume_token[0] = '\0';
      g_push_ws_req.ready = 1;
      pthread_mutex_unlock(&g_push_ws_lock);
      (void)!write(g_push_ws_req_pipe[1], "!", 1);
      char res;
      ssize_t r = read(g_push_ws_resp_pipe[0], &res, 1);
      if (r == 1) return (int)res;
      return 1;
}

int pipeline_push_ws_explicit(const zep_config_t *cfg, const char *snap_name,
                               const char *cluster_fs, const char *label,
                               sqlite3 *db, const char *ext_resume_token) {
      (void)cfg; (void)db;
      if (g_push_ws_req_pipe[1] < 0) return 1;

      char guid[ZEP_MAX_GUID_LEN] = {0};
      char cmd[1024];
      snprintf(cmd, sizeof(cmd),
          "zfs get -Hp -o value guid '%s'", snap_name);
      FILE *p = popen(cmd, "r");
      if (p) {
          if (fgets(guid, sizeof(guid), p)) {
              size_t gl = strlen(guid);
              while (gl > 0 && (guid[gl-1]=='\n'||guid[gl-1]=='\r')) guid[--gl]='\0';
          }
          int rc = pclose(p);
          audit_log("snap_guid", "zfs", cmd,
              WIFEXITED(rc) ? WEXITSTATUS(rc) : -128);
      }
      if (!guid[0]) {
          zep_log("push_ws_explicit: no guid found for snap=%s\n", snap_name);
          return 1;
      }

      pthread_mutex_lock(&g_push_ws_lock);
      snprintf(g_push_ws_req.guid, sizeof(g_push_ws_req.guid), "%s", guid);
      snprintf(g_push_ws_req.base_guid, sizeof(g_push_ws_req.base_guid), "%s", "");
      snprintf(g_push_ws_req.snapshot, sizeof(g_push_ws_req.snapshot), "%s", snap_name);
      snprintf(g_push_ws_req.label, sizeof(g_push_ws_req.label), "%s", label ? label : "");
      snprintf(g_push_ws_req.cluster_fs, sizeof(g_push_ws_req.cluster_fs), "%s", cluster_fs ? cluster_fs : "");
      g_push_ws_req.stream_size = 0;
      if (ext_resume_token && ext_resume_token[0])
          snprintf(g_push_ws_req.resume_token, sizeof(g_push_ws_req.resume_token), "%s", ext_resume_token);
      else
          g_push_ws_req.resume_token[0] = '\0';
      g_push_ws_req.ready = 1;
      pthread_mutex_unlock(&g_push_ws_lock);
      (void)!write(g_push_ws_req_pipe[1], "!", 1);
      char res;
      ssize_t r = read(g_push_ws_resp_pipe[0], &res, 1);
      if (r == 1) return (int)res;
      return 1;
}


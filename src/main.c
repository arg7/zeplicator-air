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

static void daemon_signal_handler(int sig) {
    (void)sig;
    g_daemon_running = 0;
    pthread_cancel(g_ws_tid);
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
    }
    if (c->sock >= 0) close(c->sock);
    free(c);
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

static struct ws_node_conn *ws_node_connect(const char *server_url, const char *cert_path,
                              const char *key_path, const char *ca_path,
                              const char *key_password, const char *path) {
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
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return NULL; }
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock); freeaddrinfo(res); return NULL;
    }
    freeaddrinfo(res);
    { struct timeval tv = { .tv_sec = 90, .tv_usec = 0 }; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }

    struct ws_node_conn *c = calloc(1, sizeof(*c));
    if (!c) { close(sock); return NULL; }
    c->sock = sock;

    SSL_CTX *ssl_ctx = NULL;
    if (use_tls) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) { ws_node_disconnect(c); return NULL; }
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return NULL;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return NULL;
        }
        if (ca_path && ca_path[0]) SSL_CTX_load_verify_locations(ssl_ctx, ca_path, NULL);
        if (key_password && key_password[0])
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *)key_password);

        c->ssl = SSL_new(ssl_ctx);
        SSL_set_fd(c->ssl, sock);
        if (SSL_connect(c->ssl) <= 0) {
            SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return NULL;
        }
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
        ws_node_disconnect(c); return NULL;
    }

    char resp_buf[1024];
    int resp_len = 0;
    for (;;) {
        int n = ws_node_read(c, resp_buf + resp_len, (int)(sizeof(resp_buf) - resp_len - 1));
        if (n <= 0) { if (ssl_ctx) SSL_CTX_free(ssl_ctx); ws_node_disconnect(c); return NULL; }
        resp_len += n;
        resp_buf[resp_len] = '\0';
        if (strstr(resp_buf, "\r\n\r\n")) break;
        if (resp_len >= (int)sizeof(resp_buf) - 1) break;
    }

    if (strstr(resp_buf, "101") == NULL) {
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        ws_node_disconnect(c); return NULL;
    }

    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    return c;
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

    prctl(PR_SET_PDEATHSIG, SIGTERM);

    for (;;) {
        char ws_path[256];
        snprintf(ws_path, sizeof(ws_path), "/v1/ws/node?cn=%s", cfg->node_name);

        zep_log_debug( "ws-node: connecting to %s%s\n", cfg->server_url, ws_path);

        struct ws_node_conn *conn = ws_node_connect(cfg->server_url, cfg->cert_path, cfg->key_path,
                                    cfg->ca_path, cfg->key_password, ws_path);
        if (!conn) {
            zep_log_debug( "ws-node: connect failed, retrying in 5s\n");
            sleep(5);
            continue;
        }

        unsigned char *buf = malloc(WS_NODE_FRAME_MAX);
        unsigned char *out = malloc(WS_NODE_FRAME_MAX);
        if (!buf || !out) { free(buf); free(out); ws_node_disconnect(conn); sleep(5); continue; }

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
                char _rrecv_cmd[2048] = {0};
                if (rfs[0]) {
                    char rcmd2[2048];
                    snprintf(rcmd2, sizeof(rcmd2),
                             "zfs recv -F -s -u '%s' 2>/dev/null", rfs);
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
                    snprintf(rcmd2, sizeof(rcmd2), "zfs recv -F -u '%s' 2>/dev/null", pfs);
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
                          snprintf(scmd, sizeof(scmd),
                              "set -o pipefail; exec zfs send %s -t '%s'%s%s%s%s%s%s",
                              cfg->send_options[0] ? cfg->send_options : "",
                              prt,
                              cfg->push_buf_cmd[0] ? " | " : "",
                              cfg->push_buf_cmd[0] ? cfg->push_buf_cmd : "",
                              cfg->push_zip_cmd[0] ? " | " : "",
                              cfg->push_zip_cmd[0] ? cfg->push_zip_cmd : "",
                              cfg->debug_inject_zfs_pipeline_cmd[0] ? " | " : "",
                              cfg->debug_inject_zfs_pipeline_cmd[0] ? cfg->debug_inject_zfs_pipeline_cmd : "");
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
                    if (send_fp) pclose(send_fp);
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
                }

                /* server_done was set by the main loop above */
                char pres = (push_ws_err || server_done != 1) ? 1 : 0;
                (void)!write(g_push_ws_resp_pipe[1], &pres, 1);
                continue;
            }

            if (!FD_ISSET(ws_fd, &rfds) && !ssl_pending) continue;

            ssize_t n = ws_node_recv_frame(conn, out, WS_NODE_FRAME_MAX, &buf[0]);
            unsigned char opcode = buf[0] & 0x0F;

            if (n < 0) { zep_log_debug( "ws-node: recv error, reconnecting\n"); break; }
            if (opcode == WS_NODE_OP_CLOSE) { zep_log_debug( "ws-node: close\n"); break; }
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
                                    ws_node_send_frame(conn, WS_NODE_OP_EXIT, &exit_byte, 1);
                                }
                                ws_node_send_frame(conn, WS_NODE_OP_CLOSE, NULL, 0);
                                break;
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
                                ws_node_send_frame(conn, WS_NODE_OP_EXIT, &exit_byte, 1);
                            }
                            ws_node_send_frame(conn, WS_NODE_OP_CLOSE, NULL, 0);
                            break;
                        }
                    }
                    cJSON_Delete(task);
                }
            }
        }

        free(buf); free(out);
        ws_node_disconnect(conn);
    }
    free(cfg);
    return NULL;
}

static void usage(const char *prog) {
    zep_log(
        "Zeplicator Air v%s — air-gapped ZFS replication\n"
        "\n"
        "Usage: %s <command> [options]\n"
        "\n"
       "Commands:\n"
         "  cron    Query server for due tasks, execute push/pull\n"
         "  rotate  Purge old snapshots beyond retention (safe, skips protected)\n"
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

static int cmd_rotate(int argc, char *argv[]) {
    char filesystem[ZEP_MAX_SNAPSHOT_NAME] = {0};

    static struct option opts[] = {
        {"filesystem", required_argument, 0, 'f'},
        {"db",         required_argument, 0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "f:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'f': snprintf(filesystem, sizeof(filesystem), "%s", optarg); break;
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

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);

    if (!cfg.cluster[0]) {
        zep_log( "rotate: no cluster configured\n");
        db_close(db);
        return 1;
    }

    char **protected_guids = NULL;
    int pcount = 0;
    {
        char *protected_url = NULL;
        if (asprintf(&protected_url, "/v1/cron/protected?%s", cfg.cluster) < 0) {
            db_close(db);
            return 1;
        }
        char *pj = http_get_json(&http_cfg, protected_url);
        free(protected_url);
        if (pj) {
            cJSON *pa = cJSON_Parse(pj);
            free(pj);
            if (pa && cJSON_IsArray(pa)) {
                pcount = cJSON_GetArraySize(pa);
                protected_guids = calloc((size_t)pcount, sizeof(char *));
                for (int i = 0; i < pcount; i++) {
                    cJSON *item = cJSON_GetArrayItem(pa, i);
                    if (item && cJSON_IsString(item))
                        protected_guids[i] = strdup(item->valuestring);
                }
                cJSON_Delete(pa);
            }
        }
    }

    char rot_url[256];
    snprintf(rot_url, sizeof(rot_url), "/v1/cron/rotation?cluster=%s", cfg.cluster);
    char *rj = http_get_json(&http_cfg, rot_url);
    int purged = 0;
    cJSON *deleted = cJSON_CreateArray();

    if (rj) {
        cJSON *rot = cJSON_Parse(rj);
        free(rj);
        if (rot) {
            cJSON *skip = cJSON_GetObjectItem(rot, "skip");
            if (!cJSON_IsTrue(skip)) {
                cJSON *list = cJSON_GetObjectItem(rot, "rotate");
                if (list && cJSON_IsArray(list)) {
                    cJSON *item;
                    cJSON_ArrayForEach(item, list) {
                        cJSON *sid = cJSON_GetObjectItem(item, "snapshot");
                        cJSON *sg = cJSON_GetObjectItem(item, "guid");
                        if (!sid || !cJSON_IsString(sid) ||
                            !sg || !cJSON_IsString(sg))
                            continue;

                        int prot = 0;
                        for (int k = 0; k < pcount; k++)
                            if (protected_guids[k] &&
                                strcmp(protected_guids[k], sg->valuestring) == 0)
                                { prot = 1; break; }

                        if (!prot && cfg.resume) {
                            cJSON *cf = cJSON_GetObjectItem(item, "cluster_fs");
                            cJSON *lb = cJSON_GetObjectItem(item, "label");
                            if (cf && lb && cJSON_IsString(cf) && cJSON_IsString(lb)) {
                                char skey[320], sval[ZEP_MAX_LINE * 2];
                                snprintf(skey, sizeof(skey), "push_state_%s_%s",
                                         cf->valuestring, lb->valuestring);
                                if (db_config_get(db, skey, sval, sizeof(sval)) == ZEP_ERR_OK && sval[0]) {
                                    char *save = NULL, *sc = strdup(sval);
                                    if (sc) {
                                        strtok_r(sc, ":", &save);
                                        char *sn = strtok_r(NULL, ":", &save);
                                        if (sn && strcmp(sn, sid->valuestring) == 0)
                                            prot = 1;
                                        free(sc);
                                    }
                                }
                            }
                        }
                        if (prot) continue;

                        char dcmd[1024];
                        snprintf(dcmd, sizeof(dcmd),
                            "zfs destroy '%s' 2>&1", sid->valuestring);
                        FILE *dp = popen(dcmd, "r");
                        if (dp) {
                            if (pclose(dp) == 0) {
                                printf("purged: %s (label=%s)\n",
                                    sid->valuestring,
                                    cJSON_GetObjectItem(item, "label")
                                        ? cJSON_GetObjectItem(item, "label")->valuestring : "");
                                purged++;
                                cJSON_AddItemToArray(deleted,
                                    cJSON_CreateString(sg->valuestring));
                            }
                        }
                    }
                }
            }
            cJSON_Delete(rot);
        }
    }

    if (cJSON_GetArraySize(deleted) > 0) {
        cJSON *ack = cJSON_CreateObject();
        cJSON_AddItemToObject(ack, "deleted", deleted);
        char *body = cJSON_PrintUnformatted(ack);
        cJSON_Delete(ack);
        http_post_json(&http_cfg, "/v1/cron/rotate-ack", body);
        free(body);
        deleted = cJSON_CreateArray();
    }
    cJSON_Delete(deleted);

    for (int i = 0; i < pcount; i++) free(protected_guids[i]);
    free(protected_guids);
    db_close(db);
    printf("rotate: purged %d snapshots\n", purged);
    return 0;
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

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);
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

    /* In daemon mode, maintain persistent curl handle for connection reuse */
    if (daemon_mode)
        http_persistent_start(&http_cfg);

    do {
        char *json = http_get_json(&http_cfg, "/v1/cron/sync");
        if (!json) {
            if (daemon_mode) { sleep((unsigned int)interval); continue; }
            return 1;
        }

        cJSON *tasks = cJSON_Parse(json);
        int task_count = tasks && cJSON_IsArray(tasks) ? cJSON_GetArraySize(tasks) : -1;
        zep_log( "cron: tasks=%d first=%.*s\n", task_count,
               (int)(strlen(json) < 200 ? strlen(json) : 200), json);
        free(json);
        if (!tasks || !cJSON_IsArray(tasks)) {
            if (tasks) cJSON_Delete(tasks);
            if (daemon_mode) { sleep((unsigned int)interval); continue; }
            return 1;
        }

        int tasks_done = 0;

        /* Collect push task pointers for batching (no ownership transfer) */
        cJSON **push_ptrs = NULL;
        int push_count = 0;
        {
            cJSON *item;
            int total = cJSON_GetArraySize(tasks);
            push_ptrs = malloc((size_t)total * sizeof(cJSON *));
            cJSON_ArrayForEach(item, tasks) {
                cJSON *action = cJSON_GetObjectItem(item, "action");
                if (!action || !cJSON_IsString(action) || strcmp(action->valuestring, "push") != 0) continue;
                cJSON *cfs = cJSON_GetObjectItem(item, "cluster_fs");
                if (!cfs || !cJSON_IsString(cfs)) continue;
                cJSON *lbl = cJSON_GetObjectItem(item, "label");
                if (!lbl || !cJSON_IsString(lbl)) continue;
                push_ptrs[push_count++] = item;
            }
        }

        /* Create snapshots for all push tasks that have a cluster,
         * track last snapshot name.  Always create — the server tells us
         * which labels are due.  The "create" flag on the first cycle is
         * just an optimization to avoid redundant creates. */
        char local_fs_last[ZEP_MAX_SNAPSHOT_NAME] = {0};
        char cfs_last[ZEP_MAX_PATH] = {0};
        char label_last[ZEP_MAX_SNAPSHOT_NAME] = {0};
        char snap_last[ZEP_MAX_PATH] = {0};
        /* Capture one timestamp for all snapshots (all created within same second) */
        time_t now = time(NULL);
        struct tm tm = {0};
        gmtime_r(&now, &tm);
        char ts_buf[32];
        strftime(ts_buf, sizeof(ts_buf), "%Y%m%d%H%M%S", &tm);

        for (int i = 0; i < push_count; i++) {
            cJSON *p = push_ptrs[i];
            cJSON *lbl = cJSON_GetObjectItem(p, "label");
            cJSON *cfs = cJSON_GetObjectItem(p, "cluster_fs");
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];

            if (db_open(g_db_path, &db) == ZEP_ERR_OK) {
                db_init_tables(db);
                zep_config_t cfg2;
                db_config_load(db, &cfg2);
                if (pipeline_resolve_fs(cfs->valuestring, cfg2.mapping,
                                        local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                    if (cfg2.cluster[0]) {
                        char snap_label[128];
                        snprintf(snap_label, sizeof(snap_label), "%s-%s-%s",
                                 cfg2.cluster, lbl->valuestring, ts_buf);
                        char snap_full[512];
                        snprintf(snap_full, sizeof(snap_full), "%s@%s", local_fs, snap_label);

                        /* Check if snapshot already exists */
                        char guid_cmd[1024];
                        snprintf(guid_cmd, sizeof(guid_cmd),
                                 "zfs get -Hp -o value guid '%s' 2>/dev/null", snap_full);
                        FILE *_guid_fp = audit_popen(guid_cmd);
                        if (_guid_fp) {
                            char _gline[128];
                            while (fgets(_gline, sizeof(_gline), _guid_fp)) {
                                char *nl = strchr(_gline, '\n');
                                if (nl) *nl = '\0';
                                if (_gline[0]) break;
                            }
                            pclose(_guid_fp);
                            if (_gline[0]) {
                                /* Snapshot already exists — skip create but still track it */
                            } else {
                                /* Does not exist — create it */
                                char snap_cmd[2048];
                                snprintf(snap_cmd, sizeof(snap_cmd),
                                         "zfs snapshot '%s'", snap_full);
                                zep_log("cron: creating snapshot '%s'\n", snap_label);
                                char _snap_err[512];
                                FILE *_snap_fp = audit_popen(snap_cmd);
                                int _snap_rc = _snap_fp ? audit_popen_result(_snap_fp, _snap_err, sizeof(_snap_err)) : -128;
                                audit_log_err("snapshot", "zfs", snap_cmd, _snap_rc, _snap_err);
                            }
                        }

                        if (i == push_count - 1 && cfg2.cluster[0]) {
                            snprintf(local_fs_last, sizeof(local_fs_last), "%s", local_fs);
                            snprintf(cfs_last, sizeof(cfs_last), "%s", cfs->valuestring);
                            snprintf(label_last, sizeof(label_last), "%s", lbl->valuestring);
                            snprintf(snap_last, sizeof(snap_last), "%s@%s", local_fs, snap_label);
                        }
                    } else {
                        if (i == push_count - 1) {
                            snprintf(local_fs_last, sizeof(local_fs_last), "%s", local_fs);
                            snprintf(cfs_last, sizeof(cfs_last), "%s", cfs->valuestring);
                            snprintf(label_last, sizeof(label_last), "%s", lbl->valuestring);
                        }
                    }
                }
                db_close(db);
            }
        }

        /* Push only the last task (most recent snapshot), ack all */
        for (int i = 0; i < push_count; i++) {
            cJSON *p = push_ptrs[i];
            cJSON *lbl = cJSON_GetObjectItem(p, "label");
            cJSON *cfs = cJSON_GetObjectItem(p, "cluster_fs");
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            if (db_open(g_db_path, &db) == ZEP_ERR_OK) {
                db_init_tables(db);
                zep_config_t cfg2;
                db_config_load(db, &cfg2);
                if (pipeline_resolve_fs(cfs->valuestring, cfg2.mapping,
                                        local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                    char ext_resume_token[ZEP_MAX_LINE] = {0};
                    cJSON *rto = cJSON_GetObjectItem(p, "resume_token");
                    if (rto && cJSON_IsString(rto) && rto->valuestring[0]) {
                        snprintf(ext_resume_token, sizeof(ext_resume_token),
                                 "%s", rto->valuestring);
                    }
                    if (i == push_count - 1 && cfg2.cluster[0] && snap_last[0]) {
                        /* Use explicit snapshot name to avoid ZFS -S creation
                         * tiebreaking when multiple snapshots share the same
                         * second timestamp */
                        pipeline_push_ws_explicit(&cfg2, snap_last,
                                         cfs_last, lbl->valuestring,
                                         db, ext_resume_token[0] ? ext_resume_token : NULL);
                    }
                    tasks_done++;
                    {
                        char body[512];
                        snprintf(body, sizeof(body),
                                 "{\"label\":\"%s\",\"cluster_fs\":\"%s\"}",
                                 lbl->valuestring, cfs->valuestring);
                        http_post_json(&http_cfg, "/v1/cron/ack", body);
                    }
                }
                db_close(db);
            }
        }

        free(push_ptrs);

        cJSON *task;
        cJSON_ArrayForEach(task, tasks) {
            cJSON *action = cJSON_GetObjectItem(task, "action");
            cJSON *cfs = cJSON_GetObjectItem(task, "cluster_fs");
            cJSON *label = cJSON_GetObjectItem(task, "label");

            if (!action || !cJSON_IsString(action)) continue;

            zep_log( "cron: task action=%s cfs=%s\n",
                   action->valuestring,
                   (cfs && cJSON_IsString(cfs)) ? cfs->valuestring : "(none)");

            if (strcmp(action->valuestring, "push") == 0 &&
                cfs && cJSON_IsString(cfs) &&
                label && cJSON_IsString(label)) {
                /* Already handled above — skip */
            } else if (strcmp(action->valuestring, "sync") == 0 &&
                       cfs && cJSON_IsString(cfs)) {
                cJSON *donor = cJSON_GetObjectItem(task, "donor");
                cJSON *snap_list = cJSON_GetObjectItem(task, "snapshots");
                char local_fs[ZEP_MAX_SNAPSHOT_NAME];
                if (db_open(g_db_path, &db) == ZEP_ERR_OK) {
                    db_init_tables(db);
                    zep_config_t cfg2;
                    db_config_load(db, &cfg2);
                    if (pipeline_resolve_fs(cfs->valuestring, cfg2.mapping,
                                            local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                        int nsnaps = (snap_list && cJSON_IsArray(snap_list)) ? cJSON_GetArraySize(snap_list) : 0;
                        zep_log( "cron: sync action cfs=%s local=%s donor=%s snaps=%d\n",
                               cfs->valuestring, local_fs,
                               (donor && cJSON_IsString(donor)) ? donor->valuestring : "",
                               nsnaps);
                        if (snap_list && cJSON_IsArray(snap_list) && cJSON_GetArraySize(snap_list) > 0) {
                            char local_guid[ZEP_MAX_GUID_LEN] = {0};
                            zfs_get_latest_guid(local_fs, local_guid, sizeof(local_guid));
                            cJSON *snap;
                            cJSON_ArrayForEach(snap, snap_list) {
                                cJSON *g = cJSON_GetObjectItem(snap, "guid");
                                if (!g || !cJSON_IsString(g)) continue;
                                zep_log("pull_ws: pulling guid=%s\n", g->valuestring);
                                pipeline_pull_ws(&cfg2, &http_cfg, local_fs,
                                    (donor && cJSON_IsString(donor)) ? donor->valuestring : "",
                                    g->valuestring, local_guid[0] ? local_guid : "", db);
                                zfs_get_latest_guid(local_fs, local_guid, sizeof(local_guid));
                            }
                        }
                        tasks_done++;

                        char latest[ZEP_MAX_GUID_LEN] = {0};
                        zfs_get_latest_guid(local_fs, latest, sizeof(latest));
                        if (latest[0]) {
                            char body[128];
                            snprintf(body, sizeof(body), "{\"guid\":\"%s\"}", latest);
                            http_post_json(&http_cfg, "/v1/cron/ack", body);
                        }
                    } else {
                        zep_log( "cron: resolve_fs FAILED for cfs=%s\n", cfs->valuestring);
                    }
                    db_close(db);
                }
            } else if (strcmp(action->valuestring, "inventory") == 0 &&
                       cfs && cJSON_IsString(cfs)) {
                zep_log( "cron: inventory action cfs=%s\n", cfs->valuestring);
                char local_fs[ZEP_MAX_SNAPSHOT_NAME];
                if (db_open(g_db_path, &db) == ZEP_ERR_OK) {
                    db_init_tables(db);
                    zep_config_t cfg2;
                    db_config_load(db, &cfg2);
                    if (pipeline_resolve_fs(cfs->valuestring, cfg2.mapping,
                                            local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                        cJSON *snaps = cJSON_CreateArray();
                        char cmd[1024];
                        snprintf(cmd, sizeof(cmd),
                            "zfs list -Hp -t snapshot -o name '%s' 2>/dev/null",
                            local_fs);
                        FILE *fp = popen(cmd, "r");
                        if (fp) {
                            char line[ZEP_MAX_SNAPSHOT_NAME];
                            while (fgets(line, sizeof(line), fp)) {
                                size_t sl = strlen(line);
                                while (sl > 0 && (line[sl-1] == '\n' || line[sl-1] == '\r'))
                                    line[--sl] = '\0';
                                if (!line[0]) continue;
                                char label[64] = {0};
                                char *at = strchr(line, '@');
                                if (at) {
                                    char *d1 = strchr(at + 1, '-');
                                    char *d2 = d1 ? strchr(d1 + 1, '-') : NULL;
                                    if (d2) {
                                        size_t ll = (size_t)(d2 - (at + 1));
                                        if (ll >= sizeof(label)) ll = sizeof(label) - 1;
                                        memcpy(label, at + 1, ll);
                                        label[ll] = '\0';
                                    }
                                }
                                char gbuf[ZEP_MAX_GUID_LEN] = {0};
                                char guid_cmd[2048], _guid_err[512];
                                snprintf(guid_cmd, sizeof(guid_cmd),
                                    "zfs get -Hp -o value guid '%s' 2>/dev/null", line);
                                FILE *gp = audit_popen(guid_cmd);
                                if (gp) {
                                    if (fgets(gbuf, sizeof(gbuf), gp)) {
                                        size_t gl = strlen(gbuf);
                                        while (gl > 0 && (gbuf[gl-1] == '\n' || gbuf[gl-1] == '\r'))
                                            gbuf[--gl] = '\0';
                                    }
                                    int _guid_rc = audit_popen_result(gp, _guid_err, sizeof(_guid_err));
                                    audit_log_err("inventory_guid", "zfs", guid_cmd, _guid_rc, _guid_err);
                                }
                                cJSON *sn = cJSON_CreateObject();
                                cJSON_AddStringToObject(sn, "guid", gbuf);
                                cJSON_AddStringToObject(sn, "snapshot", line);
                                cJSON_AddStringToObject(sn, "label", label);
                                cJSON_AddItemToArray(snaps, sn);
                            }
                            int list_rc = pclose(fp);
                            audit_log("inventory_list", "zfs", cmd, WIFEXITED(list_rc) ? WEXITSTATUS(list_rc) : -128);
                            }
                        cJSON *inv = cJSON_CreateObject();
                        cJSON_AddStringToObject(inv, "cluster_fs", cfs->valuestring);
                        cJSON_AddItemToObject(inv, "snapshots", snaps);
                        char *body = cJSON_PrintUnformatted(inv);
                        cJSON_Delete(inv);
                        http_post_json(&http_cfg, "/v1/cron/inventory", body);
                        free(body);
                        tasks_done++;
                    }
                    db_close(db);
                }
            }
        }
        cJSON_Delete(tasks);

        if (cfg.cluster[0]) {
            char rot_url[256];
            snprintf(rot_url, sizeof(rot_url), "/v1/cron/rotation?cluster=%s", cfg.cluster);
            char *rj = http_get_json(&http_cfg, rot_url);
            if (rj) {
                cJSON *rot = cJSON_Parse(rj);
                free(rj);
                if (rot) {
                    cJSON *skip = cJSON_GetObjectItem(rot, "skip");
                     if (!cJSON_IsTrue(skip)) {
                        cJSON *list = cJSON_GetObjectItem(rot, "rotate");
                        cJSON *deleted = cJSON_CreateArray();
                        if (list && cJSON_IsArray(list)) {
                            cJSON *item;
                            cJSON_ArrayForEach(item, list) {
                                cJSON *sid = cJSON_GetObjectItem(item, "snapshot");
                                cJSON *sg = cJSON_GetObjectItem(item, "guid");
                                if (sid && cJSON_IsString(sid) &&
                                    sg && cJSON_IsString(sg)) {
                                    /* protect snapshot if push is in progress (resume) */
                                    int prot2 = 0;
                                    if (cfg.resume) {
                                        cJSON *cf2 = cJSON_GetObjectItem(item, "cluster_fs");
                                        cJSON *lb2 = cJSON_GetObjectItem(item, "label");
                                        if (cf2 && lb2 && cJSON_IsString(cf2) && cJSON_IsString(lb2)) {
                                            char skey[320], sval[ZEP_MAX_LINE * 2];
                                            snprintf(skey, sizeof(skey), "push_state_%s_%s",
                                                     cf2->valuestring, lb2->valuestring);
                                            sqlite3 *rdb = NULL;
                                            if (db_open(g_db_path, &rdb) == ZEP_ERR_OK) {
                                                if (db_config_get(rdb, skey, sval, sizeof(sval)) == ZEP_ERR_OK && sval[0]) {
                                                    char *save = NULL, *sc = strdup(sval);
                                                    if (sc) {
                                                        strtok_r(sc, ":", &save);
                                                        char *sn = strtok_r(NULL, ":", &save);
                                                        if (sn && strcmp(sn, sid->valuestring) == 0)
                                                            prot2 = 1;
                                                        free(sc);
                                                    }
                                                }
                                                db_close(rdb);
                                            }
                                        }
                                    }
                                    if (prot2) continue;
                                    char dcmd[1024];
                                    snprintf(dcmd, sizeof(dcmd),
                                        "zfs destroy '%s' 2>/dev/null", sid->valuestring);
                                    char _dest_err[512];
                                    FILE *_dest_fp = audit_popen(dcmd);
                                    int _dest_rc = _dest_fp ? audit_popen_result(_dest_fp, _dest_err, sizeof(_dest_err)) : -128;
                                    audit_log_err("destroy", "zfs", dcmd, _dest_rc, _dest_err);
                                    int rc = _dest_rc;
                                    if (rc == 0) {
                                        cJSON_AddItemToArray(deleted,
                                            cJSON_CreateString(sg->valuestring));
                                        tasks_done++;
                                    }
                                }
                            }
                            cJSON *remaining = cJSON_CreateArray();
                            cJSON *seen = cJSON_CreateObject();
                            cJSON *item2;
                            cJSON_ArrayForEach(item2, list) {
                                cJSON *cf = cJSON_GetObjectItem(item2, "cluster_fs");
                                cJSON *lb = cJSON_GetObjectItem(item2, "label");
                                if (!cf || !lb) continue;
                                char key[256];
                                snprintf(key, sizeof(key), "%s:%s",
                                    cf->valuestring, lb->valuestring);
                                if (!cJSON_GetObjectItem(seen, key)) {
                                    cJSON_AddTrueToObject(seen, key);
                                    char local_fs[ZEP_MAX_SNAPSHOT_NAME];
                                    if (pipeline_resolve_fs(cf->valuestring,
                                            cfg.mapping, local_fs,
                                            sizeof(local_fs)) == ZEP_ERR_OK) {
                                        char cmd[1024];
                                        snprintf(cmd, sizeof(cmd),
                                            "zfs list -H -t snapshot '%s' 2>/dev/null | grep '@.*%s-' | wc -l",
                                            local_fs, lb->valuestring);
                                        FILE *fp = popen(cmd, "r");
                                        int count = 0;
                                        if (fp) {
                                            if (fscanf(fp, "%d", &count) != 1)
                                                count = 0;
                                            pclose(fp);
                                        }
                                        cJSON *r = cJSON_CreateObject();
                                        cJSON_AddStringToObject(r, "cluster_fs",
                                            cf->valuestring);
                                        cJSON_AddStringToObject(r, "label",
                                            lb->valuestring);
                                        cJSON_AddNumberToObject(r, "count", count);
                                        cJSON_AddItemToArray(remaining, r);
                                    }
                                }
                            }
                            cJSON_Delete(seen);
                            {
                                cJSON *ack = cJSON_CreateObject();
                                cJSON_AddItemToObject(ack, "deleted", deleted);
                                cJSON_AddItemToObject(ack, "remaining", remaining);
                                char *body = cJSON_PrintUnformatted(ack);
                                cJSON_Delete(ack);
                                http_post_json(&http_cfg, "/v1/cron/rotate-ack", body);
                                free(body);
                                deleted = cJSON_CreateArray();
                            }
                        } else {
                            cJSON_Delete(deleted);
                        }
                    }
                    cJSON_Delete(rot);
                }
            }
        }

        if (daemon_mode) {
            for (int s = 0; s < interval && g_daemon_running; s++)
                sleep(1);
        }
    } while (daemon_mode && g_daemon_running);

    if (daemon_mode)
        http_persistent_stop(&http_cfg);

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

    if (strcmp(cmd, "rotate") == 0) rc = cmd_rotate(sub_argc, sub_argv);
    else if (strcmp(cmd, "cron") == 0)   rc = cmd_cron(sub_argc, sub_argv);
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
      snprintf(cmd, sizeof(cmd), "zfs list -Hp -t snapshot -o name,guid -S creation '%s' 2>/dev/null", fs);
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
          pclose(p);
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
          "zfs get -Hp -o value guid '%s' 2>/dev/null", snap_name);
      FILE *p = popen(cmd, "r");
      if (p) {
          if (fgets(guid, sizeof(guid), p)) {
              size_t gl = strlen(guid);
              while (gl > 0 && (guid[gl-1]=='\n'||guid[gl-1]=='\r')) guid[--gl]='\0';
          }
          pclose(p);
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


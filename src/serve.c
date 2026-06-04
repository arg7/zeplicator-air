/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "common.h"
#include "db.h"
#include "zstream.h"
#include "auth.h"
#include "audit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <microhttpd.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cjson/cJSON.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

static char g_storage_root[ZEP_MAX_PATH] = "/var/lib/zep-air";
static char g_db_path[ZEP_MAX_PATH]       = "/var/lib/zep-air/zep-air.db";
static int  g_port = 8443;
static char g_cert_path[ZEP_MAX_PATH] = "";
static char g_key_path[ZEP_MAX_PATH] = "";
static char g_ca_path[ZEP_MAX_PATH] = "";
static char g_admin_cert_path[ZEP_MAX_PATH] = "";
static char g_key_password[128] = "";
static int  g_setup_mode = 0;
static int  g_no_tls = 0;
  static int  g_resume = 0;
    static char g_debug_inject_pull_cmd[128] = "";
    static char g_push_unzip_cmd[128] = "";
    static char g_pull_zip_cmd[128] = "";
    static struct MHD_Daemon *g_daemon = NULL;
static sqlite3 *g_db = NULL;


/* Persistent node WebSocket connection */
struct node_ws {
    struct node_ws *next;
    char cn[64];
    int sock;
    int ws_connected;
    int ws_closed;
    pthread_mutex_t lock;
    time_t last_ping;
    time_t last_pong;
    char pipe_cmd[4096];
    int pipe_starting;
    int pipe_thread_exited;
    int pipe_bridge_active;
    pthread_cond_t pipe_ready;
    /* Pipes for inter-thread data transfer */
    int pipe_admin_to_node[2];
    int pipe_node_to_admin[2];
    pthread_t thread;
};

#define MAX_NODE_WS 64
static struct node_ws *g_node_ws = NULL;
static pthread_mutex_t g_node_ws_lock = PTHREAD_MUTEX_INITIALIZER;

struct conn_ctx {
    char method[8];
    char target_url[512];
    char node[64];
    char prefix[128];
    char file[32];
    unsigned char *body;
    size_t body_len;
    size_t body_cap;
    int parsed;
    int authed;
    char role[16];
};

static void conn_ctx_free(struct conn_ctx *ctx) {
    if (ctx) {
        free(ctx->body);
        free(ctx);
    }
}

static void completed_cb(void *cls, struct MHD_Connection *conn,
                         void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls; (void)conn; (void)toe;
    if (*con_cls) {
        conn_ctx_free((struct conn_ctx *)*con_cls);
        *con_cls = NULL;
    }
}

static void parse_url(const char *url, struct conn_ctx *ctx) {
    memset(ctx->node, 0, sizeof(ctx->node));
    memset(ctx->prefix, 0, sizeof(ctx->prefix));
    memset(ctx->file, 0, sizeof(ctx->file));
    ctx->parsed = 0;

    int n = 0;
    char url_copy[512];
    snprintf(url_copy, sizeof(url_copy), "%s", url);

    if (strncmp(url_copy, "/v1/nodes/", 10) == 0) {
        char *save = NULL;
        char *tok = strtok_r(url_copy + 10, "/", &save);
        if (tok) {
            snprintf(ctx->node, sizeof(ctx->node), "%s", tok);
            n++;

            tok = strtok_r(NULL, "/", &save);
            if (tok && strcmp(tok, "snapshots") == 0) {
                tok = strtok_r(NULL, "/", &save);
                if (tok) {
                    snprintf(ctx->prefix, sizeof(ctx->prefix), "%s", tok);
                    n++;

                    tok = strtok_r(NULL, "/", &save);
                    if (tok) {
                        if (strcmp(tok, "meta") == 0) {
                            snprintf(ctx->file, sizeof(ctx->file), "meta");
                            n++;
                        } else if (strncmp(tok, "meta.json", 9) == 0) {
                            snprintf(ctx->file, sizeof(ctx->file), "meta.json");
                            n++;
                        } else if (strcmp(tok, "status") == 0) {
                            snprintf(ctx->file, sizeof(ctx->file), "status");
                            n++;
                        } else if (strcmp(tok, "blobs") == 0) {
                            tok = strtok_r(NULL, "", &save);
                            if (tok) {
                                snprintf(ctx->file, sizeof(ctx->file), "%s", tok);
                                n += 2;
                            }
                        }
                    }
                }
            }
        }
    }
    ctx->parsed = n;
}

static enum MHD_Result send_response(struct MHD_Connection *conn,
                                      int status, const char *ctype,
                                      const void *body, size_t body_len,
                                      struct conn_ctx *ctx) {
    if (ctx) {
        const char *method = ctx->method[0] ? ctx->method : "?";
        const char *role   = ctx->role[0]   ? ctx->role   : "?";
        zep_log("http: %s %s %s %s → %d (%zub)\n", ctx->node[0] ? ctx->node : "?", role, method, ctx->target_url, status, body_len);
    }
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        body_len, (void *)body, MHD_RESPMEM_MUST_COPY);
    if (!resp) return MHD_NO;
    if (ctype) MHD_add_response_header(resp, "Content-Type", ctype);
    enum MHD_Result ret = MHD_queue_response(conn, (unsigned int)status, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result send_error(struct MHD_Connection *conn, int status,
                                  const char *msg, struct conn_ctx *ctx) {
    return send_response(conn, status, "text/plain", msg, strlen(msg), ctx);
}

static enum MHD_Result send_json(struct MHD_Connection *conn, int status,
                                 const char *json, struct conn_ctx *ctx) {
    return send_response(conn, status, "application/json", json, strlen(json), ctx);
}

static char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    *len = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[*len] = '\0';
    return buf;
}


static struct node_ws *node_ws_find_locked(const char *cn) {
    for (struct node_ws *nw = g_node_ws; nw; nw = nw->next)
        if (strcmp(nw->cn, cn) == 0) return nw;
    return NULL;
}

static struct node_ws *node_ws_find(const char *cn) {
    pthread_mutex_lock(&g_node_ws_lock);
    struct node_ws *nw = node_ws_find_locked(cn);
    pthread_mutex_unlock(&g_node_ws_lock);
    return nw;
}

static struct node_ws *node_ws_register(const char *cn, int sock) {
    pthread_mutex_lock(&g_node_ws_lock);
    /* Signal existing connection to close gracefully */
    struct node_ws *nw = g_node_ws;
    while (nw) {
        if (strcmp(nw->cn, cn) == 0) {
            pthread_mutex_lock(&nw->lock);
            nw->ws_closed = 1;
            pthread_mutex_unlock(&nw->lock);
            break;
        }
        nw = nw->next;
    }
    nw = calloc(1, sizeof(*nw));
    if (!nw) { pthread_mutex_unlock(&g_node_ws_lock); return NULL; }
    snprintf(nw->cn, sizeof(nw->cn), "%s", cn);
    nw->sock = sock;
    nw->ws_connected = 1;
    nw->ws_closed = 0;
    nw->last_ping = time(NULL);
    nw->last_pong = time(NULL);
    nw->pipe_admin_to_node[0] = -1;
    nw->pipe_admin_to_node[1] = -1;
    nw->pipe_node_to_admin[0] = -1;
    nw->pipe_node_to_admin[1] = -1;
    pthread_mutex_init(&nw->lock, NULL);
    pthread_cond_init(&nw->pipe_ready, NULL);
    nw->pipe_thread_exited = 0;
    nw->next = g_node_ws;
    g_node_ws = nw;
    zep_log_debug("ws: node %s registered sock=%d\n", cn, sock);
    pthread_mutex_unlock(&g_node_ws_lock);
    return nw;
}

static void node_ws_shutdown(void) {
    pthread_mutex_lock(&g_node_ws_lock);
    for (struct node_ws *nw = g_node_ws; nw; nw = nw->next) {
        pthread_mutex_lock(&nw->lock);
        nw->ws_closed = 1;
        nw->pipe_starting = 1;
        pthread_cond_signal(&nw->pipe_ready);
        pthread_mutex_unlock(&nw->lock);
    }
    pthread_mutex_unlock(&g_node_ws_lock);

    /* Give threads time to notice ws_closed and exit */
    sleep(2);

    /* Wait for threads to exit cooperatively (up to 5s) */
    pthread_mutex_lock(&g_node_ws_lock);
    for (struct node_ws *nw = g_node_ws; nw; nw = nw->next) {
        if (!nw->thread) continue;
        pthread_mutex_unlock(&g_node_ws_lock);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += 5;
        int rc = pthread_timedjoin_np(nw->thread, NULL, &ts);

        int joined = (rc != EAGAIN);
        pthread_mutex_lock(&g_node_ws_lock);
        if (!joined)
            zep_log_warn("ws: node %s thread did not exit in 5s, abandoning\n", nw->cn);
        nw->thread = 0;

        if (!joined) continue;

        if (nw->pipe_admin_to_node[0] >= 0) close(nw->pipe_admin_to_node[0]);
        if (nw->pipe_admin_to_node[1] >= 0) close(nw->pipe_admin_to_node[1]);
        if (nw->pipe_node_to_admin[0] >= 0) close(nw->pipe_node_to_admin[0]);
        if (nw->pipe_node_to_admin[1] >= 0) close(nw->pipe_node_to_admin[1]);
        pthread_mutex_destroy(&nw->lock);
        pthread_cond_destroy(&nw->pipe_ready);
    }
    pthread_mutex_unlock(&g_node_ws_lock);
}

static void node_ws_unregister(struct node_ws *target) {
    pthread_mutex_lock(&g_node_ws_lock);
    struct node_ws *prev = NULL, *nw = g_node_ws;
    while (nw) {
        if (nw == target) {
            if (prev) prev->next = nw->next;
            else g_node_ws = nw->next;
zep_log_debug("ws: node %s unregistered\n", nw->cn);
            pthread_mutex_destroy(&nw->lock);
            pthread_cond_destroy(&nw->pipe_ready);
            if (!nw->pipe_bridge_active)
                free(nw);
            break;
        }
        prev = nw;
        nw = nw->next;
    }
    pthread_mutex_unlock(&g_node_ws_lock);
}

/* === WebSocket Support === */

#define WS_MAGIC "258EAFA5-E914-47DA-95CA-5AB5AC88212E"
#define WS_FRAME_MAX (32 * 1024 * 1024)
#define WS_OP_TEXT  0x01
#define WS_OP_BIN   0x02
#define WS_OP_EOF   0x03
#define WS_OP_EXIT  0x04
#define WS_OP_CLOSE 0x08
#define WS_OP_PING  0x09
#define WS_OP_PONG  0x0A

static int ws_build_accept(const char *client_key, char *accept, size_t accept_size) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    char buf[256];
    snprintf(buf, sizeof(buf), "%s%s", client_key, WS_MAGIC);
    SHA1((unsigned char *)buf, strlen(buf), hash);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, hash, SHA_DIGEST_LENGTH);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    snprintf(accept, accept_size, "%.*s", (int)(bptr->length - 1), bptr->data);
    BIO_free_all(b64);
    return 0;
}

static ssize_t ws_parse_frame(const unsigned char *buf, size_t buf_len,
                                unsigned char *out, size_t out_size,
                                unsigned char *opcode_out) {
    if (buf_len < 2) return -1;
    unsigned char opcode = buf[0] & 0x0F;
    int masked = (buf[1] >> 7) & 1;
    uint64_t payload_len = buf[1] & 0x7F;
    size_t header_len = 2;
    if (payload_len == 126) {
        if (buf_len < 4) return -1;
        payload_len = (buf[2] << 8) | buf[3];
        header_len = 4;
    } else if (payload_len == 127) {
        if (buf_len < 10) return -1;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | buf[2 + i];
        header_len = 10;
    }
    size_t mask_offset = header_len;
    if (masked) {
        header_len += 4;
        if (buf_len < header_len) return -1;
    }
    if (payload_len > out_size) return -1;
    if (buf_len < header_len + payload_len) return -1;
    const unsigned char *mask = masked ? buf + mask_offset : NULL;
    for (size_t i = 0; i < payload_len; i++)
        out[i] = masked ? buf[header_len + i] ^ mask[i % 4] : buf[header_len + i];
    *opcode_out = opcode;
    return (ssize_t)payload_len;
}

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
    if (payload_len > 0) memcpy(buf + header_len, payload, payload_len);
    return header_len + payload_len;
}

#define WS_SUBCHUNK (128 * 1024)
#define WS_ADMIN_BUF (WS_SUBCHUNK + 256)

static ssize_t ws_send_frame_gtls(struct node_ws *nw, unsigned char opcode,
                                    const unsigned char *payload, size_t payload_len) {
    unsigned char *frame = malloc(payload_len + 14);
    if (!frame) return -1;
    size_t flen = ws_build_frame(frame, payload_len + 14, opcode, payload, payload_len);
    if (flen == 0) {
        free(frame);
        return -1;
    }
    /* After WS upgrade, nw->sock is a non-blocking socketpair endpoint.
     * MHD's internal polling thread handles TLS: it decrypts data from the
     * real client socket via GnuTLS and writes plaintext to mhd.socket (sv[1]).
     * Our thread writes plaintext to app.socket (sv[0]=nw->sock). MHD reads
     * from mhd.socket, encrypts via GnuTLS, sends to client. No GnuTLS calls
     * from our thread — avoids race with MHD's internal polling thread. */
    ssize_t sent = 0;
    while ((size_t)sent < flen) {
        ssize_t n = send(nw->sock, frame + sent, flen - (size_t)sent, MSG_NOSIGNAL);
        zep_log_debug("ws_send_frame: sock=%d sent=%zd total=%zu errno=%d\n", nw->sock, n, flen, errno);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                fd_set wfds; FD_ZERO(&wfds); FD_SET(nw->sock, &wfds);
                struct timeval tv = { .tv_sec = 60, .tv_usec = 0 };
                if (select(nw->sock + 1, NULL, &wfds, NULL, &tv) <= 0) { free(frame); return -1; }
                continue;
            }
            free(frame);
            return -1;
        }
        sent += n;
    }
    free(frame);
    return (ssize_t)flen;
}

static ssize_t ws_recv_node(struct node_ws *nw, unsigned char *buf, size_t buf_size) {
    /* MHD's polling thread decrypts TLS data from the real client socket
     * and writes plaintext to mhd.socket (sv[1]).  Our thread reads from
     * app.socket (sv[0]=nw->sock) — plain socketpair, no GnuTLS needed. */
    for (;;) {
        ssize_t n = recv(nw->sock, buf, buf_size, 0);
        zep_log_debug("ws_recv_node: sock=%d n=%zd errno=%d\n", nw->sock, n, errno);
        if (n >= 0) return n;
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return n;
        /* Non-blocking socket: select + retry, but also handle the race
         * where select says data is available but recv still gets EAGAIN. */
        fd_set rfds; FD_ZERO(&rfds); FD_SET(nw->sock, &rfds);
        struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
        int sel = select(nw->sock + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) return -1;
        /* select says data available — try recv again */
    }
}

/* Thread-local buffer for leftover WS frame data between calls.
 * When multiple frames arrive in one TCP packet, we parse one,
 * keep the rest, and continue on the next call. */
static __thread size_t lt_buf_used = 0;
static __thread unsigned char lt_buf[128 * 1024 + 256];

static ssize_t ws_recv_frame_full(struct node_ws *nw, unsigned char *buf, size_t buf_size,
                                   unsigned char *out, size_t out_size,
                                   unsigned char *opcode_out) {
    (void)buf; (void)buf_size;
    size_t total_used = lt_buf_used;
    for (;;) {
        if (total_used >= 2) {
            uint64_t plen = lt_buf[1] & 0x7F;
            size_t need = 2;
            if (plen == 126) need = 4;
            else if (plen == 127) need = 10;
            if (total_used >= need) {
                int masked = (lt_buf[1] >> 7) & 1;
                size_t header_len = need;
                if (plen == 126)
                    plen = (lt_buf[2] << 8) | lt_buf[3];
                else if (plen == 127) {
                    plen = 0;
                    for (int i = 0; i < 8; i++)
                        plen = (plen << 8) | lt_buf[2 + i];
                }
                if (masked) header_len += 4;
                if (plen <= (uint64_t)out_size && header_len + (size_t)plen <= total_used) {
                    ssize_t r = ws_parse_frame(lt_buf, total_used, out, out_size, opcode_out);
                    if (r >= 0) {
                        size_t consumed = header_len + (size_t)r;
                        total_used -= consumed;
                        if (total_used > 0)
                            memmove(lt_buf, lt_buf + consumed, total_used);
                        lt_buf_used = total_used;
                        return r;
                    }
                    return -1;
                }
            }
        }
        if (total_used == sizeof(lt_buf)) {
            lt_buf_used = 0;
            return -1;
        }
        ssize_t n = ws_recv_node(nw, lt_buf + total_used, sizeof(lt_buf) - total_used);
        if (n <= 0) {
            lt_buf_used = total_used;
            return n;
        }
        total_used += (size_t)n;
    }
}

static void ws_make_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) return;
    if (flags & O_NONBLOCK)
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static void ws_set_keepalive(int fd) {
    int keepalive = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
    int idle = 30, interval = 10, count = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif
}


struct node_ws_thread_ctx {
    struct node_ws *nw;
};

#define MAX_PENDING 8

static void server_dispatch_rotation(struct node_ws *nw,
                                     const char *cluster_buf,
                                     const char *direction);

static void
scheduler_run(struct node_ws *nw, const char *cluster_buf,
    char pending_snaps[][ZEP_MAX_SNAPSHOT_NAME],
    char pending_labels[][64],
    int *pending_tail, const char *mapping_buf)
{
    char cluster_def[4096] = {0};
    char ckey[128];
    snprintf(ckey, sizeof(ckey), "cluster_%s", cluster_buf);
    db_config_get(g_db, ckey, cluster_def, sizeof(cluster_def));
    if (!cluster_def[0]) return;
    cJSON *cj = cJSON_Parse(cluster_def);
    if (!cj || !cJSON_IsObject(cj)) return;

    cJSON *pools = cJSON_GetObjectItem(cj, "pools");
    cJSON *labels = cJSON_GetObjectItem(cj, "labels");
    cJSON *fs_arr = cJSON_GetObjectItem(cj, "filesystems");
    time_t now = time(NULL);
    struct tm tm_sched;
    gmtime_r(&now, &tm_sched);
    char ts_str[16];
    strftime(ts_str, sizeof(ts_str), "%Y%m%d-%H%M%S", &tm_sched);

    if (pools && cJSON_IsObject(pools)) {
        cJSON *pool;
        cJSON_ArrayForEach(pool, pools) {
            const char *pool_name = pool->string;
            if (!pool_name || !cJSON_IsObject(pool)) continue;
            cJSON *dataset;
            cJSON_ArrayForEach(dataset, pool) {
                const char *ds_name = dataset->string;
                if (!ds_name || !cJSON_IsObject(dataset)) continue;
                cJSON *ds_obj = dataset;
                cJSON *lbls = cJSON_GetObjectItem(ds_obj, "labels");
                if (!lbls || !cJSON_IsObject(lbls)) continue;

                char cluster_fs[512];
                snprintf(cluster_fs, sizeof(cluster_fs), "%s/%s", pool_name, ds_name);
                /* Resolve cluster_fs to normalized name via mapping */
                if (mapping_buf[0]) {
                    const char *mp = mapping_buf;
                    const char *raw_fs = cluster_fs;
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
                        if (strcmp(raw_fs, resolved) == 0) {
                            snprintf(cluster_fs, sizeof(cluster_fs), "%s", cfs_buf);
                            break;
                        }
                        const char *comma = strchr(colon, ',');
                        mp = comma ? comma + 1 : colon + strlen(colon);
                    }
                }

                cJSON *lbl_item;
                cJSON_ArrayForEach(lbl_item, lbls) {
                    const char *ln = lbl_item->string;
                    int interval_sec = 60; /* default: "min" */
                      if (ln) {
                        char *end;
                        if (strncmp(ln, "min", 3) == 0) {
                            long val = strtol(ln + 3, &end, 10);
                            interval_sec = (end > ln + 3) ? (int)(val * 60) : 60;
                        } else if (strncmp(ln, "hour", 4) == 0) {
                            long val = strtol(ln + 4, &end, 10);
                            interval_sec = (end > ln + 4) ? (int)(val * 3600) : 3600;
                        } else if (strncmp(ln, "day", 3) == 0) {
                            long val = strtol(ln + 3, &end, 10);
                            interval_sec = (end > ln + 3) ? (int)(val * 86400) : 86400;
                        } else if (strncmp(ln, "week", 4) == 0) {
                            long val = strtol(ln + 4, &end, 10);
                            interval_sec = (end > ln + 4) ? (int)(val * 7 * 86400) : 7 * 86400;
                        } else if (strncmp(ln, "month", 5) == 0) {
                            long val = strtol(ln + 5, &end, 10);
                            interval_sec = (end > ln + 5) ? (int)(val * 30 * 86400) : 30 * 86400;
                        } else if (strncmp(ln, "year", 4) == 0) {
                            long val = strtol(ln + 4, &end, 10);
                            interval_sec = (end > ln + 4) ? (int)(val * 365 * 86400) : 365 * 86400;
                        }
                    }
                    if (!ln) continue;

                    char cron_key[1024];
                    snprintf(cron_key, sizeof(cron_key),
                        "cron_last_%s_%s_%s", cluster_buf, cluster_fs, ln);
                    char last_str[32] = {0};
                    db_config_get(g_db, cron_key, last_str, sizeof(last_str));

                    time_t last = 0;
                    if (last_str[0]) {
                        struct tm tm = {0};
                        if (strptime(last_str, "%Y-%m-%dT%H:%M:%SZ", &tm))
                            last = timegm(&tm);
                    }

                    if (last > 0 && (now - last) < interval_sec)
                        continue;

                    char snap_name[1024];
                    snprintf(snap_name, sizeof(snap_name),
                        "%s@%s-%s-%s",
                        cluster_fs, cluster_buf, ln, ts_str);

                    /* Skip if snapshot already exists in DB */
                    {
                        sqlite3_stmt *chk = NULL;
                        char chk_sql[2048];
                        /* Extract the @cluster-label-timestamp suffix from snap_name
                         * and match against the end of the snapshot column.
                         * The DB stores actual ZFS names (pool/fs@cluster-label-ts)
                         * while snap_name uses cluster_fs format. A suffix LIKE match
                         * covers both. */
                        const char *at = strchr(snap_name, '@');
                        if (at) {
                            int suffix_len = (int)strlen(at);
                            /* Escape SQL LIKE wildcards in the suffix */
                            char escaped[1024] = {0};
                            for (int i = 0; i < suffix_len && i < (int)sizeof(escaped) - 3; i++) {
                                char c = at[i];
                                if (c == '%' || c == '_') {
                                    escaped[strlen(escaped)] = '\\';
                                }
                                escaped[strlen(escaped)] = c;
                            }
                            snprintf(chk_sql, sizeof(chk_sql),
                                "SELECT 1 FROM snapshots WHERE node=?1 AND snapshot LIKE ?2 ESCAPE '\\\\'");
                            if (sqlite3_prepare_v2(g_db, chk_sql, -1, &chk, NULL) == SQLITE_OK) {
                                sqlite3_bind_text(chk, 1, nw->cn, -1, SQLITE_STATIC);
                                sqlite3_bind_text(chk, 2, escaped, -1, SQLITE_STATIC);
                                if (sqlite3_step(chk) == SQLITE_ROW) {
                                    sqlite3_finalize(chk);
                                    continue;
                                }
                                sqlite3_finalize(chk);
                            }
                        }
                    }

                    char task_json[2048];
                    int n = snprintf(task_json, sizeof(task_json),
                        "{\"action\":\"create_snap\",\"cluster_fs\":\"%s\",\"label\":\"%s\",\"snapshot\":\"%s\",\"guid\":\"\"}",
                        cluster_fs, ln, snap_name);
                    if (n > 0 && n < (int)sizeof(task_json)) {
                        zep_log("scheduler: create_snap %s (label=%s, interval=%ds)\n",
                            snap_name, ln, interval_sec);
                        if (*pending_tail < MAX_PENDING) {
                            snprintf(pending_snaps[*pending_tail], ZEP_MAX_SNAPSHOT_NAME, "%s", snap_name);
                            snprintf(pending_labels[*pending_tail], sizeof(pending_labels[0]), "%s", ln);
                            (*pending_tail)++;
                        }
                        ws_send_frame_gtls(nw, WS_OP_TEXT,
                            (unsigned char *)task_json, (size_t)n);
                    }
                }
            }
        }
    } else if (labels && cJSON_IsArray(labels) && fs_arr && cJSON_IsArray(fs_arr)) {
        cJSON *label_item;
        cJSON_ArrayForEach(label_item, labels) {
            const char *ln = cJSON_GetStringValue(label_item);
            if (!ln) continue;
            int interval_sec = 0;
            if (strncmp(ln, "min", 3) == 0) {
                char *end;
                long val = strtol(ln + 3, &end, 10);
                interval_sec = (end > ln + 3 && *end == 'N') ? (int)(val * 60) : 60;
            } else if (strncmp(ln, "hour", 4) == 0) {
                char *end;
                long val = strtol(ln + 4, &end, 10);
                interval_sec = (end > ln + 4 && *end == 'N') ? (int)(val * 3600) : 3600;
            } else if (strncmp(ln, "day", 3) == 0) {
                char *end;
                long val = strtol(ln + 3, &end, 10);
                interval_sec = (end > ln + 3 && *end == 'N') ? (int)(val * 86400) : 86400;
            } else if (strncmp(ln, "week", 4) == 0) {
                char *end;
                long val = strtol(ln + 4, &end, 10);
                interval_sec = (end > ln + 4 && *end == 'N') ? (int)(val * 604800) : 7 * 86400;
            }
            if (interval_sec == 0) continue;

            cJSON *fs_item;
            cJSON_ArrayForEach(fs_item, fs_arr) {
                const char *cluster_fs = cJSON_GetStringValue(fs_item);
                if (!cluster_fs) continue;

                char cron_key[1024];
                snprintf(cron_key, sizeof(cron_key),
                    "cron_last_%s_%s_%s", cluster_buf, cluster_fs, ln);
                char last_str[32] = {0};
                db_config_get(g_db, cron_key, last_str, sizeof(last_str));

                time_t last = 0;
                if (last_str[0]) {
                    struct tm tm = {0};
                    if (strptime(last_str, "%Y-%m-%dT%H:%M:%SZ", &tm))
                        last = timegm(&tm);
                }

                if (last > 0 && (now - last) < interval_sec)
                    continue;

                char snap_name[1024];
                snprintf(snap_name, sizeof(snap_name),
                    "%s@%s-%s-%s",
                    cluster_fs, cluster_buf, ln, ts_str);

                char task_json[2048];
                int n = snprintf(task_json, sizeof(task_json),
                    "{\"action\":\"create_snap\",\"cluster_fs\":\"%s\",\"label\":\"%s\",\"snapshot\":\"%s\",\"guid\":\"\"}",
                    cluster_fs, ln, snap_name);
                if (n > 0 && n < (int)sizeof(task_json)) {
                    zep_log("scheduler: create_snap %s (label=%s, interval=%ds)\n",
                        snap_name, ln, interval_sec);
                    if (*pending_tail < MAX_PENDING) {
                        snprintf(pending_snaps[*pending_tail], ZEP_MAX_SNAPSHOT_NAME, "%s", snap_name);
                        snprintf(pending_labels[*pending_tail], sizeof(pending_labels[0]), "%s", ln);
                        (*pending_tail)++;
                    }
                    ws_send_frame_gtls(nw, WS_OP_TEXT,
                        (unsigned char *)task_json, (size_t)n);
                }
            }
        }
    }
    cJSON_Delete(cj);
}

/* ── Pull trigger: find next snapshot to send to client ── */
static void node_ws_pull_trigger(struct node_ws *nw, const char *cluster_buf,
                                  const char *role_buf) {
    if (strcmp(role_buf, "client") != 0) return;
    if (!nw->cn[0] || !cluster_buf[0]) return;

    /* Find the master node for this cluster */
    char master_cn[64] = {0};
    {
        sqlite3_stmt *ms = NULL;
        if (sqlite3_prepare_v2(g_db,
            "SELECT cn FROM auth WHERE cluster = ?1 AND role = 'master' LIMIT 1",
            -1, &ms, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ms, 1, cluster_buf, -1, SQLITE_STATIC);
            if (sqlite3_step(ms) == SQLITE_ROW) {
                const char *m = (const char *)sqlite3_column_text(ms, 0);
                if (m) snprintf(master_cn, sizeof(master_cn), "%s", m);
            }
            sqlite3_finalize(ms);
        }
    }
    if (!master_cn[0]) {
        zep_log_debug("pull_trigger: no master for cluster %s\n", cluster_buf);
        return;
    }

    /* Find common GUID between master and client (only fully-pulled client records count) */
    sqlite3_stmt *common_st = NULL;
    if (sqlite3_prepare_v2(g_db,
        "SELECT s1.guid, s1.base_guid, s1.snapshot, s1.storage_base "
        "FROM snapshots s1 "
        "INNER JOIN snapshots s2 ON s1.guid = s2.guid "
        "WHERE s1.node = ?1 AND s2.node = ?2 "
        "  AND s1.direction = 'push' AND s2.direction = 'pull' "
        "  AND s2.pull_status = 'pulled' "
        "ORDER BY s1.id DESC LIMIT 1",
        -1, &common_st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(common_st, 1, master_cn, -1, SQLITE_STATIC);
        sqlite3_bind_text(common_st, 2, nw->cn, -1, SQLITE_STATIC);
    }

    char common_guid[ZEP_MAX_GUID_LEN] = {0};
    char common_base[ZEP_MAX_GUID_LEN] = {0};
    char common_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
    char common_storage[ZEP_MAX_PATH * 2 + 256] = {0};

    if (common_st) {
        if (sqlite3_step(common_st) == SQLITE_ROW) {
            const char *g = (const char *)sqlite3_column_text(common_st, 0);
            const char *b = (const char *)sqlite3_column_text(common_st, 1);
            const char *s = (const char *)sqlite3_column_text(common_st, 2);
            const char *sb = (const char *)sqlite3_column_text(common_st, 3);
            if (g) snprintf(common_guid, sizeof(common_guid), "%s", g);
            if (b) snprintf(common_base, sizeof(common_base), "%s", b);
            if (s) snprintf(common_snap, sizeof(common_snap), "%s", s);
            if (sb) snprintf(common_storage, sizeof(common_storage), "%s", sb);
        }
        sqlite3_finalize(common_st);
    }

    /* Determine what to send: find latest verified master snap not yet pulled by client */
    char target_guid[ZEP_MAX_GUID_LEN] = {0};
    char target_base[ZEP_MAX_GUID_LEN] = {0};
    char target_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
    char target_storage[ZEP_MAX_PATH * 2 + 256] = {0};
    char target_cfs[512] = {0};

    /* Find any verified master snap with storage_base, not yet pulled by this client, excluding common GUID */
    sqlite3_stmt *next_st = NULL;
    if (sqlite3_prepare_v2(g_db,
        "SELECT guid, base_guid, snapshot, storage_base, cluster_fs "
        "FROM snapshots "
        "WHERE node = ?1 AND cluster = ?2 AND push_status = 'verified' AND direction = 'push' "
        "  AND storage_base IS NOT NULL AND storage_base != '' "
        "  AND guid NOT IN (SELECT guid FROM snapshots WHERE node=?3 AND direction='pull' AND pull_status='pulled') "
        "  AND (?4 = '' OR guid != ?4)"
        "ORDER BY id ASC LIMIT 1",
        -1, &next_st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(next_st, 1, master_cn, -1, SQLITE_STATIC);
        sqlite3_bind_text(next_st, 2, cluster_buf, -1, SQLITE_STATIC);
        sqlite3_bind_text(next_st, 3, nw->cn, -1, SQLITE_STATIC);
        sqlite3_bind_text(next_st, 4, common_guid, -1, SQLITE_STATIC);
        if (sqlite3_step(next_st) == SQLITE_ROW) {
            const char *g = (const char *)sqlite3_column_text(next_st, 0);
            const char *b = (const char *)sqlite3_column_text(next_st, 1);
            const char *s = (const char *)sqlite3_column_text(next_st, 2);
            const char *sb = (const char *)sqlite3_column_text(next_st, 3);
            const char *cf = (const char *)sqlite3_column_text(next_st, 4);
            if (g) snprintf(target_guid, sizeof(target_guid), "%s", g);
            if (b) snprintf(target_base, sizeof(target_base), "%s", b);
            if (s) snprintf(target_snap, sizeof(target_snap), "%s", s);
            if (sb) snprintf(target_storage, sizeof(target_storage), "%s", sb);
            if (cf) snprintf(target_cfs, sizeof(target_cfs), "%s", cf);
        }
        sqlite3_finalize(next_st);
    }

    if (!target_guid[0]) {
        zep_log_debug("pull_trigger: no pending pull for client %s\n", nw->cn);
        return;
    }

    /* Check if target already pulled for this client */
    sqlite3_stmt *chk_st = NULL;
    if (sqlite3_prepare_v2(g_db,
        "SELECT pull_status FROM snapshots "
        "WHERE guid = ?1 AND node = ?2 AND direction = 'pull' LIMIT 1",
        -1, &chk_st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(chk_st, 1, target_guid, -1, SQLITE_STATIC);
        sqlite3_bind_text(chk_st, 2, nw->cn, -1, SQLITE_STATIC);
        if (sqlite3_step(chk_st) == SQLITE_ROW) {
            const char *ps = (const char *)sqlite3_column_text(chk_st, 0);
            if (ps && (strcmp(ps, "pulled") == 0 || strcmp(ps, "pulling") == 0)) {
                zep_log_debug("pull_trigger: guid=%s already %s for %s, skipping\n",
                              target_guid, ps, nw->cn);
                sqlite3_finalize(chk_st);
                return;
            }
        }
        sqlite3_finalize(chk_st);
    }

   /* Send pull command and stream assembled.zfs */
    char pull_json[4096];
    int n = snprintf(pull_json, sizeof(pull_json),
        "{\"action\":\"pull\",\"guid\":\"%s\",\"base_guid\":\"%s\","
        "\"snapshot\":\"%s\",\"cluster_fs\":\"%s\"}",
        target_guid, target_base, target_snap, target_cfs);
    if (n > 0 && n < (int)sizeof(pull_json)) {
        zep_log("pull_trigger: sending pull for guid=%s snap=%s cfs=%s to client %s\n",
                 target_guid, target_snap, target_cfs, nw->cn);
        ws_send_frame_gtls(nw, WS_OP_TEXT, (unsigned char *)pull_json, (size_t)n);

        /* Look up assembled.zfs and stream it */
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(g_db,
            "SELECT storage_base FROM snapshots WHERE guid=?1 AND direction='push' LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, target_guid, -1, SQLITE_STATIC);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *storage_base = (const char *)sqlite3_column_text(st, 0);
                if (!storage_base || !storage_base[0]) {
                    zep_log_debug("pull_trigger: no storage_base for guid=%s, skipping stream\n", target_guid);
                } else {
                    char assembled_path[ZEP_MAX_PATH * 2 + 256];
                    const char *prefix = "file://";
                    const char *base_path = storage_base;
                    if (strncmp(base_path, prefix, strlen(prefix)) == 0)
                        base_path += strlen(prefix);
                    snprintf(assembled_path, sizeof(assembled_path),
                             "%sassembled.zfs", base_path);

                    if (access(assembled_path, F_OK) == 0) {
                        char pull_cmd[4096];
                        int cn = snprintf(pull_cmd, sizeof(pull_cmd),
                            "cat '%s'", assembled_path);
                        if (g_pull_zip_cmd[0]) {
                            cn += snprintf(pull_cmd + cn, sizeof(pull_cmd) - (size_t)cn,
                                " | %s", g_pull_zip_cmd);
                        }
                        if (g_debug_inject_pull_cmd[0]) {
                            cn += snprintf(pull_cmd + cn, sizeof(pull_cmd) - (size_t)cn,
                                " | %s", g_debug_inject_pull_cmd);
                        }
                        FILE *fp = popen(pull_cmd, "r");
                        if (fp) {
                            unsigned char rbuf[65536];
                            size_t nr;
                            while ((nr = fread(rbuf, 1, sizeof(rbuf), fp)) > 0) {
                                ws_send_frame_gtls(nw, WS_OP_BIN, rbuf, nr);
                            }
                            int rc = pclose(fp);
                            unsigned char ex = WIFEXITED(rc) ? (unsigned char)WEXITSTATUS(rc) : 1;
                            ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                        } else {
                            zep_log("pull_trigger: popen(%s) failed\n", pull_cmd);
                            unsigned char ex = 1;
                            ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                        }
                                    ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                               } else {
                        zep_log("pull_trigger: assembled.zfs not found\n");
                        unsigned char ex = 1;
                        ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                        ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                    }
                }
            } else {
                zep_log_debug("pull_trigger: no storage_base row for guid=%s\n", target_guid);
            }
            sqlite3_finalize(st);
        }
    }
}

static void server_dispatch_rotation(struct node_ws *nw,
                                     const char *cluster_buf,
                                     const char *direction) {
    if (!cluster_buf[0]) return;

    char mapping_buf[2048] = {0};
    {
        sqlite3_stmt *ms = NULL;
        if (sqlite3_prepare_v2(g_db,
            "SELECT mapping FROM auth WHERE cn = ?1",
            -1, &ms, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ms, 1, nw->cn, -1, SQLITE_STATIC);
            if (sqlite3_step(ms) == SQLITE_ROW) {
                const char *m = (const char *)sqlite3_column_text(ms, 0);
                if (m) snprintf(mapping_buf, sizeof(mapping_buf), "%s", m);
            }
            sqlite3_finalize(ms);
        }
    }

    char cfg_key[128], cj_buf[65536] = {0};
    cJSON *cluster_json = NULL;
    snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", cluster_buf);
    if (db_config_get(g_db, cfg_key, cj_buf, sizeof(cj_buf)) == ZEP_ERR_OK)
        cluster_json = cJSON_Parse(cj_buf);

    cJSON *rotate = cJSON_CreateArray();
    db_rotation_candidates(g_db, cluster_buf, nw->cn,
                           mapping_buf, cluster_json, rotate, direction);

    if (cluster_json) cJSON_Delete(cluster_json);

    int rc = cJSON_GetArraySize(rotate);
    if (rc == 0) { cJSON_Delete(rotate); return; }

    cJSON *protected_arr = cJSON_CreateArray();
    char ancestor[ZEP_MAX_GUID_LEN] = {0};
    if (db_common_ancestor(g_db, cluster_buf, ancestor,
            sizeof(ancestor)) == ZEP_ERR_OK && ancestor[0])
        cJSON_AddItemToArray(protected_arr, cJSON_CreateString(ancestor));

    sqlite3_stmt *st2 = NULL;
    sqlite3_prepare_v2(g_db,
        "SELECT last_ack_guid FROM auth "
        "WHERE cluster = ?1 AND role = 'client' "
        "  AND last_ack_guid != ''",
        -1, &st2, NULL);
    if (st2) {
        sqlite3_bind_text(st2, 1, cluster_buf, -1, SQLITE_STATIC);
        while (sqlite3_step(st2) == SQLITE_ROW)
            cJSON_AddItemToArray(protected_arr,
                cJSON_CreateString(
                    (const char *)sqlite3_column_text(st2, 0)));
        sqlite3_finalize(st2);
    }

    sqlite3_prepare_v2(g_db,
        "SELECT guid FROM snapshots "
        "WHERE cluster = ?1 AND direction = 'push' "
        "ORDER BY rowid DESC LIMIT 1",
        -1, &st2, NULL);
    if (st2) {
        sqlite3_bind_text(st2, 1, cluster_buf, -1, SQLITE_STATIC);
        if (sqlite3_step(st2) == SQLITE_ROW)
            cJSON_AddItemToArray(protected_arr,
                cJSON_CreateString(
                    (const char *)sqlite3_column_text(st2, 0)));
        sqlite3_finalize(st2);
    }

    cJSON *filtered = cJSON_CreateArray();
    for (int i = 0; i < rc; i++) {
        cJSON *item = cJSON_GetArrayItem(rotate, i);
        if (!item) continue;
        cJSON *g = cJSON_GetObjectItem(item, "guid");
        if (!g) continue;
        int prot = 0;
        int pc = cJSON_GetArraySize(protected_arr);
        for (int j = 0; j < pc; j++) {
            cJSON *pg = cJSON_GetArrayItem(protected_arr, j);
            if (pg && cJSON_IsString(pg) &&
                strcmp(g->valuestring, pg->valuestring) == 0)
                { prot = 1; break; }
        }
        if (!prot)
            cJSON_AddItemToArray(filtered,
                cJSON_Duplicate(item, 1));
    }
    cJSON_Delete(protected_arr);
    cJSON_Delete(rotate);

    int fc = cJSON_GetArraySize(filtered);
    if (fc == 0) { cJSON_Delete(filtered); return; }

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "action", "rotation");
    cJSON_AddItemToObject(task, "rotate", filtered);
    char *js = cJSON_PrintUnformatted(task);
    cJSON_Delete(task);
    ws_send_frame_gtls(nw, WS_OP_TEXT, (unsigned char *)js, strlen(js));
    zep_log("rotation: dispatched %d candidates to %s\n", fc, nw->cn);
    free(js);
}

static void *node_ws_thread(void *arg) {
    struct node_ws_thread_ctx *ctx = (struct node_ws_thread_ctx *)arg;
    struct node_ws *nw = ctx->nw;
    free(ctx);

    unsigned char *buf = malloc(WS_SUBCHUNK + 256);
    unsigned char *out = malloc(WS_SUBCHUNK);
    if (!buf || !out) { free(buf); free(out); return NULL; }

    if (g_logging & LOG_LEVEL_DEBUG) {
        zep_log_debug("ws: node %s listening sock=%d\n", nw->cn, nw->sock);
    }

    /* Track if discovery has been received from node */
    int discovery_done = 0;

    /* Pending create_snap task queue (FIFO) */
    char pending_snaps[MAX_PENDING][ZEP_MAX_SNAPSHOT_NAME];
    char pending_labels[MAX_PENDING][64];
    int pending_head = 0, pending_tail = 0;

    /* Query node role for scheduler */
    char role_buf[16] = {0}, cluster_buf[64] = {0}, mapping_buf[2048] = {0};
    {
        sqlite3_stmt *role_st = NULL;
        if (sqlite3_prepare_v2(g_db,
                "SELECT role, cluster, mapping FROM auth WHERE cn = ?1",
                -1, &role_st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(role_st, 1, nw->cn, -1, SQLITE_STATIC);
            if (sqlite3_step(role_st) == SQLITE_ROW) {
                const char *r = (const char *)sqlite3_column_text(role_st, 0);
                const char *c = (const char *)sqlite3_column_text(role_st, 1);
                const char *m = (const char *)sqlite3_column_text(role_st, 2);
                if (r) snprintf(role_buf, sizeof(role_buf), "%s", r);
                if (c) snprintf(cluster_buf, sizeof(cluster_buf), "%s", c);
                if (m) snprintf(mapping_buf, sizeof(mapping_buf), "%s", m);
            }
            sqlite3_finalize(role_st);
        }
    }

    /* Initial scheduler run */
    int initial_scheduler_done = 0;
    if (strcmp(role_buf, "master") == 0 && cluster_buf[0] && mapping_buf[0]) {
        scheduler_run(nw, cluster_buf, pending_snaps, pending_labels, &pending_tail, mapping_buf);
        initial_scheduler_done = 1;
    }

    time_t last_ping = time(NULL);
    time_t last_scheduler = time(NULL);
    for (;;) {
        if (pending_head >= pending_tail) {
            pending_head = 0;
            pending_tail = 0;
        }
        /* Check if pipe is starting — exit so bridge can take over */
        pthread_mutex_lock(&nw->lock);
        int exiting = nw->pipe_starting;
        int closed = nw->ws_closed;
        pthread_mutex_unlock(&nw->lock);
        if (closed) {
            if (g_logging & LOG_LEVEL_DEBUG) {
                zep_log_debug("ws: node %s closed by new connection\n", nw->cn);
            }
            break;
        }
        if (exiting) {
            if (g_logging & LOG_LEVEL_DEBUG) {
                zep_log_debug("ws: node %s exiting for pipe bridge\n", nw->cn);
            }
            pthread_mutex_lock(&nw->lock);
            nw->pipe_thread_exited = 1;
            pthread_cond_signal(&nw->pipe_ready);
            pthread_mutex_unlock(&nw->lock);
            break;
        }

        struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(nw->sock, &rfds);
        int sel = select(nw->sock + 1, &rfds, NULL, NULL, &tv);

        time_t now = time(NULL);
        if (now - last_ping >= 60) {
            ws_send_frame_gtls(nw, WS_OP_PING, NULL, 0);
            zep_log_debug( "ws: -> PING  cn=%s\n", nw->cn);
            last_ping = now;
        }

        /* Periodic scheduler: check if any labels are due */
        if (strcmp(role_buf, "master") == 0 && cluster_buf[0] && mapping_buf[0]) {
            if (now - last_scheduler >= 30) {
       scheduler_run(nw, cluster_buf, pending_snaps, pending_labels, &pending_tail, mapping_buf);
                last_scheduler = now;
            }
        }

        /* Periodic pull check for clients */
        if (strcmp(role_buf, "client") == 0 && cluster_buf[0] && nw->cn[0]) {
            if (now - last_scheduler >= 30) {
                node_ws_pull_trigger(nw, cluster_buf, role_buf);
                last_scheduler = now;
            }
        }

        if (sel > 0 && FD_ISSET(nw->sock, &rfds)) {
                ssize_t plen = ws_recv_frame_full(nw, buf, WS_SUBCHUNK, out, WS_SUBCHUNK, &buf[0]);
                unsigned char opcode = buf[0] & 0x0F;
                if (plen < 0) {
                    zep_log_debug( "ws: recv_frame_full failed plen=%zd cn=%s\n", plen, nw->cn);
                    break;
                }

            if (opcode == WS_OP_CLOSE) break;
            if (opcode == WS_OP_PING) {
                ws_send_frame_gtls(nw, WS_OP_PONG, out, (size_t)plen);
                continue;
            }
            if (opcode == WS_OP_PONG) {
                nw->last_pong = time(NULL);
                zep_log_debug( "ws: <- PONG  cn=%s\n", nw->cn);
                continue;
            }
            if (opcode == WS_OP_TEXT && plen > 0) {
                out[plen] = '\0';
                cJSON *msg = cJSON_Parse((char *)out);
                if (msg) {
                    cJSON *action = cJSON_GetObjectItem(msg, "action");
                    if (action && cJSON_IsString(action) &&
                        strcmp(action->valuestring, "pull_resume") == 0) {
                        cJSON *guid_j = cJSON_GetObjectItem(msg, "guid");
                        cJSON *token_j = cJSON_GetObjectItem(msg, "token");
                        if (guid_j && cJSON_IsString(guid_j) &&
                            token_j && cJSON_IsString(token_j)) {
                            sqlite3_stmt *st = NULL;
                            sqlite3_prepare_v2(g_db,
                                "SELECT storage_base FROM snapshots "
                                "WHERE guid = ?1 AND direction = 'push' LIMIT 1",
                                -1, &st, NULL);
                            if (st) {
                                sqlite3_bind_text(st, 1, guid_j->valuestring,
                                                  -1, SQLITE_STATIC);
                                if (sqlite3_step(st) == SQLITE_ROW) {
                                    const char *base =
                                        (const char *)sqlite3_column_text(st, 0);
                                    if (base && base[0]) {
                                        const char *dir =
                                            strncmp(base, "file://", 7) == 0
                                            ? base + 7 : base;
                                        uint64_t offset = 0;
                                        zstream_token_parse_offset(
                                            token_j->valuestring, &offset);

                                        char hdr_b64[256] = {0};
                                        {
                                            char blob0[1024];
                                            snprintf(blob0, sizeof(blob0),
                                                     "%s/0000", dir);
                                            char ucmd[2048];
                                             snprintf(ucmd, sizeof(ucmd),
                                                      "zstd -d '%s' -c "
                                                      "| head -c 128 | base64 -w0",
                                                     blob0);
                                            FILE *hp = popen(ucmd, "r");
                                             if (hp) {
                                                 if (fgets(hdr_b64,
                                                           sizeof(hdr_b64), hp))
                                                 {
                                                     size_t n = strlen(hdr_b64);
                                                     while (n > 0 &&
                                                            (hdr_b64[n-1]=='\n'
                                                             || hdr_b64[n-1]=='\r'))
                                                         hdr_b64[--n]='\0';
                                                 }
                                                 int _hp_rc = pclose(hp);
                                                 audit_log(AUDIT_EVT_EXEC, "serve", ucmd, WIFEXITED(_hp_rc) ? WEXITSTATUS(_hp_rc) : -1);
                                             }
                                        }

                                        char pipe_cmd[8192];
                                        snprintf(pipe_cmd, sizeof(pipe_cmd),
                                            "zep-stream-ff --in '%s' "
                                            "--unzip-cmd 'zstd -d' "
                                            "--skip %lu | "
                                            "zstream resume "
                                            "-t '%s' "
                                            "-H 'data:;base64,%s' -S",
                                            dir, (unsigned long)offset,
                                            token_j->valuestring,
                                            hdr_b64[0] ? hdr_b64 : "");

                                      FILE *pp = popen(pipe_cmd, "r");
                                         audit_log(AUDIT_EVT_EXEC, "serve", pipe_cmd, pp ? -128 : -127);
                                         if (pp) {
                                             unsigned char rbuf[65536];
                                             for (;;) {
                                                 size_t nr = fread(rbuf, 1,
                                                     sizeof(rbuf), pp);
                                                 if (nr == 0) break;
                                                 ws_send_frame_gtls(nw,
                                                     WS_OP_BIN, rbuf, nr);
                                             }
                                             int rc = pclose(pp);
                                             audit_log(AUDIT_EVT_EXEC, "serve", pipe_cmd, WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
                                             unsigned char ex = rc ? 1 : 0;
                                             ws_send_frame_gtls(nw,
                                                 WS_OP_EXIT, &ex, 1);
                                         } else {
                                            unsigned char ex = 1;
                                            ws_send_frame_gtls(nw,
                                                WS_OP_EXIT, &ex, 1);
                                        }
                                        ws_send_frame_gtls(nw,
                                            WS_OP_EOF, NULL, 0);
                                    }
                                }
                                sqlite3_finalize(st);
                            }
                        }
                          cJSON_Delete(msg);
                           continue;
                        }
                       /* Node-initiated snapshot discovery */
                       if (!discovery_done && action && cJSON_IsString(action) &&
                           strcmp(action->valuestring, "discovery") == 0) {
                           cJSON *snaps = cJSON_GetObjectItem(msg, "snaps");

                            /* Phase 1: Register discovered snapshots (only if node sent snapshots) */
                            if (snaps && cJSON_IsArray(snaps)) {
                                if (strcmp(role_buf, "master") == 0 && cluster_buf[0]) {
                                 struct { char cluster_fs[512]; char guid[ZEP_MAX_GUID_LEN]; } latest_fs[16];
                                 int latest_count = 0;
                                int total = 0, regd = 0, existing = 0;
                                   cJSON *snap;
                                   cJSON_ArrayForEach(snap, snaps) {
                                       cJSON *g = cJSON_GetObjectItem(snap, "guid");
                                       cJSON *snapname = cJSON_GetObjectItem(snap, "snapshot");
                                       cJSON *lbl = cJSON_GetObjectItem(snap, "label");
                                       cJSON *bg = cJSON_GetObjectItem(snap, "base_guid");
                                       if (!g || !cJSON_IsString(g)) continue;
                                       if (!snapname || !cJSON_IsString(snapname)) continue;
                                       if (!lbl || !cJSON_IsString(lbl)) continue;
                                       const char *base_guid = (bg && cJSON_IsString(bg)) ? bg->valuestring : "";
                                       total++;
                                       /* Resolve cluster_fs from mapping */
                                       char cluster_fs[512] = {0};
                                       {
                                           const char *mp = mapping_buf;
                                           const char *snap_str = snapname->valuestring;
                                           const char *at = strchr(snap_str, '@');
                                           if (at) {
                                               size_t fslen = (size_t)(at - snap_str);
                                               char local_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                               if (fslen >= sizeof(local_fs)) fslen = sizeof(local_fs) - 1;
                                               memcpy(local_fs, snap_str, fslen);
                                               local_fs[fslen] = '\0';
                                               const char *cm = mp;
                                               while (cm && *cm) {
                                                   while (*cm==' '||*cm=='\t') cm++;
                                                   if (!*cm) break;
                                                   const char *colon = strchr(cm, ':');
                                                   if (!colon) break;
                                                   size_t cflen = (size_t)(colon - cm);
                                                   char cfs_buf[512];
                                                   if (cflen >= sizeof(cfs_buf)) cflen = sizeof(cfs_buf) - 1;
                                                   memcpy(cfs_buf, cm, cflen);
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
                                                   if (strcmp(local_fs, resolved) == 0) {
                                                       snprintf(cluster_fs, sizeof(cluster_fs), "%s", cfs_buf);
                                                       break;
                                                   }
                                                   const char *comma = strchr(colon, ',');
                                                   cm = comma ? comma + 1 : colon + strlen(colon);
                                               }
                                           }
                                       }
                                       if (!cluster_fs[0]) {
                                           zep_log("discovery: skipped %s (no mapping)\n",
                                               snapname->valuestring);
                                           continue;
                                       }
                                       sqlite3_stmt *ck = NULL;
                                       if (sqlite3_prepare_v2(g_db,
                                               "SELECT 1 FROM snapshots WHERE node=?1 AND guid=?2",
                                               -1, &ck, NULL) == SQLITE_OK) {
                                           sqlite3_bind_text(ck, 1, nw->cn, -1, SQLITE_STATIC);
                                           sqlite3_bind_text(ck, 2, g->valuestring, -1, SQLITE_STATIC);
                                           if (sqlite3_step(ck) != SQLITE_ROW) {
                                                db_snapshot_insert(g_db, cluster_buf, nw->cn,
                                                     g->valuestring, base_guid, snapname->valuestring,
                                                     lbl->valuestring, cluster_fs, 0, 0,
                                                     "push", "", "pending", "discovered", "");
                                               {
                                                   sqlite3_stmt *pa = NULL;
                                                   if (sqlite3_prepare_v2(g_db,
                                                       "UPDATE snapshots SET push_status='archived' WHERE node=?1 AND guid=?2",
                                                       -1, &pa, NULL) == SQLITE_OK) {
                                                       sqlite3_bind_text(pa, 1, nw->cn, -1, SQLITE_STATIC);
                                                       sqlite3_bind_text(pa, 2, g->valuestring, -1, SQLITE_STATIC);
                                                       sqlite3_step(pa);
                                                       sqlite3_finalize(pa);
                                                   }
                                               }
                                               regd++;
                                               zep_log("discovery: registered %s guid=%s lbl=%s base=%s\n",
                                                   snapname->valuestring, g->valuestring, lbl->valuestring, base_guid);
                                           } else {
                                               existing++;
                                           }
                                           sqlite3_finalize(ck);
                                       }
                                       /* Track latest per cluster_fs */
                                       if (cluster_fs[0]) {
                                           int found = 0;
                                           for (int i = 0; i < latest_count; i++) {
                                               if (strcmp(latest_fs[i].cluster_fs, cluster_fs) == 0) {
                                                   snprintf(latest_fs[i].guid, sizeof(latest_fs[i].guid), "%s", g->valuestring);
                                                   found = 1;
                                                   break;
                                               }
                                           }
                                           if (!found && latest_count < 16) {
                                               snprintf(latest_fs[latest_count].cluster_fs, sizeof(latest_fs[latest_count].cluster_fs), "%s", cluster_fs);
                                               snprintf(latest_fs[latest_count].guid, sizeof(latest_fs[latest_count].guid), "%s", g->valuestring);
                                               latest_count++;
                                           }
                                       }
                                   }
                                   /* Promote latest per cluster_fs from archived to pending */
                                   for (int i = 0; i < latest_count; i++) {
                                       sqlite3_stmt *pr = NULL;
                                       if (sqlite3_prepare_v2(g_db,
                                           "UPDATE snapshots SET push_status='pending' "
                                           "WHERE node=?1 AND cluster_fs=?2 AND push_status='archived' "
                                           "AND guid=?3",
                                           -1, &pr, NULL) == SQLITE_OK) {
                                           sqlite3_bind_text(pr, 1, nw->cn, -1, SQLITE_STATIC);
                                           sqlite3_bind_text(pr, 2, latest_fs[i].cluster_fs, -1, SQLITE_STATIC);
                                           sqlite3_bind_text(pr, 3, latest_fs[i].guid, -1, SQLITE_STATIC);
                                           sqlite3_step(pr);
                                           sqlite3_finalize(pr);
                                       }
                                       zep_log("discovery: promoted latest for %s guid=%s\n",
                                           latest_fs[i].cluster_fs, latest_fs[i].guid);
                                   }
                                    zep_log("discovery: %s total=%d new=%d existing=%d latest_fs=%d\n",
                                        cluster_buf, total, regd, existing, latest_count);
                                } else if (strcmp(role_buf, "client") == 0 && cluster_buf[0]) {
                                    struct { char cluster_fs[512]; char guid[ZEP_MAX_GUID_LEN]; } cl_latest_fs[16];
                                    int cl_latest_count = 0;
                                    int cl_total = 0, cl_regd = 0, cl_existing = 0;
                                    cJSON *snap;
                                    cJSON_ArrayForEach(snap, snaps) {
                                        cJSON *g = cJSON_GetObjectItem(snap, "guid");
                                        cJSON *snapname = cJSON_GetObjectItem(snap, "snapshot");
                                        cJSON *lbl = cJSON_GetObjectItem(snap, "label");
                                        cJSON *bg = cJSON_GetObjectItem(snap, "base_guid");
                                        if (!g || !cJSON_IsString(g)) continue;
                                        if (!snapname || !cJSON_IsString(snapname)) continue;
                                        if (!lbl || !cJSON_IsString(lbl)) continue;
                                        const char *base_guid = (bg && cJSON_IsString(bg)) ? bg->valuestring : "";
                                        cl_total++;
                                        char cluster_fs[512] = {0};
                                        {
                                            const char *mp = mapping_buf;
                                            const char *snap_str = snapname->valuestring;
                                            const char *at = strchr(snap_str, '@');
                                            if (at) {
                                                size_t fslen = (size_t)(at - snap_str);
                                                char local_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                                if (fslen >= sizeof(local_fs)) fslen = sizeof(local_fs) - 1;
                                                memcpy(local_fs, snap_str, fslen);
                                                local_fs[fslen] = '\0';
                                                const char *cm = mp;
                                                while (cm && *cm) {
                                                    while (*cm==' '||*cm=='\t') cm++;
                                                    if (!*cm) break;
                                                    const char *colon = strchr(cm, ':');
                                                    if (!colon) break;
                                                    size_t cflen = (size_t)(colon - cm);
                                                    char cfs_buf[512];
                                                    if (cflen >= sizeof(cfs_buf)) cflen = sizeof(cfs_buf) - 1;
                                                    memcpy(cfs_buf, cm, cflen);
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
                                                    if (strcmp(local_fs, resolved) == 0) {
                                                        snprintf(cluster_fs, sizeof(cluster_fs), "%s", cfs_buf);
                                                        break;
                                                    }
                                                    const char *comma = strchr(colon, ',');
                                                    cm = comma ? comma + 1 : colon + strlen(colon);
                                                }
                                            }
                                        }
                                        if (!cluster_fs[0]) {
                                            zep_log("discovery: skipped %s (no mapping)\n",
                                                snapname->valuestring);
                                            continue;
                                        }
                                        sqlite3_stmt *ck = NULL;
                                        if (sqlite3_prepare_v2(g_db,
                                                "SELECT 1 FROM snapshots WHERE node=?1 AND guid=?2",
                                                -1, &ck, NULL) == SQLITE_OK) {
                                            sqlite3_bind_text(ck, 1, nw->cn, -1, SQLITE_STATIC);
                                            sqlite3_bind_text(ck, 2, g->valuestring, -1, SQLITE_STATIC);
                                            if (sqlite3_step(ck) != SQLITE_ROW) {
                                                db_snapshot_insert(g_db, cluster_buf, nw->cn,
                                                     g->valuestring, base_guid, snapname->valuestring,
                                                     lbl->valuestring, cluster_fs, 0, 0,
                                                     "pull", "", "pending", "discovered", "");
                                                {
                                                    sqlite3_stmt *pa = NULL;
                                                    if (sqlite3_prepare_v2(g_db,
                                                        "UPDATE snapshots SET push_status='archived' WHERE node=?1 AND guid=?2",
                                                        -1, &pa, NULL) == SQLITE_OK) {
                                                        sqlite3_bind_text(pa, 1, nw->cn, -1, SQLITE_STATIC);
                                                        sqlite3_bind_text(pa, 2, g->valuestring, -1, SQLITE_STATIC);
                                                        sqlite3_step(pa);
                                                        sqlite3_finalize(pa);
                                                    }
                                                }
                                                cl_regd++;
                                                zep_log("discovery: registered %s guid=%s lbl=%s base=%s (pull)\n",
                                                    snapname->valuestring, g->valuestring, lbl->valuestring, base_guid);
                                            } else {
                                                cl_existing++;
                                            }
                                            sqlite3_finalize(ck);
                                        }
                                        if (cluster_fs[0]) {
                                            int found = 0;
                                            for (int i = 0; i < cl_latest_count; i++) {
                                                if (strcmp(cl_latest_fs[i].cluster_fs, cluster_fs) == 0) {
                                                    snprintf(cl_latest_fs[i].guid, sizeof(cl_latest_fs[i].guid), "%s", g->valuestring);
                                                    found = 1;
                                                    break;
                                                }
                                            }
                                            if (!found && cl_latest_count < 16) {
                                                snprintf(cl_latest_fs[cl_latest_count].cluster_fs, sizeof(cl_latest_fs[cl_latest_count].cluster_fs), "%s", cluster_fs);
                                                snprintf(cl_latest_fs[cl_latest_count].guid, sizeof(cl_latest_fs[cl_latest_count].guid), "%s", g->valuestring);
                                                cl_latest_count++;
                                            }
                                        }
                                    }
                                    for (int i = 0; i < cl_latest_count; i++) {
                                        sqlite3_stmt *pr = NULL;
                                        if (sqlite3_prepare_v2(g_db,
                                            "UPDATE snapshots SET push_status='pending' "
                                            "WHERE node=?1 AND cluster_fs=?2 AND push_status='archived' "
                                            "AND guid=?3",
                                            -1, &pr, NULL) == SQLITE_OK) {
                                            sqlite3_bind_text(pr, 1, nw->cn, -1, SQLITE_STATIC);
                                            sqlite3_bind_text(pr, 2, cl_latest_fs[i].cluster_fs, -1, SQLITE_STATIC);
                                            sqlite3_bind_text(pr, 3, cl_latest_fs[i].guid, -1, SQLITE_STATIC);
                                            sqlite3_step(pr);
                                            sqlite3_finalize(pr);
                                        }
                                        zep_log("discovery: promoted latest for %s guid=%s (pull)\n",
                                            cl_latest_fs[i].cluster_fs, cl_latest_fs[i].guid);
                                    }
                                    zep_log("discovery: phase 4 completed\n");
                                } else {
                                    zep_log("discovery: node=%s role=%s — skipping\n",
                                        nw->cn, role_buf[0] ? role_buf : "(none)");
                                }
                              discovery_done = 1;
                               zep_log("discovery: phase 1 complete\n");
                               /* After discovery, check for pending pulls for client nodes */
                               if (strcmp(role_buf, "client") == 0) {
                                   node_ws_pull_trigger(nw, cluster_buf, role_buf);
                               }
                           }
                           cJSON_Delete(msg);
                           continue;
                      }
                      if (action && cJSON_IsString(action) &&
                           strcmp(action->valuestring, "pull") == 0) {
                          cJSON *guid_j = cJSON_GetObjectItem(msg, "guid");
                          if (guid_j && cJSON_IsString(guid_j)) {
                              sqlite3_stmt *st = NULL;
                              sqlite3_prepare_v2(g_db,
                                  "SELECT guid, base_guid, snapshot, storage_base, push_status "
                                  "FROM snapshots "
                                  "WHERE guid = ?1 AND direction = 'push' LIMIT 1",
                                  -1, &st, NULL);
                          if (st) {
                                   sqlite3_bind_text(st, 1, guid_j->valuestring,
                                                     -1, SQLITE_STATIC);
                               if (sqlite3_step(st) == SQLITE_ROW) {
                                        const char *snap =
                                           (const char *)sqlite3_column_text(st, 1);
                                       const char *storage_base =
                                           (const char *)sqlite3_column_text(st, 2);
                                       const char *push_status =
                                           (const char *)sqlite3_column_text(st, 3);
                                       if (snap && snap[0] && storage_base && storage_base[0]) {
                                          /* Build assembled.zfs path from storage_base "file://<path>/". */
                                          char assembled_path[ZEP_MAX_PATH * 2 + 256];
                                          const char *prefix = "file://";
                                          const char *base_path = storage_base;
                                          if (strncmp(base_path, prefix, strlen(prefix)) == 0)
                                              base_path += strlen(prefix);
                                          snprintf(assembled_path, sizeof(assembled_path),
                                                   "%sassembled.zfs", base_path);

                                          if (access(assembled_path, F_OK) != 0) {
                                               zep_log("pull: assembled.zfs not found for guid=%s path=%s\n",
                                                       guid_j->valuestring, assembled_path);
                                               unsigned char ex = 1;
                                               ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                                               ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                           } else {
                                               zep_log("pull: streaming assembled.zfs for guid=%s status=%s\n",
                                                       guid_j->valuestring, push_status ? push_status : "(none)");

                                                /* Build command: cat assembled.zfs | pull_zip_cmd | inject_cmd (optional) */
                                                char pull_cmd[4096];
                                                int n = snprintf(pull_cmd, sizeof(pull_cmd),
                                                    "cat '%s'", assembled_path);
                                                if (g_pull_zip_cmd[0]) {
                                                    n += snprintf(pull_cmd + n, sizeof(pull_cmd) - (size_t)n,
                                                        " | %s", g_pull_zip_cmd);
                                                }
                                                if (g_debug_inject_pull_cmd[0]) {
                                                    n += snprintf(pull_cmd + n, sizeof(pull_cmd) - (size_t)n,
                                                        " | %s", g_debug_inject_pull_cmd);
                                                }
                                               zep_log("pull: cmd=%s\n", pull_cmd);

                                               FILE *fp = popen(pull_cmd, "r");
                                               if (fp) {
                                                   unsigned char rbuf[65536];
                                                   size_t nr;
                                                   while ((nr = fread(rbuf, 1, sizeof(rbuf), fp)) > 0) {
                                                       ws_send_frame_gtls(nw, WS_OP_BIN, rbuf, nr);
                                                   }
                                                   int rc = pclose(fp);
                                                   unsigned char ex = WIFEXITED(rc) ? (unsigned char)WEXITSTATUS(rc) : 1;
                                                   zep_log("pull: stream done rc=%d\n", ex);
                                                   ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                                               } else {
                                                   zep_log("pull: popen(%s) failed: %s\n",
                                                           pull_cmd, strerror(errno));
                                                   unsigned char ex = 1;
                                                   ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                                               }
                                              ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                          }
                                      }
                                  }
                                  sqlite3_finalize(st);
                             }
                         }
                          cJSON_Delete(msg);
                           continue;
                        }

                       /* Pull ACK handler: client reports zfs recv result */
                       if (action && cJSON_IsString(action) &&
                            strcmp(action->valuestring, "pull_ack") == 0) {
                           cJSON *guid_j = cJSON_GetObjectItem(msg, "guid");
                           cJSON *ec_j = cJSON_GetObjectItem(msg, "exit_code");
                           cJSON *rt_j = cJSON_GetObjectItem(msg, "resume_token");
                           cJSON *err_j = cJSON_GetObjectItem(msg, "stderr");
                           if (guid_j && cJSON_IsString(guid_j)) {
                               int exit_code = ec_j && cJSON_IsNumber(ec_j) ? (int)ec_j->valueint : -1;
                               const char *rt = rt_j && cJSON_IsString(rt_j) ? rt_j->valuestring : "";
                               const char *err = err_j && cJSON_IsString(err_j) ? err_j->valuestring : "";
                               {
                                    char lk_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                    char lk_cfs[512] = {0};
                                    char lk_lbl[64] = {0};
                                    sqlite3_stmt *lk = NULL;
                                    if (sqlite3_prepare_v2(g_db,
                                        "SELECT snapshot, cluster_fs, label FROM snapshots "
                                        "WHERE guid = ?1 AND direction = 'push' LIMIT 1",
                                        -1, &lk, NULL) == SQLITE_OK) {
                                        sqlite3_bind_text(lk, 1, guid_j->valuestring, -1, SQLITE_STATIC);
                                        if (sqlite3_step(lk) == SQLITE_ROW) {
                                            const char *s = (const char *)sqlite3_column_text(lk, 0);
                                            const char *c = (const char *)sqlite3_column_text(lk, 1);
                                            const char *l = (const char *)sqlite3_column_text(lk, 2);
                                            if (s) snprintf(lk_snap, sizeof(lk_snap), "%s", s);
                                            if (c) snprintf(lk_cfs, sizeof(lk_cfs), "%s", c);
                                            if (l) snprintf(lk_lbl, sizeof(lk_lbl), "%s", l);
                                        }
                                        sqlite3_finalize(lk);
                                    }
                                if (exit_code == 0) {
                                    zep_log("pull_ack: guid=%s success for client %s\n",
                                            guid_j->valuestring, nw->cn);
                                    db_snapshot_insert(g_db, cluster_buf, nw->cn,
                                        guid_j->valuestring, "", lk_snap, lk_lbl, lk_cfs, 0, 0,
                                        "pull", "", "pending", "pulled", "");
                                    server_dispatch_rotation(nw, cluster_buf, "pull");
                                } else if (rt[0] && strcmp(rt, "-") != 0) {
                                    zep_log("pull_ack: guid=%s interrupted, resume_token=%s\n",
                                            guid_j->valuestring, rt);
                                    db_snapshot_insert(g_db, cluster_buf, nw->cn,
                                        guid_j->valuestring, "", lk_snap, lk_lbl, lk_cfs, 0, 0,
                                        "pull", "", "pending", "resuming", rt);
                                } else {
                                    zep_log("pull_ack: guid=%s failed exit_code=%d",
                                            guid_j->valuestring, exit_code);
                                    if (err[0]) zep_log(" stderr=%s", err);
                                    zep_log("\n");
                                }
                           }
                          }
                          cJSON_Delete(msg);
                            continue;
                         }

                        /* Rotate-ack handler: node reports rotation results */
                        if (action && cJSON_IsString(action) &&
                            strcmp(action->valuestring, "rotate-ack") == 0) {
                            cJSON *del_arr = cJSON_GetObjectItem(msg, "deleted");
                            if (del_arr && cJSON_IsArray(del_arr)) {
                                cJSON *g;
                                cJSON_ArrayForEach(g, del_arr) {
                                    if (cJSON_IsString(g))
                                        db_snapshot_delete_node_guid(g_db, nw->cn,
                                                                      g->valuestring);
                                }
                            }
                            cJSON *rem = cJSON_GetObjectItem(msg, "remaining");
                            if (rem && cJSON_IsArray(rem)) {
                                cJSON *r;
                                cJSON_ArrayForEach(r, rem) {
                                    cJSON *cf = cJSON_GetObjectItem(r, "cluster_fs");
                                    cJSON *lb = cJSON_GetObjectItem(r, "label");
                                    cJSON *cnt = cJSON_GetObjectItem(r, "count");
                                    if (!cf || !lb || !cnt) continue;
                                    int node_count = cnt->valueint;
                                    sqlite3_stmt *st = NULL;
                                    sqlite3_prepare_v2(g_db,
                                        "SELECT COUNT(*) FROM snapshots "
                                        "WHERE node = ?1 AND cluster_fs = ?2 "
                                        "  AND label = ?3",
                                        -1, &st, NULL);
                                    if (st) {
                                        sqlite3_bind_text(st, 1, nw->cn, -1, SQLITE_STATIC);
                                        sqlite3_bind_text(st, 2, cf->valuestring, -1, SQLITE_STATIC);
                                        sqlite3_bind_text(st, 3, lb->valuestring, -1, SQLITE_STATIC);
                                        int db_count = 0;
                                        if (sqlite3_step(st) == SQLITE_ROW)
                                            db_count = sqlite3_column_int(st, 0);
                                        sqlite3_finalize(st);
                                        if (db_count != node_count) {
                                            char err[256];
                                            snprintf(err, sizeof(err),
                                                "rotation drift: %s:%s node=%d db=%d",
                                                cf->valuestring, lb->valuestring,
                                                node_count, db_count);
                                            zep_log("rotate-ack: %s\n", err);
                                            sqlite3_stmt *up = NULL;
                                            sqlite3_prepare_v2(g_db,
                                                "UPDATE auth SET last_err = ?1 WHERE cn = ?2",
                                                -1, &up, NULL);
                                            if (up) {
                                                sqlite3_bind_text(up, 1, err, -1, SQLITE_STATIC);
                                                sqlite3_bind_text(up, 2, nw->cn, -1, SQLITE_STATIC);
                                                sqlite3_step(up);
                                                sqlite3_finalize(up);
                                            }
                                        }
                                    }
                                }
                            }
                            zep_log("rotate-ack: processed from %s\n", nw->cn);
                            zep_log("phase 6 complete\n");
                            cJSON_Delete(msg);
                            continue;
                        }

                        /* Pull resume handler: server streams resumed data */
                      if (action && cJSON_IsString(action) &&
                           strcmp(action->valuestring, "pull_resume") == 0) {
                          cJSON *guid_j = cJSON_GetObjectItem(msg, "guid");
                          cJSON *token_j = cJSON_GetObjectItem(msg, "token");
                          if (guid_j && cJSON_IsString(guid_j) &&
                              token_j && cJSON_IsString(token_j)) {
                              zep_log("pull_resume: guid=%s token=%.30s...\n",
                                      guid_j->valuestring, token_j->valuestring);
                              /* Look up the snapshot to get assembly path */
                              sqlite3_stmt *st = NULL;
                              sqlite3_prepare_v2(g_db,
                                  "SELECT storage_base FROM snapshots "
                                  "WHERE guid = ?1 AND direction = 'push' LIMIT 1",
                                  -1, &st, NULL);
                              if (st) {
                                  sqlite3_bind_text(st, 1, guid_j->valuestring, -1, SQLITE_STATIC);
                                  if (sqlite3_step(st) == SQLITE_ROW) {
                                      const char *storage_base =
                                          (const char *)sqlite3_column_text(st, 0);
                                      if (storage_base && storage_base[0]) {
                                          char assembled_path[ZEP_MAX_PATH * 2 + 256];
                                          const char *prefix = "file://";
                                          const char *base_path = storage_base;
                                          if (strncmp(base_path, prefix, strlen(prefix)) == 0)
                                              base_path += strlen(prefix);
                                          snprintf(assembled_path, sizeof(assembled_path),
                                                   "%sassembled.zfs", base_path);

                                          if (access(assembled_path, F_OK) == 0) {
                                              /* Run zstream resume to reconstruct stream */
                                              char resume_cmd[4096];
                                              snprintf(resume_cmd, sizeof(resume_cmd),
                                                  "zstream resume -t '%s' -i '%s'",
                                                  token_j->valuestring, assembled_path);
                                              FILE *fp = popen(resume_cmd, "r");
                                              if (fp) {
                                                  unsigned char rbuf[65536];
                                                  size_t nr;
                                                  while ((nr = fread(rbuf, 1, sizeof(rbuf), fp)) > 0) {
                                                      ws_send_frame_gtls(nw, WS_OP_BIN, rbuf, nr);
                                                  }
                                                  pclose(fp);
                                                  unsigned char ex = 0;
                                                  ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                                              } else {
                                                  zep_log("pull_resume: popen(%s) failed\n", resume_cmd);
                                                  unsigned char ex = 1;
                                                  ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                                              }
                                              ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                          } else {
                                              zep_log("pull_resume: assembled.zfs not found\n");
                                              unsigned char ex = 1;
                                              ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                                              ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                          }
                                      }
                                  }
                                  sqlite3_finalize(st);
                              }
                          }
                          cJSON_Delete(msg);
                           break;
                       }
                      if (action && cJSON_IsString(action) &&
                               strcmp(action->valuestring, "push") == 0) {
                             cJSON *guid_j = cJSON_GetObjectItem(msg, "guid");
                             cJSON *bg_j = cJSON_GetObjectItem(msg, "base_guid");
                             cJSON *snap_j = cJSON_GetObjectItem(msg, "snapshot");
                             cJSON *lbl_j = cJSON_GetObjectItem(msg, "label");
                             cJSON *cfs_j = cJSON_GetObjectItem(msg, "cluster_fs");
                             cJSON *rt_j = cJSON_GetObjectItem(msg, "resume_token");
                             int push_dispatch = 1;
                             if (guid_j && cJSON_IsString(guid_j) &&
                                 snap_j && cJSON_IsString(snap_j)) {
                                do {
                                const char *guid = guid_j->valuestring;
                               const char *bg = (bg_j && cJSON_IsString(bg_j)) ? bg_j->valuestring : "";
                               const char *snap = snap_j->valuestring;
                               const char *lbl = (lbl_j && cJSON_IsString(lbl_j)) ? lbl_j->valuestring : "";
                               const char *cfs = (cfs_j && cJSON_IsString(cfs_j)) ? cfs_j->valuestring : "";
                               const char *rt = (rt_j && cJSON_IsString(rt_j)) ? rt_j->valuestring : "";
                               int is_resume = (rt && rt[0]);

                               /* Compute inverted timestamp for storage directory, or reuse existing */
                               char storage_base[ZEP_MAX_PATH * 2 + 256] = {0};
                               if (is_resume) {
                                   sqlite3_stmt *sb = NULL;
                                   if (sqlite3_prepare_v2(g_db,
                                       "SELECT storage_base FROM snapshots WHERE guid=?1 LIMIT 1",
                                       -1, &sb, NULL) == SQLITE_OK) {
                                       sqlite3_bind_text(sb, 1, guid, -1, SQLITE_STATIC);
                                       if (sqlite3_step(sb) == SQLITE_ROW) {
                                           const char *base = (const char *)sqlite3_column_text(sb, 0);
                                           if (base && base[0]) {
                                               snprintf(storage_base, sizeof(storage_base), "%s", base);
                                           }
                                       }
                                       sqlite3_finalize(sb);
                                   }
                               }
                               char snap_dir[ZEP_MAX_PATH * 2 + 256];
                               if (storage_base[0]) {
                                   char dir_copy[ZEP_MAX_PATH * 2 + 256];
                                   const char *dir = strncmp(storage_base, "file://", 7) == 0 ? storage_base + 7 : storage_base;
                                   snprintf(dir_copy, sizeof(dir_copy), "%s", dir);
                                   size_t len = strlen(dir_copy);
                                   while (len > 0 && dir_copy[len-1] == '/') { dir_copy[len-1] = '\0'; len--; }
                                   snprintf(snap_dir, sizeof(snap_dir), "%s", dir_copy);
                               } else {
                                   time_t now = time(NULL);
                                   uint32_t inverted = (uint32_t)(0xFFFFFFFF - (uint32_t)now);
                                   char dir_name[64];
                                   snprintf(dir_name, sizeof(dir_name), "%u-%s", inverted, guid);
                                   snprintf(snap_dir, sizeof(snap_dir), "%s/%s/%s",
                                            g_storage_root, nw->cn, dir_name);
                               }

                               /* Create storage directory */
                               {
                                   char mcmd[2048];
                                   int n = snprintf(mcmd, sizeof(mcmd), "mkdir -p '%s'", snap_dir);
                                   if (n > 0 && n < (int)sizeof(mcmd)) {
                                       FILE *mp = audit_popen(mcmd);
                                       if (mp) {
                                           char tmp[256]; while (fgets(tmp, sizeof(tmp), mp));
                                           int mk_rc = audit_popen_result(mp, NULL, 0);
                                           audit_log(AUDIT_EVT_EXEC, "serve", mcmd, mk_rc);
                                       }
                                   }
                               }

                                /* Determine chunk number: 0 for new, scan existing .zfs for resume */
                                int chunk_num = 0;
                                if (is_resume) {
                                    uint32_t last = 0;
                                    while (1) {
                                        char test[ZEP_MAX_PATH * 2 + 256];
                                        int n = snprintf(test, sizeof(test), "%s/%04u.zfs", snap_dir, last);
                                        if (n > 0 && n < (int)sizeof(test) && access(test, F_OK) == 0) {
                                            chunk_num = (int)(last + 1);
                                            last = (uint32_t)chunk_num;
                                        } else {
                                            break;
                                        }
                                    }
                                }

                               /* Get cluster name */
                               char cluster[64] = {0};
                               sqlite3_stmt *clst = NULL;
                               if (sqlite3_prepare_v2(g_db,
                                   "SELECT cluster FROM auth WHERE cn = ?1 LIMIT 1",
                                   -1, &clst, NULL) == SQLITE_OK) {
                                   sqlite3_bind_text(clst, 1, nw->cn, -1, SQLITE_STATIC);
                                   if (sqlite3_step(clst) == SQLITE_ROW) {
                                       const char *c = (const char *)sqlite3_column_text(clst, 0);
                                       if (c && c[0]) snprintf(cluster, sizeof(cluster), "%s", c);
                                   }
                                   sqlite3_finalize(clst);
                               }

                                /* INSERT or REPLACE snapshot with status=pushing */
                                 if (cluster[0]) {
                                     sqlite3_stmt *si = NULL;
                                     char insert_base[ZEP_MAX_PATH * 2 + 256];
                                     snprintf(insert_base, sizeof(insert_base), "file://%s/", snap_dir);
                                     if (sqlite3_prepare_v2(g_db,
                                         "INSERT OR REPLACE INTO snapshots "
                                         "(cluster, node, guid, base_guid, snapshot, label, cluster_fs, "
                                         "status, blob_count, blob_size, direction, storage_base, "
                                         "push_started_at, push_completed_at) "
                                         "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pushing', 1, 0, 'push', ?8, "
                                         "COALESCE(NULLIF((SELECT push_started_at FROM snapshots WHERE guid=?3), ''), datetime('now')), "
                                         "COALESCE(NULLIF((SELECT push_completed_at FROM snapshots WHERE guid=?3), ''), ''))",
                                         -1, &si, NULL) == SQLITE_OK) {
                                         sqlite3_bind_text(si, 1, cluster, -1, SQLITE_STATIC);
                                         sqlite3_bind_text(si, 2, nw->cn, -1, SQLITE_STATIC);
                                         sqlite3_bind_text(si, 3, guid, -1, SQLITE_STATIC);
                                         sqlite3_bind_text(si, 4, bg, -1, SQLITE_STATIC);
                                         sqlite3_bind_text(si, 5, snap, -1, SQLITE_STATIC);
                                         sqlite3_bind_text(si, 6, lbl, -1, SQLITE_STATIC);
                                         sqlite3_bind_text(si, 7, cfs, -1, SQLITE_STATIC);
                                         sqlite3_bind_text(si, 8, insert_base, -1, SQLITE_STATIC);
                                        sqlite3_step(si);
                                        sqlite3_finalize(si);
                                    }
                                    /* Ensure fs row exists for this cluster/fs */
                                    {
                                        sqlite3_stmt *fs_ins = NULL;
                                        if (sqlite3_prepare_v2(g_db,
                                            "INSERT OR REPLACE INTO fs "
                                            "(cluster, fs, push_resume_token, push_bytes_recv, "
                                            " last_pushed_guid, last_pulled_guid, push_status) "
                                            "VALUES (?1, ?2, '', 0, '', '', 'pending')",
                                            -1, &fs_ins, NULL) == SQLITE_OK) {
                                            sqlite3_bind_text(fs_ins, 1, cluster, -1, SQLITE_STATIC);
                                            sqlite3_bind_text(fs_ins, 2, cfs, -1, SQLITE_STATIC);
                                            sqlite3_step(fs_ins);
                                            sqlite3_finalize(fs_ins);
                                        }
                                    }
                                 }

                                /* Assembled file path (constant, overwritten each iteration) */
                               char assembled_path[ZEP_MAX_PATH * 2 + 256];
                               snprintf(assembled_path, sizeof(assembled_path), "%s/assembled.zfs", snap_dir);

                                /* Per-chunk .zfs file path */
                                char chunk_path[ZEP_MAX_PATH * 2 + 256];
                                char chunk_path_raw[ZEP_MAX_PATH * 2 + 256];
                                char chunk_part[16];
                                snprintf(chunk_part, sizeof(chunk_part), "%04u.zfs", (uint32_t)chunk_num);
                                snprintf(chunk_path, sizeof(chunk_path), "%s/%s", snap_dir, chunk_part);
                                snprintf(chunk_path_raw, sizeof(chunk_path_raw), "%s/%s.raw", snap_dir, chunk_part);

                                /* Clean up assembled.zfs on first push; keep for resume */
                                if (chunk_num == 0)
                                    unlink(assembled_path);

                               zep_log("push: receiving chunk %s for guid=%s\n", chunk_part, guid);

                                /* Open chunk raw file (compressed from node) */
                                FILE *fp = fopen(chunk_path_raw, "wb");
                                if (!fp) {
                                    zep_log("ws: push fopen failed: %s\n", chunk_path_raw);
                                    if (cluster[0]) {
                                        sqlite3_stmt *sf = NULL;
                                        if (sqlite3_prepare_v2(g_db,
                                            "UPDATE snapshots SET status='failed' WHERE node=?1 AND guid=?2 AND status='pushing'",
                                            -1, &sf, NULL) == SQLITE_OK) {
                                            sqlite3_bind_text(sf, 1, nw->cn, -1, SQLITE_STATIC);
                                            sqlite3_bind_text(sf, 2, guid, -1, SQLITE_STATIC);
                                            sqlite3_step(sf);
                                            sqlite3_finalize(sf);
                                        }
                                    }
                                    ws_send_frame_gtls(nw, WS_OP_EXIT, (unsigned char *)&chunk_num, 1);
                                    ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                    push_dispatch = 0;
                                    break;
                               }

                               /* Send resume offset response */
                               uint64_t file_offset = 0;
                               if (is_resume) {
                                   fseek(fp, 0, SEEK_END);
                                   file_offset = (uint64_t)ftell(fp);
                                   fseek(fp, 0, SEEK_CUR);
                               }
                               {
                                   char resp[128];
                                   if (is_resume && file_offset > 0)
                                       snprintf(resp, sizeof(resp),
                                           "{\"resume\":true,\"offset\":%lu}",
                                           (unsigned long)file_offset);
                                   else
                                       snprintf(resp, sizeof(resp), "{\"resume\":false}");
                                   ws_send_frame_gtls(nw, WS_OP_TEXT,
                                            (unsigned char *)resp, strlen(resp));
                               }

                                 /* Read BIN frames and write to .zfs chunk */
                                 int node_exit_rc = -1;
                                 for (;;) {
                                     ssize_t rn = ws_recv_frame_full(nw, buf, WS_SUBCHUNK + 256, out, WS_SUBCHUNK, &buf[0]);
                                    if (rn < 0) break;
                                    unsigned char op = buf[0] & 0x0F;
                                    if (op == WS_OP_CLOSE) break;
                                    if (op == WS_OP_PING) {
                                        ws_send_frame_gtls(nw, WS_OP_PONG, out, (size_t)rn);
                                        continue;
                                    }
                                    if (op == WS_OP_PONG) continue;
                                     if (op == WS_OP_BIN && rn > 0) {
                                         if (fwrite(out, 1, (size_t)rn, fp) != (size_t)rn) { zep_log("push: fwrite chunk failed\n"); break; }
                                         zep_log("push: wrote %zd BIN bytes to chunk %s\n", rn, chunk_part);
                                         continue;
                                     }
                                     if (op == WS_OP_EXIT && rn == 1) node_exit_rc = (int)out[0];
                                     if (op == WS_OP_EXIT || op == WS_OP_EOF) break;
                                }
                                fclose(fp); fp = NULL;

                                /* Decompress chunk if push_unzip_cmd is configured */
                                if (g_push_unzip_cmd[0]) {
                                    char dcmd[1536];
                                    snprintf(dcmd, sizeof(dcmd),
                                        "exec %s < '%s' > '%s' 2>/dev/null",
                                        g_push_unzip_cmd, chunk_path_raw, chunk_path);
                                    FILE *udp = popen(dcmd, "r");
                                    int udr = udp ? pclose(udp) : -1;
                                    if (udr == 0) {
                                        unlink(chunk_path_raw);
                                    } else {
                                        zep_log("push: unzip failed rc=%d for chunk %s\n",
                                                WIFEXITED(udr) ? WEXITSTATUS(udr) : -1, chunk_part);
                                        unlink(chunk_path);
                                    }
                                } else {
                                    rename(chunk_path_raw, chunk_path);
                                }

                                /* Get chunk size */
                                uint64_t chunk_size = 0;
                                {
                                    FILE *chk = fopen(chunk_path, "rb");
                                    if (chk) { fseek(chk, 0, SEEK_END); chunk_size = (uint64_t)ftell(chk); fclose(chk); }
                                }

                               /* Validate chunk with zstream token -g -i */
                               err_t validate_err = zstream_token_from_file(chunk_path);
                               if (validate_err != ZEP_ERR_OK) {
                                   /* Garbage — retry same chunk, don't increment counter */
                                   zep_log("push: chunk %s garbage, retrying same chunk for guid=%s\n", chunk_part, guid);
                                    fp = fopen(chunk_path_raw, "wb");
                                    if (!fp) {
                                        zep_log("ws: push fopen failed on retry: %s\n", chunk_path_raw);
                                       ws_send_frame_gtls(nw, WS_OP_EXIT, (unsigned char *)&chunk_num, 1);
                                       ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                       push_dispatch = 0;
                                       break;
                                   }
                                   char req[256];
                                   snprintf(req, sizeof(req), "{\"action\":\"resume\"}");
                                   ws_send_frame_gtls(nw, WS_OP_TEXT, (unsigned char *)req, strlen(req));
                                   zep_log("push: sent resume request, waiting for re-transmit of chunk %s\n", chunk_part);

                                   for (;;) {
                                       ssize_t rn = ws_recv_frame_full(nw, buf, WS_SUBCHUNK + 256, out, WS_SUBCHUNK, &buf[0]);
                                       if (rn < 0) break;
                                       unsigned char op = buf[0] & 0x0F;
                                       if (op == WS_OP_CLOSE) break;
                                       if (op == WS_OP_PING) {
                                           ws_send_frame_gtls(nw, WS_OP_PONG, out, (size_t)rn);
                                           continue;
                                       }
                                       if (op == WS_OP_PONG) continue;
                                       if (op == WS_OP_BIN && rn > 0) {
                                           if (fwrite(out, 1, (size_t)rn, fp) != (size_t)rn) { zep_log("push: fwrite retry chunk failed\n"); break; }
                                           zep_log("push: wrote %zd BIN retry bytes to chunk %s\n", rn, chunk_part);
                                           continue;
                                       }
                                       if (op == WS_OP_EXIT || op == WS_OP_EOF) break;
                                   }
                                fclose(fp); fp = NULL;

                                /* Decompress chunk if push_unzip_cmd is configured */
                                if (g_push_unzip_cmd[0]) {
                                    char dcmd[1536];
                                    snprintf(dcmd, sizeof(dcmd),
                                        "exec %s < '%s' > '%s' 2>/dev/null",
                                        g_push_unzip_cmd, chunk_path_raw, chunk_path);
                                    FILE *udp = popen(dcmd, "r");
                                    int udr = udp ? pclose(udp) : -1;
                                    if (udr == 0) {
                                        unlink(chunk_path_raw);
                                    } else {
                                        zep_log("push: unzip failed rc=%d for chunk %s\n",
                                                WIFEXITED(udr) ? WEXITSTATUS(udr) : -1, chunk_part);
                                        unlink(chunk_path);
                                    }
                                } else {
                                    rename(chunk_path_raw, chunk_path);
                                }

                                   validate_err = zstream_token_from_file(chunk_path);
                                   if (validate_err != ZEP_ERR_OK) {
                                       zep_log("push: chunk %s still garbage after retry, aborting guid=%s\n", chunk_part, guid);
                                       ws_send_frame_gtls(nw, WS_OP_EXIT, (unsigned char *)&chunk_num, 1);
                                       ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                       push_dispatch = 0;
                                       break;
                                   }
                                   zep_log("push: chunk %s valid after retry for guid=%s\n", chunk_part, guid);
                               }

                               zep_log("push: chunk %s valid, joining for guid=%s\n", chunk_part, guid);

                               /* Accumulative join: assembled + new chunk -> assembled.tmp */
                               char assembled_tmp[ZEP_MAX_PATH * 2 + 256];
                               snprintf(assembled_tmp, sizeof(assembled_tmp), "%s/assembled.zfs.tmp", snap_dir);
                               int join_complete = 0;

                               err_t join_err = zstream_join_accumulative(
                                   assembled_path[0] && access(assembled_path, F_OK) == 0 ? assembled_path : NULL,
                                   chunk_path,
                                   assembled_tmp,
                                   &join_complete);
                               zep_log("push: join result: err=%d complete=%d for guid=%s\n",
                                       (int)join_err, join_complete, guid);

                               if (join_err != ZEP_ERR_OK) {
                                   zep_log("push: join failed for guid=%s\n", guid);
                                   if (g_resume && access(assembled_path, F_OK) == 0) {
                                       char tok[512] = {0};
                                       err_t tok_err = zstream_token_extract(assembled_path, tok, sizeof(tok));
                                       if (tok_err == ZEP_ERR_OK && tok[0]) {
                                           uint64_t assembled_sz = 0;
                                           FILE *af = fopen(assembled_path, "rb");
                                           if (af) { fseek(af, 0, SEEK_END); assembled_sz = (uint64_t)ftell(af); fclose(af); }
                                        db_fs_save_token(g_db, cluster, cfs, tok, (int64_t)assembled_sz);
                                        zep_log("push: saved resume token for guid=%s size=%lu\n",
                                                guid, (unsigned long)assembled_sz);
                                        /* Set push_status to 'pending' so dispatch finds this snapshot for the next chunk */
                                        sqlite3_stmt *rs_st = NULL;
                                        if (sqlite3_prepare_v2(g_db,
                                            "UPDATE snapshots SET push_status='pending' WHERE guid=?1",
                                            -1, &rs_st, NULL) == SQLITE_OK) {
                                            sqlite3_bind_text(rs_st, 1, guid, -1, SQLITE_STATIC);
                                            sqlite3_step(rs_st);
                                            sqlite3_finalize(rs_st);
                                        }
                                    }
                                   }
                                       sqlite3_stmt *sf = NULL;
                                   if (sqlite3_prepare_v2(g_db,
                                       "UPDATE snapshots SET push_status='resuming', "
                                       "blob_size=?, blob_count=? "
                                       "WHERE node=?1 AND guid=?2 AND push_status='pending'",
                                       -1, &sf, NULL) == SQLITE_OK) {
                                       sqlite3_bind_int64(sf, 1, (sqlite3_int64)chunk_size);
                                       sqlite3_bind_int(sf, 2, chunk_num + 1);
                                       sqlite3_bind_text(sf, 3, nw->cn, -1, SQLITE_STATIC);
                                       sqlite3_bind_text(sf, 4, guid, -1, SQLITE_STATIC);
                                       sqlite3_step(sf);
                                       sqlite3_finalize(sf);
                                   }
                                   ws_send_frame_gtls(nw, WS_OP_EXIT, (unsigned char *)&chunk_num, 1);
                                   ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                   unlink(assembled_tmp);
                                    push_dispatch = 0;
                                    if (cluster[0]) {
                                       sqlite3_stmt *rts = NULL;
                                       if (sqlite3_prepare_v2(g_db,
                                           "SELECT push_resume_token FROM fs "
                                           "WHERE cluster=?1 AND fs=?2 LIMIT 1",
                                           -1, &rts, NULL) == SQLITE_OK) {
                                           sqlite3_bind_text(rts, 1, cluster, -1, SQLITE_STATIC);
                                           sqlite3_bind_text(rts, 2, cfs, -1, SQLITE_STATIC);
                                           if (sqlite3_step(rts) == SQLITE_ROW) {
                                               const char *rt = (const char *)sqlite3_column_text(rts, 0);
                                               if (rt && rt[0]) {
                                                   char pj[4096];
                                                   int pn = snprintf(pj, sizeof(pj),
                                                       "{\"action\":\"push\",\"guid\":\"%s\",\"snapshot\":\"%s\","
                                                       "\"label\":\"%s\",\"cluster_fs\":\"%s\",\"base_guid\":\"%s\","
                                                       "\"resume_token\":\"%s\"}",
                                                       guid, snap, lbl, cfs, bg, rt);
                                                   if (pn > 0 && pn < (int)sizeof(pj)) {
                                                       zep_log("scheduler: retrying push for guid=%s with resume_token\n", guid);
                                                       zep_log("scheduler: push_cmd %s\n", pj);
                                                       ws_send_frame_gtls(nw, WS_OP_TEXT,
                                                           (unsigned char *)pj, (size_t)pn);
                                                   }
                                               }
                                           }
                                           sqlite3_finalize(rts);
                                       }
                                   }
                                   break;
                               }

                               /* Move assembled.tmp -> assembled */
                               unlink(assembled_path);
                               if (rename(assembled_tmp, assembled_path) != 0) {
                                   zep_log("push: rename assembled failed\n");
                                   ws_send_frame_gtls(nw, WS_OP_EXIT, (unsigned char *)&chunk_num, 1);
                                   ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                   push_dispatch = 0;
                                   break;
                               }

                               /* Check if complete: zstream join exit 0 means DRR_END present */
                               int is_complete = join_complete;
                               zep_log("push: joined chunk %s, node_exit_rc=%d join_complete=%d guid=%s\n",
                                       chunk_part, node_exit_rc, join_complete, guid);
                               char tok[512] = {0};
                               if (!is_complete) {
                                   zstream_token_extract(assembled_path, tok, sizeof(tok));
                               }

                               if (is_complete) {
                                    zep_log("push: full stream received for guid=%s\n", guid);

                                        uint64_t final_size = 0;
                                       FILE *af = fopen(assembled_path, "rb");
                                       if (af) { fseek(af, 0, SEEK_END); final_size = (uint64_t)ftell(af); fclose(af); }

                                        zep_log("push: db: marking snapshot verified guid=%s size=%lu chunks=%d\n",
                                                guid, (unsigned long)final_size, chunk_num + 1);
                                        db_fs_mark_snapshot_verified(g_db, guid, (int64_t)final_size,
                                                                     chunk_num + 1, bg);

                                        int pending_id = 0;
                                         if (db_fs_get_next_pending_id(g_db, cluster, nw->cn, &pending_id) == ZEP_ERR_OK && pending_id > 0) {
                                             zep_log("push: db: cascade skipped, %d pending remain\n", pending_id);
                                            /* still pending — don't cascade */
                                        } else {
                                            /* Get current snapshot rowid for cascade */
                                            sqlite3_stmt *rid_st = NULL;
                                            int current_rowid = 0;
                                            if (sqlite3_prepare_v2(g_db,
                                                "SELECT rowid FROM snapshots WHERE guid=?1 LIMIT 1",
                                                -1, &rid_st, NULL) == SQLITE_OK) {
                                                sqlite3_bind_text(rid_st, 1, guid, -1, SQLITE_STATIC);
                                                if (sqlite3_step(rid_st) == SQLITE_ROW) {
                                                    current_rowid = sqlite3_column_int(rid_st, 0);
                                                }
                                                sqlite3_finalize(rid_st);
                                            }
                                            if (current_rowid > 0) {
                                                int cascaded = 0;
                                                {
                                                    sqlite3_stmt *cc = NULL;
                                                    if (sqlite3_prepare_v2(g_db,
                                                        "SELECT COUNT(*) FROM snapshots "
                                                        "WHERE cluster=?1 AND direction='push' "
                                                        "AND rowid <= ?2 AND push_status='pending'",
                                                        -1, &cc, NULL) == SQLITE_OK) {
                                                        sqlite3_bind_text(cc, 1, cluster, -1, SQLITE_STATIC);
                                                        sqlite3_bind_int(cc, 2, current_rowid);
                                                        if (sqlite3_step(cc) == SQLITE_ROW)
                                                            cascaded = sqlite3_column_int(cc, 0);
                                                        sqlite3_finalize(cc);
                                                    }
                                                }
                                                db_fs_cascade_update_to_id(g_db, cluster, current_rowid);
                                                zep_log("push: db: cascaded %d pending snapshot(s) to verified (rowid<=%d)\n",
                                                        cascaded, current_rowid);
                                            }
                                        }

                                        int pk_rc = db_fs_mark_pushed(g_db, cluster, cfs, guid);
                                        zep_log("push: db: mark_pushed cluster=%s fs=%s guid=%s rc=%d\n",
                                                cluster, cfs, guid, (int)pk_rc);

                                   /* Clean up chunk files, keep assembled.zfs */
                                   {
                                       uint32_t i = 0;
                                       for (;;) {
                                           char cp[ZEP_MAX_PATH * 2 + 256];
                                           snprintf(cp, sizeof(cp), "%s/%04u.zfs", snap_dir, i);
                                           if (access(cp, F_OK) != 0) break;
                                           unlink(cp);
                                           i++;
                                       }
                                   }

                                   { char complete[128];
                                     snprintf(complete, sizeof(complete),
                                         "{\"guid\":\"%s\",\"size\":%lu,\"streams\":%d,\"result\":\"complete\"}",
                                         guid, (unsigned long)chunk_size, chunk_num + 1);
                                     ws_send_frame_gtls(nw, WS_OP_TEXT,
                                         (unsigned char *)complete, strlen(complete)); }
                                   zep_log("push: phase 3 complete for guid=%s size=%lu chunks=%d\n",
                                          guid, (unsigned long)chunk_size, chunk_num + 1);
                                   unsigned char ex = 0;
                                   ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                                    ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);
                                    if (cluster[0])
                                        server_dispatch_rotation(nw, cluster, "push");
                                } else {
                                    /* More data needed — save token and ask for more */
                                    if (g_resume && tok[0]) {
                                        uint64_t assembled_sz = 0;
                                        FILE *af = fopen(assembled_path, "rb");
                                        if (af) { fseek(af, 0, SEEK_END); assembled_sz = (uint64_t)ftell(af); fclose(af); }
                                        db_fs_save_token(g_db, cluster, cfs, tok, (int64_t)assembled_sz);
                                        zep_log("push: saved resume token for guid=%s size=%lu\n",
                                                guid, (unsigned long)assembled_sz);
                                    }

                                    { char complete[128];
                                      snprintf(complete, sizeof(complete),
                                          "{\"guid\":\"%s\",\"size\":%lu,\"streams\":%d,\"result\":\"incomplete\"}",
                                          guid, (unsigned long)chunk_size, chunk_num + 1);
                                      ws_send_frame_gtls(nw, WS_OP_TEXT,
                                          (unsigned char *)complete, strlen(complete)); }
                                    zep_log("push: incomplete for guid=%s, need more data (chunks=%d)\n",
                                           guid, chunk_num + 1);
                                    unsigned char ex = 0;
                                    ws_send_frame_gtls(nw, WS_OP_EXIT, &ex, 1);
                                    ws_send_frame_gtls(nw, WS_OP_EOF, NULL, 0);

                                    /* Re-dispatch the SAME guid for next chunk */
                                    {
                                        sqlite3_stmt *rts = NULL;
                                        if (sqlite3_prepare_v2(g_db,
                                            "SELECT push_resume_token FROM fs "
                                            "WHERE cluster=?1 AND fs=?2 LIMIT 1",
                                            -1, &rts, NULL) == SQLITE_OK) {
                                            sqlite3_bind_text(rts, 1, cluster, -1, SQLITE_STATIC);
                                            sqlite3_bind_text(rts, 2, cfs, -1, SQLITE_STATIC);
                                            if (sqlite3_step(rts) == SQLITE_ROW) {
                                                const char *rt = (const char *)sqlite3_column_text(rts, 0);
                                                if (rt && rt[0]) {
                                                    char pj[4096];
                                                    int pn = snprintf(pj, sizeof(pj),
                                                        "{\"action\":\"push\",\"guid\":\"%s\",\"snapshot\":\"%s\","
                                                        "\"label\":\"%s\",\"cluster_fs\":\"%s\",\"base_guid\":\"%s\","
                                                        "\"resume_token\":\"%s\"}",
                                                        guid, snap, lbl, cfs, bg, rt);
                                                    if (pn > 0 && pn < (int)sizeof(pj)) {
                                                        zep_log("scheduler: retrying push for guid=%s (incomplete)\n", guid);
                                                        zep_log("scheduler: push_cmd %s\n", pj);
                                                        ws_send_frame_gtls(nw, WS_OP_TEXT,
                                                            (unsigned char *)pj, (size_t)pn);
                                                        push_dispatch = 0;
                                                    }
                                                }
                                            }
                                            sqlite3_finalize(rts);
                                        }
                                    }
                                }
                               } while (0);
                              }
                              cJSON_Delete(msg);
                              if (push_dispatch && strcmp(role_buf, "master") == 0 && cluster_buf[0] && mapping_buf[0]) {
                                /* DB traffic: count pending/resuming snapshots */
                                {
                                    sqlite3_stmt *count_st = NULL;
                                    if (sqlite3_prepare_v2(g_db,
                                        "SELECT COUNT(*) FROM snapshots s "
                                        "WHERE s.node=?1 AND s.direction='push' "
                                        "AND (s.push_status='pending' OR s.push_status='resuming')",
                                        -1, &count_st, NULL) == SQLITE_OK) {
                                        sqlite3_bind_text(count_st, 1, nw->cn, -1, SQLITE_STATIC);
                                        if (sqlite3_step(count_st) == SQLITE_ROW) {
                                            int remaining = sqlite3_column_int(count_st, 0);
                                            zep_log("push: db state: %d push pending/resuming\n", remaining);
                                            if (remaining == 0) {
                                                zep_log("push: phase 3 complete\n");
                                                sqlite3_finalize(count_st);
                                                continue;
                                            }
                                        }
                                        sqlite3_finalize(count_st);
                                    }
                                }
                                sqlite3_stmt *next_st = NULL;
                                if (sqlite3_prepare_v2(g_db,
                                    "SELECT s.guid, s.snapshot, s.label, s.cluster_fs, s.base_guid "
                                    "FROM snapshots s "
                                    "WHERE s.node=?1 AND s.direction='push' "
                                    "AND (s.push_status='pending' OR s.push_status='resuming') "
                                    "ORDER BY rowid ASC LIMIT 1",
                                    -1, &next_st, NULL) == SQLITE_OK) {
                                    sqlite3_bind_text(next_st, 1, nw->cn, -1, SQLITE_STATIC);
                                    if (sqlite3_step(next_st) == SQLITE_ROW) {
                                        const char *ng = (const char *)sqlite3_column_text(next_st, 0);
                                        const char *ns = (const char *)sqlite3_column_text(next_st, 1);
                                        const char *nl = (const char *)sqlite3_column_text(next_st, 2);
                                        const char *nc = (const char *)sqlite3_column_text(next_st, 3);
                                        char rtok[512] = {0};
                                        char last_pushed_guid[ZEP_MAX_GUID_LEN] = {0};
                                        {
                                            sqlite3_stmt *rts = NULL;
                                            if (sqlite3_prepare_v2(g_db,
                                                "SELECT last_pushed_guid, push_resume_token FROM fs "
                                                "WHERE cluster=?1 AND fs=?2 LIMIT 1",
                                                -1, &rts, NULL) == SQLITE_OK) {
                                                sqlite3_bind_text(rts, 1, cluster_buf, -1, SQLITE_STATIC);
                                                sqlite3_bind_text(rts, 2, nc, -1, SQLITE_STATIC);
                                                if (sqlite3_step(rts) == SQLITE_ROW) {
                                                    const char *lpg = (const char *)sqlite3_column_text(rts, 0);
                                                    const char *rt = (const char *)sqlite3_column_text(rts, 1);
                                                    if (lpg && lpg[0])
                                                        snprintf(last_pushed_guid, sizeof(last_pushed_guid), "%s", lpg);
                                                    if (rt && rt[0])
                                                        snprintf(rtok, sizeof(rtok), "%s", rt);
                                                }
                                                sqlite3_finalize(rts);
                                            }
                                        }
                                        char base_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                        if (last_pushed_guid[0]) {
                                            sqlite3_stmt *bs_st = NULL;
                                            if (sqlite3_prepare_v2(g_db,
                                                "SELECT snapshot FROM snapshots WHERE guid=?1",
                                                -1, &bs_st, NULL) == SQLITE_OK) {
                                                sqlite3_bind_text(bs_st, 1, last_pushed_guid, -1, SQLITE_STATIC);
                                                if (sqlite3_step(bs_st) == SQLITE_ROW) {
                                                    const char *bs = (const char *)sqlite3_column_text(bs_st, 0);
                                                    if (bs && bs[0])
                                                        snprintf(base_snap, sizeof(base_snap), "%s", bs);
                                                }
                                                sqlite3_finalize(bs_st);
                                            }
                                        }
                                        if (ng && nc) {
                                            char pj[4096];
                                            int pn;
                                            if (rtok[0]) {
                                                pn = snprintf(pj, sizeof(pj),
                                                    "{\"action\":\"push\",\"guid\":\"%s\",\"snapshot\":\"%s\","
                                                    "\"label\":\"%s\",\"cluster_fs\":\"%s\",\"base_guid\":\"%s\","
                                                    "\"base_snap\":\"%s\",\"resume_token\":\"%s\"}",
                                                    ng, ns ? ns : "", nl ? nl : "", nc,
                                                    last_pushed_guid, base_snap, rtok);
                                            } else {
                                                pn = snprintf(pj, sizeof(pj),
                                                    "{\"action\":\"push\",\"guid\":\"%s\",\"snapshot\":\"%s\","
                                                    "\"label\":\"%s\",\"cluster_fs\":\"%s\",\"base_guid\":\"%s\","
                                                    "\"base_snap\":\"%s\"}",
                                                    ng, ns ? ns : "", nl ? nl : "", nc,
                                                    last_pushed_guid, base_snap);
                                            }
                                            if (pn > 0 && pn < (int)sizeof(pj)) {
                                                zep_log("scheduler: dispatching push for guid=%s label=%s%s\n",
                                                        ng, nl ? nl : "",
                                                        rtok[0] ? " (resume)" : "");
                                                zep_log("scheduler: push_cmd %s\n", pj);
                                                ws_send_frame_gtls(nw, WS_OP_TEXT,
                                                    (unsigned char *)pj, (size_t)pn);
                                            }
                                        }
                                    }
                                    sqlite3_finalize(next_st);
                                }
                            }
                            continue;
                        }
                      /* Handle create_snap response from node */
                      if (action && cJSON_IsString(action) &&
                          strcmp(action->valuestring, "create_snap") == 0) {
                         zep_log("create_snap: RX response from %s\n", nw->cn);
                         cJSON *guid_j = cJSON_GetObjectItem(msg, "guid");
                         cJSON *rc_j = cJSON_GetObjectItem(msg, "rc");
                         if (rc_j && cJSON_IsNumber(rc_j) && rc_j->valueint == 0 &&
                             guid_j && cJSON_IsString(guid_j) &&
                             pending_head < pending_tail) {
                             const char *guid = guid_j->valuestring;
                             const char *snap_name = pending_snaps[pending_head];
                             const char *label = pending_labels[pending_head];
                             pending_head++;

                             /* Determine cluster_fs from snapshot name (before @) */
                             const char *at = strchr(snap_name, '@');
                             char cluster_fs[512] = {0};
                             if (at) {
                                 size_t n = (size_t)(at - snap_name);
                                 if (n >= sizeof(cluster_fs)) n = sizeof(cluster_fs) - 1;
                                 memcpy(cluster_fs, snap_name, n);
                                 cluster_fs[n] = '\0';
                             }

                             /* Resolve to local snapshot name for DB storage */
                             char local_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
                             if (cluster_fs[0] && mapping_buf[0]) {
                                 const char *mp = mapping_buf;
                                 while (mp && *mp) {
                                     while (*mp==' '||*mp=='\t') mp++;
                                     if (!*mp) break;
                                     const char *colon = strchr(mp, ':');
                                     if (!colon) break;
                                     size_t cflen = (size_t)(colon - mp);
                                     char cfs_buf[512] = {0};
                                     if (cflen >= sizeof(cfs_buf)) cflen = sizeof(cfs_buf) - 1;
                                     memcpy(cfs_buf, mp, cflen);
                                     if (strcmp(cfs_buf, cluster_fs) == 0) {
                                         const char *start = colon + 1;
                                         while (*start==' ') start++;
                                         const char *end = strchr(start, ',');
                                         if (!end) end = start + strlen(start);
                                         const char *paren = strchr(start, '(');
                                         size_t ln = paren ? (size_t)(paren - start) : (size_t)(end - start);
                                         char local_fs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                         if (ln >= sizeof(local_fs)) ln = sizeof(local_fs) - 1;
                                         memcpy(local_fs, start, ln);
                                         snprintf(local_snap, sizeof(local_snap), "%s%s", local_fs, at);
                                         break;
                                     }
                                     const char *comma = strchr(colon, ',');
                                     mp = comma ? comma + 1 : colon + strlen(colon);
                                 }
                             }
                             if (!local_snap[0] && at)
                                 snprintf(local_snap, sizeof(local_snap), "%s", snap_name);

                              if (cluster_fs[0]) {
                                  char now_str[32];
                                  {
                                      time_t tnow = time(NULL);
                                      struct tm tm;
                                      gmtime_r(&tnow, &tm);
                                      strftime(now_str, sizeof(now_str), "%Y-%m-%dT%H:%M:%SZ", &tm);
                                  }
                                   db_snapshot_insert(g_db, cluster_buf, nw->cn,
                                        guid, "", local_snap, label, cluster_fs, 0, 0,
                                        "push", "", "pending", "discovered", "");
                                  {
                                      sqlite3_stmt *pa = NULL;
                                      if (sqlite3_prepare_v2(g_db,
                                          "UPDATE snapshots SET push_status='archived' WHERE node=?1 AND guid=?2",
                                          -1, &pa, NULL) == SQLITE_OK) {
                                          sqlite3_bind_text(pa, 1, nw->cn, -1, SQLITE_STATIC);
                                          sqlite3_bind_text(pa, 2, guid, -1, SQLITE_STATIC);
                                          sqlite3_step(pa);
                                          sqlite3_finalize(pa);
                                      }
                                  }
                                  char cron_key[1024];
                                  snprintf(cron_key, sizeof(cron_key),
                                      "cron_last_%s_%s_%s", cluster_buf, cluster_fs, label);
                                  db_config_set(g_db, cron_key, now_str);
                                  zep_log("scheduler: registered snap %s guid=%s label=%s\n",
                                       local_snap, guid, label);
                                  zep_log("create_snap: phase 2 complete\n");
                              }
                         } else {
                             if (pending_head < pending_tail) pending_head++;
                             zep_log("create_snap failed for node %s rc=%d\n",
                                 nw->cn, rc_j ? rc_j->valueint : -1);
                        }
                          zep_log_debug("create_snap: head=%d tail=%d initial_done=%d\n",
                              pending_head, pending_tail, initial_scheduler_done);
                           /* After all create_snap tasks acknowledged, promote latest per fs to pending, then dispatch push */
                           if (pending_head >= pending_tail &&
                               strcmp(role_buf, "master") == 0
                               && cluster_buf[0] && mapping_buf[0]) {
                               {
                                   sqlite3_stmt *prom_st = NULL;
                                   if (sqlite3_prepare_v2(g_db,
                                       "UPDATE snapshots SET push_status='pending' "
                                       "WHERE node=?1 AND push_status='archived' "
                                       "AND id IN (SELECT MAX(id) FROM snapshots "
                                       "WHERE node=?1 AND push_status='archived' "
                                       "GROUP BY cluster_fs)",
                                       -1, &prom_st, NULL) == SQLITE_OK) {
                                       sqlite3_bind_text(prom_st, 1, nw->cn, -1, SQLITE_STATIC);
                                       sqlite3_step(prom_st);
                                       sqlite3_finalize(prom_st);
                                   }
                                   zep_log("scheduler: promoted latest per fs to pending\n");
                               }
                               zep_log("scheduler: all create_snap done, dispatching push\n");
                              initial_scheduler_done = 0;
                              sqlite3_stmt *push_st = NULL;
                               zep_log_debug("push query: node=%s cluster=%s\n", nw->cn, cluster_buf);
                               int prep_rc = sqlite3_prepare_v2(g_db,
                                   "SELECT s.guid, s.snapshot, s.label, s.cluster_fs, s.base_guid "
                                   "FROM snapshots s "
                                   "WHERE s.node=?1 AND s.direction='push' "
                                   "AND (s.push_status='pending' OR s.push_status='resuming') "
                                   "ORDER BY rowid ASC LIMIT 1",
                                   -1, &push_st, NULL);
                               zep_log_debug("push query prepare rc=%d err=%s\n", prep_rc, sqlite3_errmsg(g_db));
                               if (prep_rc == SQLITE_OK) {
                                   sqlite3_bind_text(push_st, 1, nw->cn, -1, SQLITE_STATIC);
                                   int step_rc = sqlite3_step(push_st);
                                   zep_log_debug("push query step_rc=%d\n", step_rc);
                                   if (step_rc == SQLITE_ROW) {
                                       const char *pguid = (const char *)sqlite3_column_text(push_st, 0);
                                       const char *psnap = (const char *)sqlite3_column_text(push_st, 1);
                                       const char *plbl = (const char *)sqlite3_column_text(push_st, 2);
                                        const char *pcfs = (const char *)sqlite3_column_text(push_st, 3);
                                         /* Get last_pushed_guid and resume token from fs table */
                                         char resume_token[256] = {0};
                                         char last_pushed_guid_cs[ZEP_MAX_GUID_LEN] = {0};
                                         {
                                             sqlite3_stmt *rt_st = NULL;
                                             if (sqlite3_prepare_v2(g_db,
                                                 "SELECT last_pushed_guid, push_resume_token FROM fs "
                                                 "WHERE cluster=?1 AND fs=?2 LIMIT 1",
                                                 -1, &rt_st, NULL) == SQLITE_OK) {
                                                 sqlite3_bind_text(rt_st, 1, cluster_buf, -1, SQLITE_STATIC);
                                                 sqlite3_bind_text(rt_st, 2, pcfs, -1, SQLITE_STATIC);
                                                 if (sqlite3_step(rt_st) == SQLITE_ROW) {
                                                     const char *lpg = (const char *)sqlite3_column_text(rt_st, 0);
                                                     const char *rt = (const char *)sqlite3_column_text(rt_st, 1);
                                                     if (lpg && lpg[0])
                                                         snprintf(last_pushed_guid_cs, sizeof(last_pushed_guid_cs), "%s", lpg);
                                                     if (rt && rt[0])
                                                         snprintf(resume_token, sizeof(resume_token), "%s", rt);
                                                 }
                                                 sqlite3_finalize(rt_st);
                                             }
                                         }
                                         char base_snap_cs[ZEP_MAX_SNAPSHOT_NAME] = {0};
                                         if (last_pushed_guid_cs[0]) {
                                             sqlite3_stmt *bs_st = NULL;
                                             if (sqlite3_prepare_v2(g_db,
                                                 "SELECT snapshot FROM snapshots WHERE guid=?1",
                                                 -1, &bs_st, NULL) == SQLITE_OK) {
                                                 sqlite3_bind_text(bs_st, 1, last_pushed_guid_cs, -1, SQLITE_STATIC);
                                                 if (sqlite3_step(bs_st) == SQLITE_ROW) {
                                                     const char *bs = (const char *)sqlite3_column_text(bs_st, 0);
                                                     if (bs && bs[0])
                                                         snprintf(base_snap_cs, sizeof(base_snap_cs), "%s", bs);
                                                 }
                                                 sqlite3_finalize(bs_st);
                                             }
                                         }
                                        if (pguid && pcfs) {
                                            char push_json[4096];
                                            int pn;
                                            if (resume_token[0]) {
                                                pn = snprintf(push_json, sizeof(push_json),
                                                    "{\"action\":\"push\",\"guid\":\"%s\",\"snapshot\":\"%s\","
                                                    "\"label\":\"%s\",\"cluster_fs\":\"%s\",\"base_guid\":\"%s\","
                                                    "\"base_snap\":\"%s\",\"resume_token\":\"%s\"}",
                                                    pguid, psnap ? psnap : "", plbl ? plbl : "", pcfs,
                                                    last_pushed_guid_cs, base_snap_cs, resume_token);
                                            } else {
                                                pn = snprintf(push_json, sizeof(push_json),
                                                    "{\"action\":\"push\",\"guid\":\"%s\",\"snapshot\":\"%s\","
                                                    "\"label\":\"%s\",\"cluster_fs\":\"%s\",\"base_guid\":\"%s\","
                                                    "\"base_snap\":\"%s\"}",
                                                    pguid, psnap ? psnap : "", plbl ? plbl : "", pcfs,
                                                    last_pushed_guid_cs, base_snap_cs);
                                            }
                                            if (pn > 0 && pn < (int)sizeof(push_json)) {
                                                zep_log("scheduler: dispatching push for guid=%s label=%s%s\n",
                                                        pguid, plbl ? plbl : "",
                                                        resume_token[0] ? " (resume)" : "");
                                                zep_log("scheduler: push_cmd %s\n", push_json);
                                                ws_send_frame_gtls(nw, WS_OP_TEXT,
                                                    (unsigned char *)push_json, (size_t)pn);
                                            }
                                       }
                                  }
                                  sqlite3_finalize(push_st);
                              }
                          }
                          cJSON_Delete(msg);
                          continue;
                       }
                       cJSON_Delete(msg);
                }
            }
                if (plen == 0) continue; /* empty data frame */
        }

        if (time(NULL) - nw->last_pong > 180) break;
    }

if (g_logging & LOG_LEVEL_DEBUG) {
         zep_log_debug("ws: node %s disconnected\n", nw->cn);
     }

    free(buf); free(out);

    /* Signal bridge that thread has fully exited (if not already done) */
    pthread_mutex_lock(&nw->lock);
    if (nw->pipe_starting && !nw->pipe_thread_exited) {
        nw->pipe_thread_exited = 1;
        pthread_cond_signal(&nw->pipe_ready);
    }
    pthread_mutex_unlock(&nw->lock);

    /* Always clean up our nw entry */
    node_ws_unregister(nw);
    return NULL;
}

/* Node WS upgrade handler */
static void ws_node_upgrade_handler(void *cls, struct MHD_Connection *conn,
                                      void *con_cls, const char *extra_in,
                                      size_t extra_in_size, int sock,
                                      struct MHD_UpgradeResponseHandle *urh) {
    (void)cls; (void)conn; (void)con_cls; (void)extra_in; (void)extra_in_size;

    const char *cn = (const char *)cls;
    if (!cn) { MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE); return; }

    ws_set_keepalive(sock);

    struct node_ws *nw = node_ws_register(cn, sock);
    if (!nw) { MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE); return; }

    /* Spawn thread for WS loop — uses plain send/recv on socketpair fd.
     * MHD's internal polling thread handles TLS (gnutls_record_send/recv)
     * on the real client socket. The socketpair (sv[0]=app.socket) carries
     * plaintext — our thread never touches GnuTLS, avoiding the data race. */
    struct node_ws_thread_ctx *ctx = malloc(sizeof(*ctx));
    ctx->nw = nw;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED);
    pthread_create(&nw->thread, &attr, node_ws_thread, ctx);
    pthread_attr_destroy(&attr);
    // thread not detached — MHD must join it during cleanup
}

static int pipe_allowed_check(char *const *cmd_tokens, int cmd_n, const char *allowlist) {
    if (!allowlist || !allowlist[0]) return 0;
    if (cmd_n == 0) return 0;

    char *al_copy = strdup(allowlist);
    if (!al_copy) return 0;
    char *save = NULL;
    char *entry = strtok_r(al_copy, ",", &save);
    while (entry) {
        while (*entry == ' ' || *entry == '\t') entry++;
        if (!*entry) { entry = strtok_r(NULL, ",", &save); continue; }

        char *entry_tokens[32];
        int entry_neg[32] = {0};
        int entry_n = 0;
        int first_neg = -1;
        char *ep = entry;
        while (*ep && entry_n < 31) {
            while (*ep == ' ' || *ep == '\t') ep++;
            if (!*ep) break;
            int neg = 0;
            if (*ep == '!') { neg = 1; ep++; if (first_neg < 0) first_neg = entry_n; }
            char *estart = ep;
            while (*ep && *ep != ' ' && *ep != '\t') ep++;
            if (*ep) *ep++ = '\0';
            if (!estart[0]) continue;
            entry_neg[entry_n] = neg;
            entry_tokens[entry_n++] = estart;
        }

		if (entry_n == 0) { entry = strtok_r(NULL, ",", &save); continue; }

		if (entry_n == 1 && strcmp(entry_tokens[0], "*") == 0) { free(al_copy); return 1; }

		int prefix_n = (first_neg >= 0) ? first_neg : entry_n;
        if (prefix_n == 0 || prefix_n > cmd_n) {
            entry = strtok_r(NULL, ",", &save);
            continue;
        }

        for (int i = 0; i < prefix_n - 1; i++) {
            if (strcmp(entry_tokens[i], cmd_tokens[i]) != 0)
                goto next_entry;
        }
        {
            int last = prefix_n - 1;
            size_t elen = strlen(entry_tokens[last]);
            if (strncmp(entry_tokens[last], cmd_tokens[last], elen) != 0)
                goto next_entry;
        }

        if (prefix_n < cmd_n) {
            for (int i = prefix_n; i < entry_n; i++) {
                if (entry_neg[i] && strcmp(entry_tokens[i], cmd_tokens[prefix_n]) == 0) {
                    free(al_copy);
                    return 0;
                }
            }
        }

        free(al_copy);
        return 1;

next_entry:
        entry = strtok_r(NULL, ",", &save);
    }

    free(al_copy);
    return 0;
}

static int tool_allowed(const char *tool, const char *tools_list) {
    if (!tool || !tools_list || !tools_list[0]) return 0;
    if (!tool[0]) return 0;

    char *list_copy = strdup(tools_list);
    if (!list_copy) return 0;
    char *save = NULL;
    char *entry = strtok_r(list_copy, ",", &save);
    while (entry) {
        while (*entry == ' ' || *entry == '\t') entry++;
		if (strcmp(entry, "*") == 0) { free(list_copy); return 1; }
		if (strcmp(entry, tool) == 0) { free(list_copy); return 1; }
        entry = strtok_r(NULL, ",", &save);
    }
    free(list_copy);
    return 0;
}

static int pipe_allowed(const char *command, const char *allowlist) {
    if (!command || !allowlist || !allowlist[0]) return 0;

    char *cmd_tokens[128];
    int cmd_n = 0;
    char *cmd_copy = strdup(command);
    if (!cmd_copy) return 0;
    char *p = cmd_copy;
    while (*p && cmd_n < 127) {
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
        cmd_tokens[cmd_n++] = start;
    }

    if (cmd_n == 0) { free(cmd_copy); return 0; }

    /* Split into segments at pipe boundaries */
    struct { int start; int len; } segments[65];
    int seg_count = 0;
    int seg_start = 0;
    for (int i = 0; i < cmd_n; i++) {
        if (strcmp(cmd_tokens[i], "|") == 0) {
            if (i > seg_start) {
                segments[seg_count].start = seg_start;
                segments[seg_count].len = i - seg_start;
                seg_count++;
            }
            seg_start = i + 1;
        }
    }
    if (cmd_n > seg_start) {
        segments[seg_count].start = seg_start;
        segments[seg_count].len = cmd_n - seg_start;
        seg_count++;
    }

    if (seg_count == 1) {
        /* No pipeline — single command check */
        int result = pipe_allowed_check(cmd_tokens, cmd_n, allowlist);
        free(cmd_copy);
        return result;
    }

    /* Load pipe_allow_tools */
    char tools_list[1024] = {0};
    db_config_get(g_db, "pipe_allow_tools", tools_list, sizeof(tools_list));
    if (!tools_list[0])
        snprintf(tools_list, sizeof(tools_list), "buffer,mbuffer,zstd,lz4,gzip,gunzip");

    /* Classify: tool segment (first token in tools list) vs main (non-tool) */
    int main_seg = -1;
    for (int i = 0; i < seg_count; i++) {
        int is_tool = tool_allowed(cmd_tokens[segments[i].start], tools_list);
        if (!is_tool) {
            if (main_seg >= 0) {
                /* Multiple non-tool segments — ambiguous pipeline */
                free(cmd_copy);
                return 0;
            }
            main_seg = i;
        }
    }

    if (main_seg < 0) {
        /* All segments are tools — no recognizable main command */
        free(cmd_copy);
        return 0;
    }

    /* Verify all tool segments are known tools */
    for (int i = 0; i < seg_count; i++) {
        if (i == main_seg) continue;
        if (!tool_allowed(cmd_tokens[segments[i].start], tools_list)) {
            free(cmd_copy);
            return 0;
        }
    }

    /* Check main command segment against pipe_allow */
    int result = pipe_allowed_check(
        &cmd_tokens[segments[main_seg].start],
        segments[main_seg].len,
        allowlist);
    free(cmd_copy);
    return result;
}

/* Admin pipe WS upgrade handler - bridges to node WS */
static void ws_pipe_upgrade_handler(void *cls, struct MHD_Connection *conn,
                                     void *con_cls, const char *extra_in,
                                     size_t extra_in_size, int sock,
                                     struct MHD_UpgradeResponseHandle *urh) {
    (void)cls; (void)conn; (void)con_cls; (void)extra_in; (void)extra_in_size;

    const char *node_cn = (const char *)cls;
    if (!node_cn) { MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE); return; }

    ws_set_keepalive(sock);

    /* Find node connection */
    struct node_ws *nw = node_ws_find(node_cn);
    if (!nw) {
        zep_log( "ws: pipe request for %s — not connected\n", node_cn);
        fflush(stderr);
        MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
        return;
    }
zep_log_debug("ws: pipe found node %s sock=%d\n", node_cn, nw->sock);

    /* Check pipe_allow before taking over node thread */
    const char *command = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "command");
    const char *interactive = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "interactive");
    int is_interactive = (interactive && strcmp(interactive, "1") == 0);
    if (command) {

        char pipe_allow[2048] = {0};
        db_config_get(g_db, "pipe_allow", pipe_allow, sizeof(pipe_allow));
        if (!pipe_allow[0]) snprintf(pipe_allow, sizeof(pipe_allow), "zfs");

        if (!pipe_allowed(command, pipe_allow)) {
            zep_log( "ws: pipe denied for '%s' to node %s\n", command, node_cn);
            char errmsg[512];
            int elen = snprintf(errmsg, sizeof(errmsg), "pipe: access denied for '%s'", command);
            unsigned char fbuf[2048];
            size_t flen;
            flen = ws_build_frame(fbuf, sizeof(fbuf), WS_OP_TEXT, (unsigned char *)errmsg, (size_t)elen);
            if (flen > 0) send(sock, fbuf, flen, MSG_NOSIGNAL);
            flen = ws_build_frame(fbuf, sizeof(fbuf), WS_OP_EXIT, (unsigned char *)"\x01", 1);
            if (flen > 0) send(sock, fbuf, flen, MSG_NOSIGNAL);
            flen = ws_build_frame(fbuf, sizeof(fbuf), WS_OP_CLOSE, NULL, 0);
            if (flen > 0) send(sock, fbuf, flen, MSG_NOSIGNAL);
            MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
            return;
        }
    }

    /* Signal node thread to exit so we can take over the socket */
    pthread_mutex_lock(&nw->lock);
    nw->pipe_starting = 1;
    pthread_mutex_unlock(&nw->lock);

    /* Wait for node thread to signal it has exited */
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        pthread_mutex_lock(&nw->lock);
        while (!nw->pipe_thread_exited) {
            pthread_cond_timedwait(&nw->pipe_ready, &nw->lock, &ts);
        }
        pthread_mutex_unlock(&nw->lock);
    }

    /* Mark bridge as active so node thread doesn't free nw */
    nw->pipe_bridge_active = 1;

    /* Join the node thread to ensure it is fully dead */
    pthread_join(nw->thread, NULL);

   zep_log_debug("ws: node %s thread joined, pipe taking over\n", node_cn);

    /* Bridge: admin socket ↔ node WS via socketpair (nw->sock) */
    int node_fd = nw->sock;
    int admin_raw_fd = sock;

    /* Send task JSON to node */
    if (command) {
        cJSON *task = cJSON_CreateObject();
        cJSON_AddStringToObject(task, "action", "pipe");
        cJSON_AddStringToObject(task, "command", command);
        if (is_interactive) cJSON_AddBoolToObject(task, "interactive", 1);
        char *task_json = cJSON_PrintUnformatted(task);
        if (task_json) {
zep_log_debug("ws: sending task to node: %s\n", task_json);
            ws_send_frame_gtls(nw, WS_OP_TEXT, (unsigned char *)task_json, strlen(task_json));
            free(task_json);
        }
        cJSON_Delete(task);
    }

    /* Bridge: admin socket ↔ node WS */
    ws_make_blocking(sock);
    ws_make_blocking(node_fd);
    unsigned char *admin_buf = malloc(WS_ADMIN_BUF);
    size_t admin_acc_len = 0;
    unsigned char *node_buf = malloc(WS_SUBCHUNK);
    unsigned char *admin_out = malloc(WS_SUBCHUNK);
    unsigned char *node_out = malloc(WS_SUBCHUNK);
    if (!admin_buf || !node_buf || !admin_out || !node_out) {
        free(admin_buf); free(node_buf); free(admin_out); free(node_out);
        MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
        return;
    }

    int admin_alive = 1, node_alive = 1;
    for (;;) {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = 0;
             if (admin_alive) { FD_SET(admin_raw_fd, &rfds); if (admin_raw_fd > maxfd) maxfd = admin_raw_fd; }
        if (node_alive) { FD_SET(node_fd, &rfds); if (node_fd > maxfd) maxfd = node_fd; }
        int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);

        if (sel > 0) {
            /* Admin → Node: read raw bytes into accumulator */
            if (admin_alive && FD_ISSET(admin_raw_fd, &rfds)) {
                unsigned char tmp[16384];
                ssize_t n = recv(sock, tmp, sizeof(tmp), 0);
                if (n <= 0) {
                    admin_alive = 0;
                } else if (admin_acc_len + (size_t)n > WS_ADMIN_BUF) {
                    admin_alive = 0;
                } else {
                    memcpy(admin_buf + admin_acc_len, tmp, (size_t)n);
                    admin_acc_len += (size_t)n;
                }
            }

            /* Node → Admin: forward all BIN and TEXT frames */
                     if (node_alive && FD_ISSET(node_fd, &rfds)) {
                ssize_t plen = ws_recv_frame_full(nw, node_buf, WS_SUBCHUNK, node_out, WS_SUBCHUNK, &node_buf[0]);
                if (plen < 0) { node_alive = 0; }
                else {
                    unsigned char opcode = node_buf[0] & 0x0F;
                    if (opcode == WS_OP_CLOSE) {
                        node_alive = 0;
                    }
                    else if (opcode == WS_OP_PING) {
                        ws_send_frame_gtls(nw, WS_OP_PONG, node_out, (size_t)plen);
                    }
                    else if (admin_alive && (opcode == WS_OP_BIN || opcode == WS_OP_TEXT || opcode == WS_OP_EOF || opcode == WS_OP_EXIT)) {
                        unsigned char fbuf[WS_SUBCHUNK + 14];
                        size_t flen = ws_build_frame(fbuf, sizeof(fbuf), opcode, node_out, (size_t)plen);
                        if (flen > 0) {
                            ssize_t sent = 0;
                            while ((size_t)sent < flen) {
                                ssize_t n = send(sock, fbuf + sent, flen - (size_t)sent, MSG_NOSIGNAL);
                                if (n <= 0) break;
                                sent += n;
                            }
                        }
                    }
                }
            }
        }

        /* Consume complete frames from admin accumulator */
        while (admin_alive && admin_acc_len >= 2) {
            unsigned char aop = admin_buf[0] & 0x0F;
            uint64_t plf = admin_buf[1] & 0x7F;
            size_t hlen = 2;
            uint64_t plen_val;

            if (plf < 126) {
                plen_val = plf;
            } else if (plf == 126) {
                if (admin_acc_len < 4) break;
                plen_val = ((uint64_t)admin_buf[2] << 8) | admin_buf[3];
                hlen = 4;
            } else {
                if (admin_acc_len < 10) break;
                plen_val = 0;
                for (int i = 0; i < 8; i++)
                    plen_val = (plen_val << 8) | admin_buf[2 + i];
                hlen = 10;
            }

            size_t ftot = hlen + (size_t)plen_val;
            if (admin_acc_len < ftot) break;

            if (aop == WS_OP_CLOSE) {
                if (node_alive)
                    ws_send_frame_gtls(nw, WS_OP_CLOSE, NULL, 0);
                admin_alive = 0;
            } else if (aop == WS_OP_PING) {
                unsigned char fbuf[WS_SUBCHUNK + 14];
                size_t flen = ws_build_frame(fbuf, sizeof(fbuf), WS_OP_PONG, admin_buf + hlen, (size_t)plen_val);
                if (flen > 0) send(sock, fbuf, flen, MSG_NOSIGNAL);
            } else if (node_alive && (aop == WS_OP_BIN || aop == WS_OP_TEXT || aop == WS_OP_EOF || aop == WS_OP_EXIT)) {
                if (ws_send_frame_gtls(nw, aop, admin_buf + hlen, (size_t)plen_val) < 0)
                    node_alive = 0;
            }

            memmove(admin_buf, admin_buf + ftot, admin_acc_len - ftot);
            admin_acc_len -= ftot;
        }

        if (!admin_alive && node_alive) {
            ws_send_frame_gtls(nw, WS_OP_CLOSE, NULL, 0);
        }

        if (!admin_alive || !node_alive) break;
    }

zep_log_debug("ws: pipe bridge ended admin=%d node=%d\n", admin_alive, node_alive);

    {
        unsigned char cbuf[14];
        size_t clen = ws_build_frame(cbuf, sizeof(cbuf), WS_OP_CLOSE, NULL, 0);
        send(sock, cbuf, clen, MSG_NOSIGNAL);
    }
    MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);

    free(admin_buf); free(node_buf); free(admin_out); free(node_out);

    /* Free nw — node thread skipped free due to pipe_bridge_active */
    free(nw);

    /* Don't unregister node — it reconnects on its own */
}

static enum MHD_Result ws_handle_node(struct MHD_Connection *conn,
                                       const char *cn) {
zep_log_debug("ws: node upgrade request for %s\n", cn);

    const char *upgrade = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Upgrade");
    const char *ws_key = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Key");
    const char *ws_ver = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Version");

    if (!upgrade || strcasecmp(upgrade, "websocket") != 0)
        return send_error(conn, 400, "Upgrade: websocket required", NULL);
    if (!ws_key || !ws_key[0])
        return send_error(conn, 400, "Sec-WebSocket-Key required", NULL);
    if (!ws_ver || strcmp(ws_ver, "13") != 0)
        return send_error(conn, 400, "Sec-WebSocket-Version: 13 required", NULL);

    char accept[128];
    ws_build_accept(ws_key, accept, sizeof(accept));

    struct MHD_Response *resp = MHD_create_response_for_upgrade(
        &ws_node_upgrade_handler, (void *)cn);
    if (!resp) return send_error(conn, 500, "Failed to create upgrade response", NULL);

    MHD_add_response_header(resp, "Upgrade", "websocket");
    MHD_add_response_header(resp, "Connection", "Upgrade");
    MHD_add_response_header(resp, "Sec-WebSocket-Accept", accept);

    enum MHD_Result ret = MHD_queue_response(conn, 101, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result ws_handle_pipe(struct MHD_Connection *conn,
                                       const char *node_cn) {
   zep_log_debug("ws: pipe upgrade request for node %s\n", node_cn);

    const char *upgrade = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Upgrade");
    const char *ws_key = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Key");
    const char *ws_ver = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Version");

    if (!upgrade || strcasecmp(upgrade, "websocket") != 0)
        return send_error(conn, 400, "Upgrade: websocket required", NULL);
    if (!ws_key || !ws_key[0])
        return send_error(conn, 400, "Sec-WebSocket-Key required", NULL);
    if (!ws_ver || strcmp(ws_ver, "13") != 0)
        return send_error(conn, 400, "Sec-WebSocket-Version: 13 required", NULL);

    if (!node_ws_find(node_cn))
        return send_error(conn, 503, "Node not connected", NULL);

    char accept[128];
    ws_build_accept(ws_key, accept, sizeof(accept));

    struct MHD_Response *resp = MHD_create_response_for_upgrade(
        &ws_pipe_upgrade_handler, (void *)node_cn);
    if (!resp) return send_error(conn, 500, "Failed to create upgrade response", NULL);

    MHD_add_response_header(resp, "Upgrade", "websocket");
    MHD_add_response_header(resp, "Connection", "Upgrade");
    MHD_add_response_header(resp, "Sec-WebSocket-Accept", accept);

    enum MHD_Result ret = MHD_queue_response(conn, 101, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result handle_request(void *cls, struct MHD_Connection *conn,
                                       const char *url, const char *method,
                                       const char *version, const char *upload_data,
                                       size_t *upload_data_size, void **con_cls) {
    (void)cls; (void)version;
    struct conn_ctx *ctx = (struct conn_ctx *)*con_cls;

    if (!ctx) {
        ctx = calloc(1, sizeof(*ctx));
        if (!ctx) return MHD_NO;
        *con_cls = ctx;
        snprintf(ctx->method, sizeof(ctx->method), "%s", method);
        snprintf(ctx->target_url, sizeof(ctx->target_url), "%s", url);
        parse_url(url, ctx);

        const union MHD_ConnectionInfo *info = MHD_get_connection_info(
            conn, MHD_CONNECTION_INFO_GNUTLS_CLIENT_CERT);
        gnutls_x509_crt_t client_cert =
            info ? (gnutls_x509_crt_t)info->client_cert : NULL;

        if (!client_cert) {
            const union MHD_ConnectionInfo *sinfo = MHD_get_connection_info(
                conn, MHD_CONNECTION_INFO_GNUTLS_SESSION);
            if (sinfo && sinfo->tls_session) {
                unsigned int cert_count = 0;
                const gnutls_datum_t *certs = gnutls_certificate_get_peers(
                    (gnutls_session_t)sinfo->tls_session, &cert_count);
                if (certs && cert_count > 0) {
                    gnutls_x509_crt_t crt;
                    if (gnutls_x509_crt_init(&crt) >= 0) {
                        if (gnutls_x509_crt_import(crt, &certs[0],
                                GNUTLS_X509_FMT_DER) >= 0)
                            client_cert = crt;
                        else
                            gnutls_x509_crt_deinit(crt);
                    }
                }
            }
        }

        if (strcmp(url, "/health") == 0) {
            return send_response(conn, 200, "text/plain", "ok", 2, ctx);
        }

        if (client_cert) {
            unsigned char fp_buf[32];
            size_t fp_size = sizeof(fp_buf);
            if (gnutls_x509_crt_get_fingerprint(client_cert,
                    GNUTLS_DIG_SHA256, fp_buf, &fp_size) == 0) {
                char fp_hex[65];
                for (size_t j = 0; j < fp_size; j++)
                    sprintf(fp_hex + j * 2, "%02X", fp_buf[j]);
                fp_hex[fp_size * 2] = '\0';

                char role[16] = {0};
                db_auth_get_role_by_fp(g_db, fp_hex, role, sizeof(role));
                snprintf(ctx->role, sizeof(ctx->role), "%s", role);

                size_t dn_size = 0;
                gnutls_x509_crt_get_dn(client_cert, NULL, &dn_size);
                if (dn_size > 0) {
                    char *dn = malloc(dn_size);
                    if (dn) {
                        if (gnutls_x509_crt_get_dn(client_cert, dn, &dn_size) == 0) {
                            const char *cn_start = strstr(dn, "CN=");
                            if (cn_start) {
                                cn_start += 3;
                                const char *end = strchr(cn_start, ',');
                                size_t n = end ? (size_t)(end - cn_start)
                                               : strlen(cn_start);
                                if (!ctx->node[0]) {
                                    if (n >= sizeof(ctx->node)) n = sizeof(ctx->node) - 1;
                                    memcpy(ctx->node, cn_start, n);
                                    ctx->node[n] = '\0';
                                }
                            }
                        }
                        free(dn);
                    }
                }

                zep_log("auth: fp=%.4s cn=%s role=%s %s %s\n",
                         fp_hex, ctx->node[0] ? ctx->node : "?", role, method, url);

                if (client_cert) {
                    gnutls_x509_crt_deinit(client_cert);
                    client_cert = NULL;
                }

                if (strncmp(ctx->target_url, "/v1/admin", 9) == 0 &&
                    strcmp(role, "admin") != 0) {
                    return send_error(conn, 403, "Admin access required", ctx);
                }
            }
        }

        if (g_no_tls && !ctx->node[0]) {
            const char *cn = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "cn");
            if (cn && cn[0]) snprintf(ctx->node, sizeof(ctx->node), "%s", cn);
        }

        ctx->authed = 1;
        return MHD_YES;
    }

    if (!ctx->authed) {
        return send_error(conn, 401, "Client certificate required", ctx);
    }

    if (*upload_data_size > 0) {
        size_t new_len = ctx->body_len + *upload_data_size;
        if (new_len > ctx->body_cap) {
            size_t new_cap = ctx->body_cap ? ctx->body_cap * 2 : 65536;
            while (new_cap < new_len) new_cap *= 2;
            unsigned char *nb = realloc(ctx->body, new_cap);
            if (!nb) return MHD_NO;
            ctx->body = nb;
            ctx->body_cap = new_cap;
        }
        memcpy(ctx->body + ctx->body_len, upload_data, *upload_data_size);
        ctx->body_len = new_len;
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* ── admin routes ── */
    if (strncmp(ctx->target_url, "/v1/admin", 9) == 0) {

        /* cluster routes */
        if (strncmp(ctx->target_url, "/v1/admin/clusters", 18) == 0) {
            if (strcmp(ctx->method, "POST") == 0 &&
                strcmp(ctx->target_url, "/v1/admin/clusters") == 0) {
                cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
                if (!json) return send_error(conn, 400, "Invalid JSON", ctx);
                cJSON *name = cJSON_GetObjectItem(json, "name");
                if (!name || !cJSON_IsString(name) || !name->valuestring[0]) {
                    cJSON_Delete(json);
                    return send_error(conn, 400, "Missing cluster name", ctx);
                }
                char cfg_key[128];
                snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", name->valuestring);
                char *js = cJSON_PrintUnformatted(json);
                cJSON_Delete(json);
                db_config_set(g_db, cfg_key, js);
                zep_log_debug( "cluster set: key=%s len=%zu\n", cfg_key, strlen(js));
                free(js);
                return send_json(conn, 200, "{\"ok\":true}", ctx);
            }

            if (strcmp(ctx->method, "GET") == 0) {
                if (strncmp(ctx->target_url, "/v1/admin/clusters/", 19) == 0) {
                    const char *cn = ctx->target_url + 19;
                    if (cn[0]) {
                        char cfg_key[128], val[65536] = {0};
                        snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", cn);
                        if (db_config_get(g_db, cfg_key, val, sizeof(val)) == ZEP_ERR_OK)
                            return send_json(conn, 200, val, ctx);
                    }
                    return send_error(conn, 404, "Not found", ctx);
                }
                /* list clusters: return names */
                cJSON *arr = cJSON_CreateArray();
                char key_buf[256], val_buf[16];
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(g_db,
                    "SELECT key FROM config WHERE key LIKE 'cluster_%'", -1, &st, NULL);
                if (st) {
                    while (sqlite3_step(st) == SQLITE_ROW) {
                        const char *k = (const char *)sqlite3_column_text(st, 0);
                        if (k && strlen(k) > 8)
                            cJSON_AddItemToArray(arr, cJSON_CreateString(k + 8));
                    }
                    sqlite3_finalize(st);
                }
                (void)key_buf; (void)val_buf;
                char *js = cJSON_PrintUnformatted(arr);
                cJSON_Delete(arr);
                enum MHD_Result ret = send_json(conn, 200, js, ctx);
                free(js);
                return ret;
            }

            if (strcmp(ctx->method, "DELETE") == 0 &&
                strncmp(ctx->target_url, "/v1/admin/clusters/", 19) == 0) {
                const char *cn = ctx->target_url + 19;
                if (cn[0]) {
                    char cfg_key[128];
                    snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", cn);
                    db_config_set(g_db, cfg_key, "");
                    return send_json(conn, 200, "{\"ok\":true}", ctx);
                }
                return send_error(conn, 400, "Missing cluster name", ctx);
            }

            return send_error(conn, 404, "Cluster endpoint not found", ctx);
        }

        if (strcmp(ctx->method, "POST") == 0) {
            if (strcmp(ctx->target_url, "/v1/admin/nodes") == 0) {
                cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
                if (!json) return send_error(conn, 400, "Invalid JSON", ctx);
                cJSON *cn = cJSON_GetObjectItem(json, "cn");
                cJSON *role = cJSON_GetObjectItem(json, "role");
                cJSON *pem = cJSON_GetObjectItem(json, "pem");
                cJSON *cl = cJSON_GetObjectItem(json, "cluster");
                cJSON *mp = cJSON_GetObjectItem(json, "mapping");
                int ok = 0;
                if (cn && cJSON_IsString(cn) && role && cJSON_IsString(role) &&
                    pem && cJSON_IsString(pem)) {
                    const char *cluster_name = (cl && cJSON_IsString(cl)) ? cl->valuestring : "";
                    const char *mapping = (mp && cJSON_IsString(mp)) ? mp->valuestring : "";

                    if (cluster_name[0]) {
                        char cluster_json[65536] = {0};
                        char cfg_key[128];
                        snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", cluster_name);
                        if (db_config_get(g_db, cfg_key, cluster_json,
                                          sizeof(cluster_json)) != ZEP_ERR_OK) {
                            cJSON_Delete(json);
                            return send_error(conn, 400, "Cluster not found", ctx);
                        }
                    }

                    BIO *bio = BIO_new_mem_buf(pem->valuestring, -1);
                    if (bio) {
                        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
                        BIO_free(bio);
                        if (cert) {
                            char *fp = auth_cert_fingerprint(cert);
                            X509_free(cert);
                            if (fp) {
                                db_cert_store(g_db, cn->valuestring, fp,
                                              pem->valuestring, role->valuestring,
                                              cluster_name, mapping);
                                free(fp);
                                ok = 1;
                            }
                        }
                    }
                }
                cJSON_Delete(json);
                return ok ? send_json(conn, 200, "{\"ok\":true}", ctx)
                          : send_error(conn, 400, "Bad request", ctx);
            }
        }

        if (strcmp(ctx->method, "GET") == 0 && strcmp(ctx->target_url, "/v1/admin/nodes") == 0) {
            char **names = NULL;
            int count = 0;
            db_auth_list(g_db, &names, &count);
            cJSON *arr = cJSON_CreateArray();
            for (int i = 0; i < count; i++) cJSON_AddItemToArray(arr, cJSON_CreateString(names[i]));
            char *js = cJSON_PrintUnformatted(arr);
            cJSON_Delete(arr);
      enum MHD_Result ret = send_json(conn, 200, js, ctx);
             free(js);
             for (int i = 0; i < count; i++) free(names[i]);
             free(names);
             return ret;
        }

        if (strcmp(ctx->method, "DELETE") == 0 && strncmp(ctx->target_url, "/v1/admin/nodes/", 16) == 0) {
            const char *cn = ctx->target_url + 16;
            if (cn[0]) {
                db_auth_remove(g_db, cn);
                return send_json(conn, 200, "{\"ok\":true}", ctx);
            }
            return send_error(conn, 400, "Missing node name", ctx);
        }

        if (strcmp(ctx->method, "GET") == 0 &&
            strncmp(ctx->target_url, "/v1/admin/config", 16) == 0) {
            const char *key = ctx->target_url + 16;
            if (*key == '/') key++;
            if (key[0]) {
                char val[65536] = {0};
                if (db_config_get(g_db, key, val, sizeof(val)) == ZEP_ERR_OK)
                    return send_json(conn, 200, val, ctx);
                return send_json(conn, 200, "null", ctx);
            }
            cJSON *obj = cJSON_CreateObject();
            sqlite3_stmt *st = NULL;
            sqlite3_prepare_v2(g_db,
                "SELECT key, value FROM config ORDER BY key", -1, &st, NULL);
            if (st) {
                while (sqlite3_step(st) == SQLITE_ROW) {
                    const char *k = (const char *)sqlite3_column_text(st, 0);
                    const char *v = (const char *)sqlite3_column_text(st, 1);
                    if (k) cJSON_AddStringToObject(obj, k, v ? v : "");
                }
                sqlite3_finalize(st);
            }
            char *js = cJSON_PrintUnformatted(obj);
            cJSON_Delete(obj);
            enum MHD_Result ret = send_json(conn, 200, js, ctx);
            free(js);
            return ret;
        }

        if (strcmp(ctx->method, "DELETE") == 0 &&
            strncmp(ctx->target_url, "/v1/admin/config/", 17) == 0) {
            const char *key = ctx->target_url + 17;
            if (key[0]) {
                db_config_set(g_db, key, "");
                return send_json(conn, 200, "{\"ok\":true}", ctx);
            }
            return send_error(conn, 400, "Missing key", ctx);
        }

        /* ── pipe: admin checks if node is connected (WS-only pipe) ── */
        if (strcmp(ctx->method, "GET") == 0 &&
            strcmp(ctx->target_url, "/v1/admin/pipe") == 0) {
            const char *node_param = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "node");
            if (!node_param || !node_param[0])
                return send_error(conn, 400, "Missing node parameter", ctx);
            if (!node_ws_find(node_param))
                return send_error(conn, 503, "Node not connected", ctx);
            return send_json(conn, 200, "{\"ok\":true}", ctx);
        }

        /* ── config set / suspend / resume / promote / rollback / snap ── */
        if (strcmp(ctx->method, "POST") == 0 || strcmp(ctx->method, "PUT") == 0) {
            const char *rest = ctx->target_url + 10;

            if (strncmp(rest, "config/", 7) == 0) {
                const char *key = rest + 7;
                if (!key[0]) return send_error(conn, 400, "Missing key", ctx);
zep_log_debug("config set: key=%s body_len=%zu body=%.*s\n",
                             key, ctx->body_len, (int)ctx->body_len, ctx->body);
                 cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
                 if (json) {
                     cJSON *val = cJSON_GetObjectItem(json, "value");
                     if (val && cJSON_IsString(val)) {
                         err_t ret = db_config_set(g_db, key, val->valuestring);
                         zep_log_debug("config set: db_config_set returned %d\n", ret);
                    }
                 cJSON_Delete(json);
                 } else {
                     zep_log_debug("config set: JSON parse failed\n");
                 }
                return send_json(conn, 200, "{\"ok\":true}", ctx);
            }

            if (strncmp(rest, "suspend", 7) == 0) {
                const char *arg = rest + 7;
                sqlite3_stmt *st = NULL;
                if (*arg == '/') arg++;
                if (strcmp(arg, "master") == 0 || strcmp(arg, "clients") == 0 || arg[0]) {
                    if (strcmp(arg, "master") == 0)
                        sqlite3_prepare_v2(g_db,
                            "UPDATE auth SET suspended = 0 WHERE role = 'master'", -1, &st, NULL);
                    else if (strcmp(arg, "clients") == 0)
                        sqlite3_prepare_v2(g_db,
                            "UPDATE auth SET suspended = 0 WHERE role = 'client'", -1, &st, NULL);
                    else
                        db_set_suspended(g_db, arg, 0);
                    if (st) { sqlite3_step(st); sqlite3_finalize(st); }
                    return send_json(conn, 200, "{\"ok\":true}", ctx);
                }
                sqlite3_prepare_v2(g_db,
                    "UPDATE auth SET suspended = 0", -1, &st, NULL);
                if (st) { sqlite3_step(st); sqlite3_finalize(st); }
                return send_json(conn, 200, "{\"ok\":true}", ctx);
            }

            if (strncmp(rest, "promote/", 8) == 0) {
                const char *new_master = rest + 8;
                if (!new_master[0]) return send_error(conn, 400, "Missing node", ctx);
                char cluster[64] = {0}, old_master_cn[64] = {0};
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(g_db,
                    "SELECT cluster FROM auth WHERE cn = ?", -1, &st, NULL);
                if (st) {
                    sqlite3_bind_text(st, 1, new_master, -1, SQLITE_STATIC);
                    if (sqlite3_step(st) == SQLITE_ROW)
                        snprintf(cluster, sizeof(cluster), "%s",
                                 (const char *)sqlite3_column_text(st, 0));
                    sqlite3_finalize(st);
                }
                if (!cluster[0]) return send_error(conn, 400, "Node not in any cluster", ctx);
                sqlite3_prepare_v2(g_db,
                    "SELECT cn FROM auth WHERE cluster = ? AND role = 'master'",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_text(st, 1, cluster, -1, SQLITE_STATIC);
                    if (sqlite3_step(st) == SQLITE_ROW)
                        snprintf(old_master_cn, sizeof(old_master_cn), "%s",
                                 (const char *)sqlite3_column_text(st, 0));
                    sqlite3_finalize(st);
                }
                if (old_master_cn[0]) {
                    db_set_suspended(g_db, old_master_cn, 1);
                    db_update_role(g_db, old_master_cn, "client");
                }
                db_update_role(g_db, new_master, "master");
                db_set_suspended(g_db, new_master, 0);
                return send_json(conn, 200, "{\"ok\":true}", ctx);
            }

            if (strncmp(rest, "rollback/", 9) == 0) {
                const char *snap = rest + 9;
                if (!snap[0]) return send_error(conn, 400, "Missing snapshot name", ctx);
                char key[256];
                snprintf(key, sizeof(key), "rollback_target");
                db_config_set(g_db, key, snap);
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(g_db,
                    "UPDATE auth SET suspended = 1", -1, &st, NULL);
                if (st) { sqlite3_step(st); sqlite3_finalize(st); }
                return send_json(conn, 200, "{\"ok\":true}", ctx);
            }

            if (strncmp(rest, "snap/", 5) == 0) {
                const char *snap_name = rest + 5;
                if (!snap_name[0]) return send_error(conn, 400, "Missing snapshot name", ctx);
                char key[256];
                snprintf(key, sizeof(key), "manual_snap_%s", snap_name);
                db_config_set(g_db, key, "pending");
                return send_json(conn, 200, "{\"ok\":true}", ctx);
            }

            if (strncmp(rest, "unsnap/", 7) == 0) {
                const char *snap_name = rest + 7;
                if (!snap_name[0]) return send_error(conn, 400, "Missing snapshot name", ctx);
                char key[256];
                snprintf(key, sizeof(key), "manual_snap_%s", snap_name);
                db_config_set(g_db, key, "");
                return send_json(conn, 200, "{\"ok\":true}", ctx);
            }
        }

        return send_error(conn, 404, "Admin endpoint not found", ctx);
    }

    /* ── WebSocket: node persistent connection ── */
    if (strncmp(ctx->target_url, "/v1/ws/node", 11) == 0) {
        const char *cn = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "cn");
        if (!cn || !cn[0]) return send_error(conn, 400, "Missing cn parameter", ctx);
        return ws_handle_node(conn, cn);
    }

    /* ── WebSocket: admin pipe connection ── */
    if (strncmp(ctx->target_url, "/v1/ws/pipe", 11) == 0) {
        const char *node_cn = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "node");
        if (!node_cn || !node_cn[0]) return send_error(conn, 400, "Missing node parameter", ctx);
        return ws_handle_pipe(conn, node_cn);
    }

    /* ── cron sync endpoint ── */
    if (strcmp(ctx->method, "GET") == 0 &&
        strcmp(ctx->target_url, "/v1/cron/sync") == 0) {
        cJSON *tasks = cJSON_CreateArray();

        char role[16] = {0}, cluster_name[64] = {0}, last_err[256] = {0};
        int suspended = 0;
        if (ctx->node[0]) {
            sqlite3_stmt *st = NULL;
            sqlite3_prepare_v2(g_db,
                "SELECT role, cluster, suspended, last_err FROM auth WHERE cn = ?",
                -1, &st, NULL);
            if (st) {
                sqlite3_bind_text(st, 1, ctx->node, -1, SQLITE_STATIC);
                if (sqlite3_step(st) == SQLITE_ROW) {
                    const char *r = (const char *)sqlite3_column_text(st, 0);
                    const char *c = (const char *)sqlite3_column_text(st, 1);
                    const char *le = (const char *)sqlite3_column_text(st, 3);
                    suspended = sqlite3_column_int(st, 2);
                    snprintf(role, sizeof(role), "%s", r ? r : "");
                    snprintf(cluster_name, sizeof(cluster_name), "%s", c ? c : "");
                    if (le && le[0])
                        snprintf(last_err, sizeof(last_err), "%s", le);
                }
                sqlite3_finalize(st);
            }
        }
        int drift = last_err[0] && strncmp(last_err, "rotation drift", 14) == 0;

        time_t now = time(NULL);

        if (drift && cluster_name[0]) {
            sqlite3_stmt *cl = NULL;
            sqlite3_prepare_v2(g_db,
                "UPDATE auth SET last_err = '' WHERE cn = ?1",
                -1, &cl, NULL);
            if (cl) {
                sqlite3_bind_text(cl, 1, ctx->node, -1, SQLITE_STATIC);
                sqlite3_step(cl);
                sqlite3_finalize(cl);
            }
            char cfg_key[128], cluster_json[65536] = {0};
            snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", cluster_name);
            if (db_config_get(g_db, cfg_key, cluster_json,
                              sizeof(cluster_json)) == ZEP_ERR_OK) {
                cJSON *cj = cJSON_Parse(cluster_json);
                if (cj) {
                    cJSON *pools = cJSON_GetObjectItem(cj, "pools");
                    if (pools) {
                        cJSON *pool;
                        cJSON_ArrayForEach(pool, pools) {
                            cJSON *fs;
                            cJSON_ArrayForEach(fs, pool) {
                                cJSON *t = cJSON_CreateObject();
                                cJSON_AddStringToObject(t, "action", "inventory");
                                char cfs[512];
                                snprintf(cfs, sizeof(cfs), "%s/%s",
                                    pool->string, fs->string);
                                cJSON_AddStringToObject(t, "cluster_fs", cfs);
                                cJSON_AddItemToArray(tasks, t);
                            }
                        }
                    }
                    cJSON_Delete(cj);
                }
            }
        }
        /* Retry pass: detect failed snapshots with resume tokens */
        if (g_resume && strcmp(role, "master") == 0 && cluster_name[0]) {
            sqlite3_stmt *rst = NULL;
            if (sqlite3_prepare_v2(g_db,
                "SELECT s.guid, f.push_resume_token, f.fs, s.label "
                "FROM fs f "
                "JOIN snapshots s ON s.guid = f.last_pushed_guid "
                "WHERE s.node = ?1 AND f.push_resume_token != '' "
                "AND f.push_status != 'pushed' "
                "AND s.direction = 'push' "
                "LIMIT 1",
                -1, &rst, NULL) == SQLITE_OK) {
                sqlite3_bind_text(rst, 1, ctx->node, -1, SQLITE_STATIC);
                if (sqlite3_step(rst) == SQLITE_ROW) {
                    const char *guid = (const char *)sqlite3_column_text(rst, 0);
                    const char *rtok = (const char *)sqlite3_column_text(rst, 1);
                    const char *cfs = (const char *)sqlite3_column_text(rst, 2);
                    const char *lbl = (const char *)sqlite3_column_text(rst, 3);
                    if (guid && rtok && cfs && lbl) {
                        cJSON *rt = cJSON_CreateObject();
                        cJSON_AddStringToObject(rt, "action", "push");
                        cJSON_AddStringToObject(rt, "cluster_fs", cfs);
                        cJSON_AddStringToObject(rt, "label", lbl);
                        cJSON_AddStringToObject(rt, "resume_token", rtok);
                        zep_log("cron/sync: retry push for guid=%s label=%s\n", guid, lbl);
                        cJSON_AddItemToArray(tasks, rt);
                    }
                }
                sqlite3_finalize(rst);
            }
        }
        /* fall through to normal cron sync logic below */

        if (suspended) {
            cJSON_AddItemToArray(tasks, cJSON_CreateObject());
            /* empty task list — no work for suspended nodes */
        } else if (strcmp(role, "master") == 0 && cluster_name[0]) {
            char cfg_key[128], cluster_json[65536] = {0};
            snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", cluster_name);
            if (db_config_get(g_db, cfg_key, cluster_json,
                              sizeof(cluster_json)) == ZEP_ERR_OK) {
                cJSON *cj = cJSON_Parse(cluster_json);
                if (cj) {
                    cJSON *pools = cJSON_GetObjectItem(cj, "pools");
                    if (pools) {
                        cJSON *pool;
                        cJSON_ArrayForEach(pool, pools) {
                            cJSON *fs;
                            cJSON_ArrayForEach(fs, pool) {
                                char cluster_fs[512];
                                snprintf(cluster_fs, sizeof(cluster_fs),
                                         "%s/%s", pool->string, fs->string);
                                cJSON *labels = cJSON_GetObjectItem(fs, "labels");
                                if (labels) {
                                    cJSON *lbl;
                                    cJSON_ArrayForEach(lbl, labels) {
                                        int save_count = lbl->valueint;
                                        int interval_sec = 60; /* default: "min" */
                                        const char *ln = lbl->string;
                                        if (ln) {
                                             char *end;
                                             if (strncmp(ln, "min", 3) == 0) {
                                                 long val = strtol(ln + 3, &end, 10);
                                                 interval_sec = (end > ln + 3) ? (int)(val * 60) : 60;
                                             } else if (strncmp(ln, "hour", 4) == 0) {
                                                 long val = strtol(ln + 4, &end, 10);
                                                 interval_sec = (end > ln + 4) ? (int)(val * 3600) : 3600;
                                             } else if (strncmp(ln, "day", 3) == 0) {
                                                 long val = strtol(ln + 3, &end, 10);
                                                 interval_sec = (end > ln + 3) ? (int)(val * 86400) : 86400;
                                             } else if (strncmp(ln, "week", 4) == 0) {
                                                 long val = strtol(ln + 4, &end, 10);
                                                 interval_sec = (end > ln + 4) ? (int)(val * 7 * 86400) : 7 * 86400;
                                             } else if (strncmp(ln, "month", 5) == 0) {
                                                 long val = strtol(ln + 5, &end, 10);
                                                 interval_sec = (end > ln + 5) ? (int)(val * 30 * 86400) : 30 * 86400;
                                             } else if (strncmp(ln, "year", 4) == 0) {
                                                 long val = strtol(ln + 4, &end, 10);
                                                 interval_sec = (end > ln + 4) ? (int)(val * 365 * 86400) : 365 * 86400;
                                             }
                                         }
                                        (void)save_count; /* retention count used by rotation (TBD) */
                                        char cron_key[1020];
                                        snprintf(cron_key, sizeof(cron_key),
                                            "cron_last_%s_%s_%s",
                                            cluster_name, cluster_fs, lbl->string);
                                        char last_str[32] = {0};
                                        db_config_get(g_db, cron_key, last_str,
                                                      sizeof(last_str));
                                        zep_log_debug( "cron/sync: %s = '%s'\n", cron_key, last_str);
                                        time_t last = 0;
                                        if (last_str[0]) {
                                            struct tm tm = {0};
                                            if (strptime(last_str, "%Y-%m-%dT%H:%M:%SZ", &tm))
                                                last = timegm(&tm);
                                        }
                                        if (last == 0 || (now - last) >= interval_sec) {
                                            cJSON *t = cJSON_CreateObject();
                                            cJSON_AddStringToObject(t, "action", "push");
                                            cJSON_AddStringToObject(t, "cluster_fs", cluster_fs);
                                            cJSON_AddStringToObject(t, "label", lbl->string);
                                            if (last == 0)
                                                cJSON_AddTrueToObject(t, "create");
                                            cJSON_AddItemToArray(tasks, t);
                                        }
                                    }
                                }
                            }
                       }
                     }
                     /* Also send inventory tasks for masters */
                     cJSON *pools2 = cJSON_GetObjectItem(cj, "pools");
                     if (pools2) {
                         cJSON *pool2;
                         cJSON_ArrayForEach(pool2, pools2) {
                             cJSON *fs2;
                             cJSON_ArrayForEach(fs2, pool2) {
                                 char cfs[512];
                                 snprintf(cfs, sizeof(cfs), "%s/%s",
                                     pool2->string, fs2->string);
                                 cJSON *inv = cJSON_CreateObject();
                                 cJSON_AddStringToObject(inv, "action", "inventory");
                                 cJSON_AddStringToObject(inv, "cluster_fs", cfs);
                                 cJSON_AddItemToArray(tasks, inv);
                             }
                         }
                     }
                     cJSON_Delete(cj);
                 }
             }
         } else if (strcmp(role, "client") == 0 && cluster_name[0]) {
            char cfg_key[128], cluster_json[65536] = {0};
            snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", cluster_name);
            if (db_config_get(g_db, cfg_key, cluster_json,
                              sizeof(cluster_json)) == ZEP_ERR_OK) {
                cJSON *cj = cJSON_Parse(cluster_json);
                if (cj) {
                    cJSON *pools = cJSON_GetObjectItem(cj, "pools");
                    if (pools) {
                       cJSON *pool;
                        cJSON_ArrayForEach(pool, pools) {
                            cJSON *fs;
                            cJSON_ArrayForEach(fs, pool) {
                                char cluster_fs[512];
                                snprintf(cluster_fs, sizeof(cluster_fs),
                                         "%s/%s", pool->string, fs->string);

                                sqlite3_stmt *st2 = NULL;
                                sqlite3_prepare_v2(g_db,
                                    "SELECT cn FROM auth WHERE cluster = ?1 AND role = 'master' LIMIT 1",
                                    -1, &st2, NULL);
                                char donor_buf[64] = {0};
                                const char *donor = NULL;
                                if (st2) {
                                    sqlite3_bind_text(st2, 1, cluster_name, -1, SQLITE_STATIC);
                                    if (sqlite3_step(st2) == SQLITE_ROW) {
                                        snprintf(donor_buf, sizeof(donor_buf), "%s",
                                                 (const char *)sqlite3_column_text(st2, 0));
                                        donor = donor_buf;
                                    }
                                    sqlite3_finalize(st2);
                                }

                                if (!donor) continue;

                                char client_guid[ZEP_MAX_GUID_LEN] = {0};
                                db_snapshot_latest_guid(g_db, ctx->node,
                                    "pull", client_guid, sizeof(client_guid));
                                zep_log_debug("cron/sync: client=%s cguid=%s\n",
                                    ctx->node, client_guid[0] ? client_guid : "(none)");

                                char *chain_js = db_snapshot_chain_json(g_db,
                                    cluster_name, donor,
                                    client_guid[0] ? client_guid : NULL);
                                if (chain_js) {
                                    cJSON *snap_arr = cJSON_Parse(chain_js);
                                    free(chain_js);
                                    if (snap_arr && cJSON_GetArraySize(snap_arr) > 0) {
                                        cJSON *t = cJSON_CreateObject();
                                        cJSON_AddStringToObject(t, "action", "sync");
                                        cJSON_AddStringToObject(t, "cluster_fs", cluster_fs);
                                        cJSON_AddStringToObject(t, "donor", donor);
                                        cJSON_AddItemToObject(t, "snapshots", snap_arr);
                                        cJSON_AddItemToArray(tasks, t);
                                    } else if (snap_arr) {
                                        cJSON_Delete(snap_arr);
                                    }
                                }
                            }
                        }
                    }
                    cJSON_Delete(cj);
                }
            }
        }

        char *js = cJSON_PrintUnformatted(tasks);
        cJSON_Delete(tasks);
        enum MHD_Result ret = send_json(conn, 200, js, ctx);
        free(js);
        return ret;
    }

    if (strcmp(ctx->method, "POST") == 0 &&
        strcmp(ctx->target_url, "/v1/cron/ack") == 0) {
        zep_log_debug( "cron/ack: body=%.*s\n", (int)ctx->body_len, (const char *)ctx->body);
        cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
        if (json) {
            cJSON *guid = cJSON_GetObjectItem(json, "guid");
            if (guid && cJSON_IsString(guid) && ctx->node[0]) {
                char cl_buf[64] = {0};
                sqlite3_stmt *cs = NULL;
                sqlite3_prepare_v2(g_db, "SELECT cluster FROM auth WHERE cn = ?1", -1, &cs, NULL);
                if (cs) {
                    sqlite3_bind_text(cs, 1, ctx->node, -1, SQLITE_STATIC);
                    if (sqlite3_step(cs) == SQLITE_ROW) {
                        const char *cl = (const char *)sqlite3_column_text(cs, 0);
                        if (cl && cl[0]) snprintf(cl_buf, sizeof(cl_buf), "%s", cl);
                    }
                    sqlite3_finalize(cs);
                }
             db_snapshot_insert(g_db, cl_buf[0] ? cl_buf : "",
                      ctx->node, guid->valuestring, "", "",
                      "", "", 0, 0, "pull", "", "pending", "discovered", "");
            }
            cJSON *lbl = cJSON_GetObjectItem(json, "label");
            cJSON *cfs = cJSON_GetObjectItem(json, "cluster_fs");
            if (lbl && cJSON_IsString(lbl) && cfs && cJSON_IsString(cfs) && ctx->node[0]) {
                char cluster_buf[64] = {0};
                sqlite3_stmt *cs = NULL;
                sqlite3_prepare_v2(g_db, "SELECT cluster FROM auth WHERE cn = ?1", -1, &cs, NULL);
                if (cs) {
                    sqlite3_bind_text(cs, 1, ctx->node, -1, SQLITE_STATIC);
                    if (sqlite3_step(cs) == SQLITE_ROW) {
                        const char *cl = (const char *)sqlite3_column_text(cs, 0);
                        if (cl && cl[0]) snprintf(cluster_buf, sizeof(cluster_buf), "%s", cl);
                    }
                    sqlite3_finalize(cs);
                }
                if (cluster_buf[0]) {
                    char cron_key[1024];
                    snprintf(cron_key, sizeof(cron_key),
                             "cron_last_%s_%s_%s", cluster_buf, cfs->valuestring, lbl->valuestring);
                    char now_str[32];
                    time_t tnow = time(NULL);
                    struct tm tm;
                    gmtime_r(&tnow, &tm);
                    strftime(now_str, sizeof(now_str), "%Y-%m-%dT%H:%M:%SZ", &tm);
                    zep_log_debug( "cron/ack: set %s = %s\n", cron_key, now_str);
                    db_config_set(g_db, cron_key, now_str);
                }
            }
            cJSON_Delete(json);
        }
        return send_json(conn, 200, "{\"ok\":true}", ctx);
    }

    /* ── POST /v1/cron/inventory ── */
    if (strcmp(ctx->method, "POST") == 0 &&
        strcmp(ctx->target_url, "/v1/cron/inventory") == 0) {
        cJSON *json = cJSON_ParseWithLength((const char *)ctx->body,
                                             ctx->body_len);
        if (json && ctx->node[0]) {
            cJSON *cfs = cJSON_GetObjectItem(json, "cluster_fs");
            cJSON *snaps = cJSON_GetObjectItem(json, "snapshots");
            char cl_buf[64] = {0}, role_buf[16] = {0};
            sqlite3_stmt *cs = NULL;
            sqlite3_prepare_v2(g_db,
                "SELECT cluster, role FROM auth WHERE cn = ?1", -1, &cs, NULL);
            if (cs) {
                sqlite3_bind_text(cs, 1, ctx->node, -1, SQLITE_STATIC);
                if (sqlite3_step(cs) == SQLITE_ROW) {
                    const char *cl = (const char *)sqlite3_column_text(cs, 0);
                    const char *rl = (const char *)sqlite3_column_text(cs, 1);
                    if (cl && cl[0])
                        snprintf(cl_buf, sizeof(cl_buf), "%s", cl);
                    if (rl && rl[0])
                        snprintf(role_buf, sizeof(role_buf), "%s", rl);
                }
                sqlite3_finalize(cs);
            }

            if (snaps && cJSON_IsArray(snaps) && cfs &&
                cJSON_IsString(cfs) && cl_buf[0]) {

                /* count GUIDs for parameterized NOT IN clause */
                int guid_count = 0;
                cJSON *sn;
                cJSON_ArrayForEach(sn, snaps) {
                    cJSON *g = cJSON_GetObjectItem(sn, "guid");
                    if (g && cJSON_IsString(g))
                        guid_count++;
                }

                /* build parameterized DELETE with ? placeholders */
                char del_sql[65536];
                int pos = 0;
                pos += snprintf(del_sql + pos, sizeof(del_sql) - (size_t)pos,
                    "DELETE FROM snapshots "
                    "WHERE node = ?1 AND cluster = ?2 "
                    "  AND cluster_fs = ?3");
                for (int i = 0; i < guid_count; i++) {
                    pos += snprintf(del_sql + pos, sizeof(del_sql) - (size_t)pos,
                        " AND guid != ?%d", i + 4);
                }

                sqlite3_stmt *del = NULL;
                sqlite3_prepare_v2(g_db, del_sql, -1, &del, NULL);
                if (del) {
                    sqlite3_bind_text(del, 1, ctx->node, -1, SQLITE_STATIC);
                    sqlite3_bind_text(del, 2, cl_buf, -1, SQLITE_STATIC);
                    sqlite3_bind_text(del, 3, cfs->valuestring, -1, SQLITE_STATIC);
                    int gi = 0;
                    cJSON_ArrayForEach(sn, snaps) {
                        cJSON *g = cJSON_GetObjectItem(sn, "guid");
                        if (!g || !cJSON_IsString(g)) continue;
                        sqlite3_bind_text(del, 4 + gi, g->valuestring, -1, SQLITE_STATIC);
                        gi++;
                    }
                    sqlite3_step(del);
                    sqlite3_finalize(del);
                }

                int has_common = 0;
                cJSON_ArrayForEach(sn, snaps) {
                    cJSON *g = cJSON_GetObjectItem(sn, "guid");
                    cJSON *snap = cJSON_GetObjectItem(sn, "snapshot");
                    cJSON *lbl = cJSON_GetObjectItem(sn, "label");
                    if (!g || !snap || !lbl) continue;

                    db_snapshot_insert(g_db, cl_buf, ctx->node,
                        g->valuestring, "",
                        snap->valuestring, lbl->valuestring,
                        cfs->valuestring, 0, 0,
                        strcmp(role_buf, "master") == 0 ? "push" : "pull",
                        "", "pending", "discovered", "");


                    if (!has_common) {
                        sqlite3_stmt *ck = NULL;
                        sqlite3_prepare_v2(g_db,
                            "SELECT 1 FROM snapshots "
                            "WHERE guid = ?1 AND direction = 'push' AND cluster = ?2",
                            -1, &ck, NULL);
                        if (ck) {
                            sqlite3_bind_text(ck, 1, g->valuestring, -1, SQLITE_STATIC);
                            sqlite3_bind_text(ck, 2, cl_buf, -1, SQLITE_STATIC);
                            has_common = (sqlite3_step(ck) == SQLITE_ROW);
                            sqlite3_finalize(ck);
                        }
                    }
                }

                if (has_common) {
                    zep_log( "inventory: %s/%s has common snapshot, ok\n",
                           ctx->node, cfs->valuestring);
                    sqlite3_stmt *up = NULL;
                    sqlite3_prepare_v2(g_db,
                        "UPDATE auth SET suspended = 0, last_err = '' "
                        "WHERE cn = ?1",
                        -1, &up, NULL);
                    if (up) {
                        sqlite3_bind_text(up, 1, ctx->node, -1, SQLITE_STATIC);
                        sqlite3_step(up);
                        sqlite3_finalize(up);
                    }
                } else {
                    int snap_count = cJSON_GetArraySize(snaps);
                    if (snap_count == 0) {
                        sqlite3_stmt *init_st = NULL;
                        sqlite3_prepare_v2(g_db,
                            "SELECT 1 FROM snapshots "
                            "WHERE cluster = ?1 AND cluster_fs = ?2 "
                            "  AND direction = 'push' AND base_guid = '0' "
                            "LIMIT 1",
                            -1, &init_st, NULL);
                        int has_initial = 0;
                        if (init_st) {
                            sqlite3_bind_text(init_st, 1, cl_buf, -1,
                                              SQLITE_STATIC);
                            sqlite3_bind_text(init_st, 2, cfs->valuestring,
                                              -1, SQLITE_STATIC);
                            has_initial =
                                (sqlite3_step(init_st) == SQLITE_ROW);
                            sqlite3_finalize(init_st);
                        }
                        if (has_initial) {
                            zep_log( "inventory: %s has no snaps for %s, "
                                   "master has initial — full sync next "
                                   "cycle\n",
                                   ctx->node, cfs->valuestring);
                            sqlite3_stmt *up = NULL;
                            sqlite3_prepare_v2(g_db,
                                "UPDATE auth SET suspended = 0, "
                                "last_err = '' WHERE cn = ?1",
                                -1, &up, NULL);
                            if (up) {
                                sqlite3_bind_text(up, 1, ctx->node, -1,
                                                  SQLITE_STATIC);
                                sqlite3_step(up);
                                sqlite3_finalize(up);
                            }
                            db_snapshot_insert(g_db, cl_buf, ctx->node,
                                "", "", "", "", cfs->valuestring,
                                0, 0, "pull", "", "pending", "discovered", "");
                        } else {
                            zep_log( "inventory: %s has no snaps for %s, "
                                   "no initial — waiting for master "
                                   "first push\n",
                                   ctx->node, cfs->valuestring);
                        }
                    } else {
                        zep_log( "inventory: %s has %d snap(s) for %s, "
                               "none match master — foreign data, "
                               "suspending\n",
                               ctx->node, snap_count, cfs->valuestring);
                        sqlite3_stmt *up = NULL;
                        sqlite3_prepare_v2(g_db,
                            "UPDATE auth SET suspended = 1, "
                            "last_err = 'no common snapshots for ' "
                            "|| ?1 WHERE cn = ?2",
                            -1, &up, NULL);
                        if (up) {
                            sqlite3_bind_text(up, 1, cfs->valuestring,
                                              -1, SQLITE_STATIC);
                            sqlite3_bind_text(up, 2, ctx->node, -1,
                                              SQLITE_STATIC);
                            sqlite3_step(up);
                            sqlite3_finalize(up);
                        }
                    }
                }
            }
            cJSON_Delete(json);
        }
        return send_json(conn, 200, "{\"ok\":true}", ctx);
    }

    /* ── GET /v1/snapshots/<guid>/meta ── */
    if (strcmp(ctx->method, "GET") == 0 &&
        strncmp(ctx->target_url, "/v1/snapshots/", 14) == 0) {
        const char *rest = ctx->target_url + 14;
        const char *meta_suf = strstr(rest, "/meta");
        if (meta_suf && meta_suf > rest) {
            char guid[ZEP_MAX_GUID_LEN];
            size_t glen = (size_t)(meta_suf - rest);
            if (glen >= sizeof(guid)) glen = sizeof(guid) - 1;
            memcpy(guid, rest, glen);
            guid[glen] = '\0';

            sqlite3_stmt *st = NULL;
            sqlite3_prepare_v2(g_db,
                "SELECT storage_base FROM snapshots "
                "WHERE guid = ?1 AND direction = 'push' LIMIT 1",
                -1, &st, NULL);
            if (st) {
                sqlite3_bind_text(st, 1, guid, -1, SQLITE_STATIC);
                if (sqlite3_step(st) == SQLITE_ROW) {
                    const char *base = (const char *)sqlite3_column_text(st, 0);
                    if (base && base[0]) {
                        char *fpath = NULL;
                        if (asprintf(&fpath, "%smeta.json",
                                     strncmp(base, "file://", 7) == 0 ? base + 7 : base) < 0) {
                            sqlite3_finalize(st);
                            return send_error(conn, 500, "OOM", ctx);
                        }
                        FILE *f = fopen(fpath, "rb");
                        if (f) {
                            fseek(f, 0, SEEK_END);
                            long sz = ftell(f);
                            fseek(f, 0, SEEK_SET);
                            char *body = malloc((size_t)sz + 1);
                            if (body) {
                                (void)!fread(body, 1, (size_t)sz, f);
                                body[sz] = '\0';
                            }
                            fclose(f);
                            free(fpath);
                            sqlite3_finalize(st);
                            if (body) {
                                enum MHD_Result r = send_json(conn, 200, body, ctx);
                                free(body);
                                return r;
                            }
                            return send_error(conn, 500, "OOM", ctx);
                        }
                        free(fpath);
                    }
                }
                sqlite3_finalize(st);
            }
            return send_error(conn, 404, "Snapshot not found", ctx);
        }
    }




    if (strcmp(ctx->method, "GET") == 0) {
        if (strcmp(ctx->target_url, "/health") == 0) {
            return send_response(conn, 200, "text/plain", "ok", 2, ctx);
        }


        if (ctx->parsed >= 3 && ctx->prefix[0] && ctx->file[0]) {
            char *path = NULL;
            if (strcmp(ctx->file, "meta.json") == 0) {
                if (asprintf(&path, "%s/%s/%s/meta.json",
                             g_storage_root, ctx->node, ctx->prefix) < 0)
                    return send_error(conn, 500, "OOM", ctx);
            } else {
                int part = atoi(ctx->file);
                if (asprintf(&path, "%s/%s/%s/%04d",
                             g_storage_root, ctx->node, ctx->prefix, part) < 0)
                    return send_error(conn, 500, "OOM", ctx);
            }

            size_t flen = 0;
            char *data = read_file(path, &flen);
            free(path);
            if (!data) return send_error(conn, 404, "Not found", ctx);

            const char *ctype = strstr(ctx->file, ".json") ? "application/json"
                                                           : "application/octet-stream";
            struct MHD_Response *resp = MHD_create_response_from_buffer(
                flen, data, MHD_RESPMEM_MUST_FREE);
            if (!resp) { free(data); return MHD_NO; }
            MHD_add_response_header(resp, "Content-Type", ctype);
            enum MHD_Result ret = MHD_queue_response(conn, 200, resp);
            MHD_destroy_response(resp);
            return ret;
        }
        return send_error(conn, 404, "Not found", ctx);
    }

    return send_error(conn, 405, "Method not allowed", ctx);
}

static void sig_handler(int sig) {
    (void)sig;
    if (g_daemon)
        MHD_stop_daemon(g_daemon);
    g_daemon = NULL;
}

static int load_pem(const char *path, char **data) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    *data = malloc((size_t)sz + 1);
    if (!*data) { fclose(f); return -1; }
    size_t r = fread(*data, 1, (size_t)sz, f);
    fclose(f);
    (*data)[r] = '\0';

    if (g_key_password[0] && strstr(*data, "ENCRYPTED")) {
        EVP_PKEY *pkey = NULL;
        BIO *bio = BIO_new_mem_buf(*data, (int)r);
        if (bio) {
            pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, g_key_password);
            BIO_free(bio);
        }
        if (!pkey) {
            zep_log_warn("load_pem: failed to decrypt key from %s\n", path);
            return -1;
        }
        /* Write decrypted key back as PEM */
        BIO *out = BIO_new(BIO_s_mem());
        if (out) {
            PEM_write_bio_PrivateKey_traditional(out, pkey, NULL, NULL, 0, NULL, NULL);
            char *mem_ptr;
            long mem_len = BIO_get_mem_ptr(out, &mem_ptr);
            if (mem_len > 0) {
                free(*data);
                *data = malloc((size_t)mem_len + 1);
                if (*data) {
                    memcpy(*data, mem_ptr, (size_t)mem_len);
                    (*data)[mem_len] = '\0';
                }
            }
            BIO_free(out);
        }
        EVP_PKEY_free(pkey);
        if (!*data) return -1;
    }
    return 0;
}

static void usage_serve(const char *prog) {
    zep_log( "Usage: %s [options]\n", prog);
    zep_log( "  -p, --port PORT       Listen port (default: 8443)\n");
    zep_log( "  -s, --storage DIR     Storage directory (default: /var/lib/zep-air)\n");
    zep_log( "  -c, --cert FILE       TLS server certificate (PEM)\n");
    zep_log( "  -k, --key FILE        TLS server private key (PEM)\n");
    zep_log( "  -a, --ca FILE         CA certificate for client auth (optional)\n");
    zep_log( "  -D, --db FILE         SQLite database path (default: /var/lib/zep-air/zep-air.db)\n");
    zep_log( "  -S, --setup           Run setup mode: store CA + server + admin certs in DB, then exit\n");
    zep_log( "  -A, --admin-cert      Admin client certificate for setup mode (PEM)\n");
    zep_log( "  -P, --password PASS   Password for encrypted private keys\n");
    zep_log( "  -N, --no-tls          Disable TLS (plain HTTP, for WS debugging)\n");
    zep_log( "  --logging LEVELS      Comma-separated log levels: DEBUG,INFO,WARN,ERROR,AUDIT (default: INFO,WARN,ERROR)\n");
    zep_log( "  -v                    Verbose (all levels, backwards compat)\n");
    zep_log( "  -h, --help            This help\n");
}

int serve_main(int argc, char *argv[]) {
    static struct option long_opts[] = {
        {"port",    required_argument, 0, 'p'},
        {"storage", required_argument, 0, 's'},
        {"cert",    required_argument, 0, 'c'},
        {"key",     required_argument, 0, 'k'},
        {"ca",      required_argument, 0, 'a'},
        {"db",         required_argument, 0, 'D'},
        {"admin-cert", required_argument, 0, 'A'},
        {"password",  required_argument, 0, 'P'},
        {"no-tls",    no_argument,       0, 'N'},
        {"setup",      no_argument,       0, 'S'},
        {"verbose", no_argument,       0, 'v'},
        {"logging", required_argument, 0, 'L'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:s:c:k:a:A:D:P:SvL:L:", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': g_port = atoi(optarg); break;
            case 's': snprintf(g_storage_root, sizeof(g_storage_root), "%s", optarg); break;
            case 'c': snprintf(g_cert_path, sizeof(g_cert_path), "%s", optarg); break;
            case 'k': snprintf(g_key_path, sizeof(g_key_path), "%s", optarg); break;
            case 'a': snprintf(g_ca_path, sizeof(g_ca_path), "%s", optarg); break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'A': snprintf(g_admin_cert_path, sizeof(g_admin_cert_path), "%s", optarg); break;
            case 'P': snprintf(g_key_password, sizeof(g_key_password), "%s", optarg); break;
case 'v': g_logging = LOG_LEVEL_ALL; break;  /* -v for backwards compat: show all */
             case 'S': g_setup_mode = 1; break;
             case 'N': g_no_tls = 1; break;
            case 'L':
                g_logging = zep_log_parse_mask(optarg);
                if (g_logging == 0) {
                    zep_log("error: invalid logging levels '%s'\n", optarg);
                    usage_serve(argv[0]);; return 1;
                }
                break;
            case 'h': usage_serve(argv[0]);; return 0;
            default:  usage_serve(argv[0]);; return 1;
        }
    }

    char *cert_pem = NULL, *key_pem = NULL, *ca_pem = NULL;

    if (g_setup_mode) {
        if (!g_cert_path[0] || !g_ca_path[0] || !g_admin_cert_path[0]) {
            zep_log( "error: --setup requires --cert, --key, --ca, and --admin-cert\n");
            return 1;
        }
        if (load_pem(g_cert_path, &cert_pem) != 0) return 1;
        if (load_pem(g_key_path, &key_pem) != 0) { free(cert_pem); return 1; }
        if (load_pem(g_ca_path, &ca_pem) != 0) { free(cert_pem); free(key_pem); return 1; }

        if (db_open(g_db_path, &g_db) != ZEP_ERR_OK) {
            free(cert_pem); free(key_pem); free(ca_pem);
            return 1;
        }
        db_init_tables(g_db);

        X509 *cert = NULL;
        FILE *cf = fopen(g_cert_path, "r");
        if (cf) { cert = PEM_read_X509(cf, NULL, NULL, NULL); fclose(cf); }

        X509 *ca = NULL;
        FILE *caf = fopen(g_ca_path, "r");
        if (caf) { ca = PEM_read_X509(caf, NULL, NULL, NULL); fclose(caf); }

        if (ca) {
            char *fp = auth_cert_fingerprint(ca);
            if (fp) {
                char *cn = auth_extract_cn(ca);
                db_cert_store(g_db, cn ? cn : "Zep-Air testing", fp, ca_pem, "server", "", "");
                printf("Setup: stored CA  CN=%s  fingerprint=%s\n", cn ? cn : "?", fp);
                free(cn); free(fp);
            }
            X509_free(ca);
        }

        if (cert) {
            char *fp = auth_cert_fingerprint(cert);
            if (fp) {
                char *cn = auth_extract_cn(cert);
                db_cert_store(g_db, cn ? cn : "server", fp, cert_pem, "server", "", "");
                printf("Setup: stored server cert  CN=%s  fingerprint=%s\n", cn ? cn : "?", fp);
                free(cn); free(fp);
            }
            X509_free(cert);
        }

        X509 *admin = NULL;
        FILE *af = fopen(g_admin_cert_path, "r");
        char *admin_pem = NULL;
        if (af) {
            admin = PEM_read_X509(af, NULL, NULL, NULL);
            fclose(af);
            af = fopen(g_admin_cert_path, "r");
            if (af) {
                fseek(af, 0, SEEK_END);
                long sz = ftell(af);
                fseek(af, 0, SEEK_SET);
                admin_pem = malloc((size_t)sz + 1);
                if (admin_pem) {
                    size_t r = fread(admin_pem, 1, (size_t)sz, af);
                    admin_pem[r] = '\0';
                }
                fclose(af);
            }
        }
        if (!admin) {
            zep_log( "error: failed to load admin cert from %s\n", g_admin_cert_path);
            db_close(g_db);
            free(cert_pem); free(key_pem); free(ca_pem);
            return 1;
        }
        char *admin_fp = auth_cert_fingerprint(admin);
        if (admin_fp) {
            char *admin_cn = auth_extract_cn(admin);
                db_cert_store(g_db, admin_cn ? admin_cn : "admin", admin_fp,
                              admin_pem ? admin_pem : "none", "admin", "", "");
            printf("Setup: stored admin cert  CN=%s  fingerprint=%s\n",
                   admin_cn ? admin_cn : "?", admin_fp);
            free(admin_cn); free(admin_fp);
        }
        free(admin_pem);
        X509_free(admin);

        printf("Setup complete.\n");
        db_close(g_db);
        free(cert_pem); free(key_pem); free(ca_pem);
        return 0;
    }

    if (!g_no_tls) {
        if (!g_cert_path[0] || !g_key_path[0]) {
            zep_log( "error: --cert and --key are required (or use --no-tls)\n");
            return 1;
        }

        if (load_pem(g_cert_path, &cert_pem) != 0) return 1;
        if (load_pem(g_key_path, &key_pem) != 0) { free(cert_pem); return 1; }
        if (g_ca_path[0] && load_pem(g_ca_path, &ca_pem) != 0) {
            free(cert_pem); free(key_pem); return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (db_open(g_db_path, &g_db) != ZEP_ERR_OK) {
        free(cert_pem); free(key_pem); free(ca_pem);
        return 1;
    }
    db_init_tables(g_db);
    zep_log_init(g_db_path);

    {
        char buf[32];
        if (db_config_get(g_db, "resume", buf, sizeof(buf)) == ZEP_ERR_OK)
            g_resume = atoi(buf);
    }
    {
        char buf[512];
        if (db_config_get(g_db, "debug_inject_pull_cmd", buf, sizeof(buf)) == ZEP_ERR_OK)
            snprintf(g_debug_inject_pull_cmd, sizeof(g_debug_inject_pull_cmd), "%s", buf);
        if (db_config_get(g_db, "push_unzip_cmd", buf, sizeof(buf)) == ZEP_ERR_OK)
            snprintf(g_push_unzip_cmd, sizeof(g_push_unzip_cmd), "%s", buf);
        if (db_config_get(g_db, "pull_zip_cmd", buf, sizeof(buf)) == ZEP_ERR_OK)
            snprintf(g_pull_zip_cmd, sizeof(g_pull_zip_cmd), "%s", buf);
    }

    if (!g_no_tls && g_ca_path[0]) {
        X509_STORE *ca_store = NULL;
        if (auth_load_ca_cert(g_ca_path, &ca_store) == ZEP_ERR_OK) {
            char *ca_fp = NULL;
            X509 *ca = NULL;
            FILE *caf = fopen(g_ca_path, "r");
            if (caf) {
                ca = PEM_read_X509(caf, NULL, NULL, NULL);
                fclose(caf);
                if (ca) {
                    ca_fp = auth_cert_fingerprint(ca);
                    X509_free(ca);
                    if (ca_fp) {
                        db_cert_store(g_db, "Zep-Air testing", ca_fp, "CA", "server", "", "");
                        free(ca_fp);
                    }
                }
            }
            X509_STORE_free(ca_store);
        }
    }

    unsigned int flags = MHD_USE_INTERNAL_POLLING_THREAD | MHD_ALLOW_UPGRADE;
    if (!g_no_tls) flags |= MHD_USE_TLS;

    if (g_no_tls) {
        g_daemon = MHD_start_daemon(flags, (unsigned int)g_port, NULL, NULL,
                                     &handle_request, NULL,
                                     MHD_OPTION_NOTIFY_COMPLETED, &completed_cb, NULL,
                                     MHD_OPTION_END);
    } else {
        g_daemon = MHD_start_daemon(flags, (unsigned int)g_port, NULL, NULL,
                                     &handle_request, NULL,
                                     MHD_OPTION_NOTIFY_COMPLETED, &completed_cb, NULL,
                                     MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                     MHD_OPTION_HTTPS_MEM_KEY, key_pem,
                                     MHD_OPTION_HTTPS_MEM_TRUST, ca_pem,
                                     MHD_OPTION_END);
    }

    free(cert_pem);
    free(key_pem);
    free(ca_pem);

    if (!g_daemon) {
        zep_log( "Failed to start HTTPS server\n");
        return 1;
    }

    printf("zep-air-serve listening on port %d (%s)\n", g_port, g_no_tls ? "plain" : "TLS");
    printf("Storage root: %s\n", g_storage_root);
    if (g_ca_path[0]) printf("Client certificate authentication enabled\n");

    while (g_daemon) {
        sleep(1);
    }

    printf("\nServer stopped.\n");
    node_ws_shutdown();
    db_close(g_db);
   ;
    return 0;
}

int main(int argc, char *argv[]) {
    return serve_main(argc, argv);
}

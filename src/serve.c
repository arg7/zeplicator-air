/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "common.h"
#include "storage.h"
#include "db.h"
#include "zstream.h"
#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
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
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

static char g_storage_root[ZEP_MAX_PATH] = "/var/lib/zep-air";
static char g_db_path[ZEP_MAX_PATH]       = "/var/lib/zep-air/zep-air.db";
static int  g_port = 8443;
static char g_cert_path[ZEP_MAX_PATH] = "";
static char g_key_path[ZEP_MAX_PATH] = "";
static char g_ca_path[ZEP_MAX_PATH] = "";
static char g_admin_cert_path[ZEP_MAX_PATH] = "";
static char g_key_password[128] = "";
static int  g_verbose = 0;
static int  g_setup_mode = 0;
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
    /* Pipe bridge fields */
    int pipe_active;
    int pipe_admin_sock;
    struct MHD_UpgradeResponseHandle *pipe_admin_urh;
    pthread_mutex_t pipe_lock;
    /* Thread for WS loop */
    pthread_t thread;
    int thread_running;
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
                                      const void *body, size_t body_len) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        body_len, (void *)body, MHD_RESPMEM_MUST_COPY);
    if (!resp) return MHD_NO;
    if (ctype) MHD_add_response_header(resp, "Content-Type", ctype);
    enum MHD_Result ret = MHD_queue_response(conn, (unsigned int)status, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result send_error(struct MHD_Connection *conn, int status, const char *msg) {
    return send_response(conn, status, "text/plain", msg, strlen(msg));
}

static enum MHD_Result send_json(struct MHD_Connection *conn, int status, const char *json) {
    return send_response(conn, status, "application/json", json, strlen(json));
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

static void verify_snapshot(const char *cluster_key, const char *prefix) {
    snapshot_meta_t meta;
    memset(&meta, 0, sizeof(meta));

    err_t ret = storage_read_meta(g_storage_root, cluster_key, prefix, &meta);
    if (ret != ZEP_ERR_OK) return;

    char *dir_path = NULL;
    if (asprintf(&dir_path, "%s/%s/%s", g_storage_root, cluster_key, prefix) < 0) {
        storage_meta_free(&meta);
        return;
    }

    int found = 0;
    for (int i = 0; i < meta.blob_count; i++) {
        char *blob_path = NULL;
        if (asprintf(&blob_path, "%s/%04d", dir_path, i) < 0) {
            free(dir_path);
            storage_meta_free(&meta);
            return;
        }
        if (access(blob_path, R_OK) == 0) found++;
        free(blob_path);
    }

    if (found < meta.blob_count) {
        free(dir_path);
        storage_meta_free(&meta);
        return;
    }

    char *zst_path = NULL, *dec_path = NULL;
    if (asprintf(&zst_path, "/tmp/zep-verify-%s.zst", prefix) < 0 ||
        asprintf(&dec_path, "/tmp/zep-verify-%s.dec", prefix) < 0) {
        free(dir_path);
        free(zst_path);
        storage_meta_free(&meta);
        return;
    }

    FILE *zst = fopen(zst_path, "wb");
    if (!zst) {
        free(dir_path); free(zst_path); free(dec_path);
        storage_meta_free(&meta); return;
    }

    for (int i = 0; i < meta.blob_count; i++) {
        void *data = NULL;
        size_t len = 0;
        if (storage_read_blob(g_storage_root, cluster_key, prefix, i, &data, &len) != ZEP_ERR_OK) {
            fclose(zst); unlink(zst_path);
            free(dir_path); free(zst_path); free(dec_path);
            storage_meta_free(&meta); return;
        }
        fwrite(data, 1, len, zst);
        free(data);
    }
    fclose(zst);

    char *cmd = NULL;
    if (asprintf(&cmd, "zstd -d '%s' -o '%s' -f 2>/dev/null", zst_path, dec_path) < 0) {
        unlink(zst_path);
        free(dir_path); free(zst_path); free(dec_path);
        storage_meta_free(&meta);
        return;
    }
    int rc = system(cmd);
    free(cmd);
    if (rc != 0) {
        unlink(zst_path);
        free(dir_path); free(zst_path); free(dec_path);
        storage_meta_free(&meta);
        return;
    }
    unlink(zst_path);
    free(zst_path);
    free(dir_path);

    FILE *dfp = fopen(dec_path, "rb");
    if (!dfp) { unlink(dec_path); free(dec_path); storage_meta_free(&meta); return; }
    fseek(dfp, 0, SEEK_END);
    long dlen = ftell(dfp);
    fseek(dfp, 0, SEEK_SET);
    unsigned char *decomp = malloc((size_t)dlen);
    if (!decomp) { fclose(dfp); unlink(dec_path); free(dec_path); storage_meta_free(&meta); return; }
    if (fread(decomp, 1, (size_t)dlen, dfp) != (size_t)dlen) { fclose(dfp); unlink(dec_path); free(dec_path); free(decomp); storage_meta_free(&meta); return; }
    fclose(dfp);
    unlink(dec_path);
    free(dec_path);

    char toguid[ZEP_MAX_GUID_LEN] = {0};
    char fromguid[ZEP_MAX_GUID_LEN] = {0};
    ret = zstream_parse(decomp, (size_t)dlen, toguid, sizeof(toguid),
                        fromguid, sizeof(fromguid));
    free(decomp);

    if (ret != ZEP_ERR_OK) {
        fprintf(stderr, "verify: zstream_parse failed for %s/%s\n",
                cluster_key, prefix);
        storage_meta_free(&meta);
        return;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) {
        storage_meta_free(&meta);
        return;
    }
    db_init_tables(db);

    const char *pusher = meta.host[0] ? meta.host : cluster_key;
    db_chain_insert(db, cluster_key, toguid, fromguid, meta.snapshot, pusher);

    if (meta.label[0]) {
        const char *at = strchr(meta.snapshot, '@');
        if (at) {
            size_t fs_len = (size_t)(at - meta.snapshot);
            char fs_buf[256];
            if (fs_len >= sizeof(fs_buf)) fs_len = sizeof(fs_buf) - 1;
            memcpy(fs_buf, meta.snapshot, fs_len);
            fs_buf[fs_len] = '\0';
            char cron_key[1024];
            snprintf(cron_key, sizeof(cron_key),
                     "cron_last_%s_%s_%s", cluster_key, fs_buf, meta.label);
            char now_str[32];
            time_t tnow = time(NULL);
            struct tm tm;
            gmtime_r(&tnow, &tm);
            strftime(now_str, sizeof(now_str), "%Y-%m-%dT%H:%M:%SZ", &tm);
            db_config_set(db, cron_key, now_str);
        }
    }

    if (g_verbose) {
        printf("verify: cluster=%s toguid=%s fromguid=%s snap=%s\n",
               cluster_key, toguid, fromguid, meta.snapshot);
    }

    db_close(db);
    storage_meta_free(&meta);
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
    /* Remove existing connection for this node */
    struct node_ws *prev = NULL, *nw = g_node_ws;
    while (nw) {
        if (strcmp(nw->cn, cn) == 0) {
            if (prev) prev->next = nw->next;
            else g_node_ws = nw->next;
            pthread_mutex_unlock(&nw->lock);
            pthread_mutex_destroy(&nw->lock);
            free(nw);
            break;
        }
        prev = nw;
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
    pthread_mutex_init(&nw->lock, NULL);
    nw->next = g_node_ws;
    g_node_ws = nw;
    if (g_verbose)
        fprintf(stderr, "ws: node %s registered sock=%d\n", cn, sock);
    pthread_mutex_unlock(&g_node_ws_lock);
    return nw;
}

static void node_ws_unregister(const char *cn) {
    pthread_mutex_lock(&g_node_ws_lock);
    struct node_ws *prev = NULL, *nw = g_node_ws;
    while (nw) {
        if (strcmp(nw->cn, cn) == 0) {
            if (prev) prev->next = nw->next;
            else g_node_ws = nw->next;
            if (g_verbose)
                fprintf(stderr, "ws: node %s unregistered\n", cn);
            pthread_mutex_destroy(&nw->lock);
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
    memcpy(buf + header_len, payload, payload_len);
    return header_len + payload_len;
}

#define WS_SUBCHUNK (128 * 1024)

static ssize_t ws_send_frame(int sock, unsigned char opcode,
                              const unsigned char *payload, size_t payload_len) {
    unsigned char *frame = malloc(payload_len + 14);
    if (!frame) return -1;
    size_t flen = ws_build_frame(frame, payload_len + 14, opcode, payload, payload_len);
    if (flen == 0) {
        fprintf(stderr, "ws: build_frame failed for opcode=0x%02x len=%zu\n", opcode, payload_len);
        free(frame);
        return -1;
    }
    ssize_t sent = 0;
    while ((size_t)sent < flen) {
        ssize_t n = send(sock, frame + sent, flen - (size_t)sent, MSG_NOSIGNAL);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
            if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
                fprintf(stderr, "ws: send timeout\n");
                free(frame);
                return -1;
            }
            continue;
        }
        if (n <= 0) {
            fprintf(stderr, "ws: send failed: n=%zd errno=%d (%s)\n",
                    n, errno, strerror(errno));
            free(frame);
            return -1;
        }
        sent += n;
    }
    free(frame);
    return (ssize_t)flen;
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
    int sock;
    struct MHD_UpgradeResponseHandle *urh;
};

static void *node_ws_thread(void *arg) {
    struct node_ws_thread_ctx *ctx = (struct node_ws_thread_ctx *)arg;
    struct node_ws *nw = ctx->nw;
    int sock = ctx->sock;
    struct MHD_UpgradeResponseHandle *urh = ctx->urh;
    free(ctx);

    ws_make_blocking(sock);
    unsigned char *buf = malloc(WS_SUBCHUNK);
    unsigned char *out = malloc(WS_SUBCHUNK);
    if (!buf || !out) { free(buf); free(out); MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE); return NULL; }

    fprintf(stderr, "ws: node %s listening sock=%d\n", nw->cn, sock);
    fflush(stderr);

    time_t last_ping = time(NULL);
    FILE *cmd_fp = NULL;
    char cmd_errfile[256] = {0};
    int in_pipe = 0;
    int pipe_recv_mode = 0;

    for (;;) {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        int sel = select(sock + 1, &rfds, NULL, NULL, &tv);
        if (sel > 0) {
            fprintf(stderr, "ws: node %s select returned %d\n", nw->cn, sel);
            fflush(stderr);
        }

        time_t now = time(NULL);
        if (now - last_ping >= 60) {
            ws_send_frame(sock, WS_OP_PING, NULL, 0);
            last_ping = now;
        }

        if (sel > 0 && FD_ISSET(sock, &rfds)) {
            ssize_t n = recv(sock, buf, WS_SUBCHUNK, 0);
            if (g_verbose)
                fprintf(stderr, "ws: node %s recv n=%zd\n", nw->cn, n);
            if (n <= 0) break;

            ssize_t plen = ws_parse_frame(buf, (size_t)n, out, WS_SUBCHUNK, &buf[0]);
            unsigned char opcode = buf[0] & 0x0F;
            if (g_verbose)
                fprintf(stderr, "ws: node %s parse plen=%zd opcode=0x%02x\n", nw->cn, plen, opcode);
            if (plen < 0) break;

            if (opcode == WS_OP_CLOSE) break;
            if (opcode == WS_OP_PING) {
                ws_send_frame(sock, WS_OP_PONG, out, (size_t)plen);
                continue;
            }
            if (opcode == WS_OP_PONG) {
                nw->last_pong = time(NULL);
                continue;
            }

            /* Handle pipe task or data */
            if (opcode == WS_OP_TEXT && !in_pipe && plen > 0) {
                out[plen] = '\0';
                cJSON *task = cJSON_Parse((char *)out);
                if (task) {
                    cJSON *action = cJSON_GetObjectItem(task, "action");
                    cJSON *command = cJSON_GetObjectItem(task, "command");
                    cJSON *dir = cJSON_GetObjectItem(task, "direction");
                    if (action && command && cJSON_IsString(action) && cJSON_IsString(command)) {
                        if (strcmp(action->valuestring, "pipe") == 0) {
                            int recv_mode = (dir && cJSON_IsString(dir) && strcmp(dir->valuestring, "recv") == 0);
                            char resolved[4096];
                            snprintf(resolved, sizeof(resolved), "%s", command->valuestring);
                            char errfile[] = "/tmp/zep-pipe-err-XXXXXX";
                            int err_fd = mkstemp(errfile);
                            char full_cmd[4096 + 256];
                            if (err_fd >= 0) {
                                snprintf(full_cmd, sizeof(full_cmd), "(%s) 2>%s", resolved, errfile);
                                snprintf(cmd_errfile, sizeof(cmd_errfile), "%s", errfile);
                            } else {
                                snprintf(full_cmd, sizeof(full_cmd), "%s", resolved);
                                cmd_errfile[0] = '\0';
                            }
                            if (recv_mode) {
                                /* Admin sends data → node stdin */
                                cmd_fp = popen(full_cmd, "w");
                            } else {
                                /* Node stdout → admin receives data */
                                cmd_fp = popen(full_cmd, "r");
                            }
                            if (cmd_fp) {
                                in_pipe = 1;
                                pipe_recv_mode = recv_mode;
                                if (g_verbose)
                                    fprintf(stderr, "ws: node %s pipe started (%s): %s\n", nw->cn, recv_mode ? "recv" : "send", resolved);
                            } else {
                                fprintf(stderr, "ws: node %s popen failed: %s\n", nw->cn, resolved);
                            }
                        }
                    }
                    cJSON_Delete(task);
                }
            } else if (in_pipe && cmd_fp && (opcode == WS_OP_BIN || opcode == WS_OP_TEXT) && plen > 0) {
                if (pipe_recv_mode) {
                    /* Write to command stdin */
                    fwrite(out, 1, (size_t)plen, cmd_fp);
                    fflush(cmd_fp);
                }
            }

            /* Read from command stdout and send to admin (send mode) */
            if (in_pipe && cmd_fp && !pipe_recv_mode) {
                size_t nread = fread(out, 1, WS_SUBCHUNK, cmd_fp);
                if (nread > 0) {
                    ws_send_frame(sock, WS_OP_BIN, out, nread);
                }
            }
        }

        if (time(NULL) - nw->last_pong > 180) break;
    }

    if (g_verbose)
        fprintf(stderr, "ws: node %s disconnected\n", nw->cn);

    if (cmd_fp) {
        pclose(cmd_fp);
        if (cmd_errfile[0]) unlink(cmd_errfile);
    }

    free(buf); free(out);

    /* Clear pipe state */
    pthread_mutex_lock(&nw->lock);
    nw->pipe_active = 0;
    nw->pipe_admin_sock = -1;
    nw->pipe_admin_urh = NULL;
    pthread_mutex_unlock(&nw->lock);

    node_ws_unregister(nw->cn);
    MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
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

    /* Spawn thread for WS loop */
    struct node_ws_thread_ctx *ctx = malloc(sizeof(*ctx));
    ctx->nw = nw;
    ctx->sock = sock;
    ctx->urh = urh;
    pthread_create(&nw->thread, NULL, node_ws_thread, ctx);
    pthread_detach(nw->thread);
    nw->thread_running = 1;
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
        fprintf(stderr, "ws: pipe request for %s — not connected\n", node_cn);
        fflush(stderr);
        MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
        return;
    }
    fprintf(stderr, "ws: pipe found node %s sock=%d\n", node_cn, nw->sock);
    fflush(stderr);

    /* Signal node thread that pipe is starting */
    pthread_mutex_lock(&nw->lock);
    nw->pipe_active = 1;
    nw->pipe_admin_sock = sock;
    nw->pipe_admin_urh = urh;
    pthread_mutex_unlock(&nw->lock);

    /* Send task JSON to node */
    const char *direction = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "direction");
    const char *command = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "command");
    if (command) {
        char *task_json = NULL;
        if (asprintf(&task_json, "{\"action\":\"pipe\",\"command\":\"%s\",\"direction\":\"%s\"}",
                     command, direction ? direction : "send") > 0) {
            if (g_verbose)
                fprintf(stderr, "ws: sending task to node: %s\n", task_json);
            ws_send_frame(nw->sock, WS_OP_TEXT, (unsigned char *)task_json, strlen(task_json));
            free(task_json);
        }
    }

    /* Node thread will handle the pipe - this handler just waits for completion */
    /* The node thread will close both sockets when done */
    /* We need to wait here for the pipe to complete */
    for (;;) {
        pthread_mutex_lock(&nw->lock);
        int done = !nw->pipe_active;
        pthread_mutex_unlock(&nw->lock);
        if (done) break;
        usleep(50000);
    }

    if (g_verbose)
        fprintf(stderr, "ws: pipe complete for node %s\n", node_cn);
}

static enum MHD_Result ws_handle_node(struct MHD_Connection *conn,
                                       const char *cn) {
    if (g_verbose)
        fprintf(stderr, "ws: node upgrade request for %s\n", cn);

    const char *upgrade = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Upgrade");
    const char *ws_key = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Key");
    const char *ws_ver = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Version");

    if (!upgrade || strcasecmp(upgrade, "websocket") != 0)
        return send_error(conn, 400, "Upgrade: websocket required");
    if (!ws_key || !ws_key[0])
        return send_error(conn, 400, "Sec-WebSocket-Key required");
    if (!ws_ver || strcmp(ws_ver, "13") != 0)
        return send_error(conn, 400, "Sec-WebSocket-Version: 13 required");

    char accept[128];
    ws_build_accept(ws_key, accept, sizeof(accept));

    struct MHD_Response *resp = MHD_create_response_for_upgrade(
        &ws_node_upgrade_handler, (void *)cn);
    if (!resp) return send_error(conn, 500, "Failed to create upgrade response");

    MHD_add_response_header(resp, "Upgrade", "websocket");
    MHD_add_response_header(resp, "Connection", "Upgrade");
    MHD_add_response_header(resp, "Sec-WebSocket-Accept", accept);

    enum MHD_Result ret = MHD_queue_response(conn, 101, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result ws_handle_pipe(struct MHD_Connection *conn,
                                       const char *node_cn) {
    fprintf(stderr, "ws: pipe upgrade request for node %s\n", node_cn);
    fflush(stderr);

    const char *upgrade = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Upgrade");
    const char *ws_key = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Key");
    const char *ws_ver = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Version");

    if (!upgrade || strcasecmp(upgrade, "websocket") != 0)
        return send_error(conn, 400, "Upgrade: websocket required");
    if (!ws_key || !ws_key[0])
        return send_error(conn, 400, "Sec-WebSocket-Key required");
    if (!ws_ver || strcmp(ws_ver, "13") != 0)
        return send_error(conn, 400, "Sec-WebSocket-Version: 13 required");

    if (!node_ws_find(node_cn))
        return send_error(conn, 503, "Node not connected");

    char accept[128];
    ws_build_accept(ws_key, accept, sizeof(accept));

    struct MHD_Response *resp = MHD_create_response_for_upgrade(
        &ws_pipe_upgrade_handler, (void *)node_cn);
    if (!resp) return send_error(conn, 500, "Failed to create upgrade response");

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
            return send_response(conn, 200, "text/plain", "ok", 2);
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

                if (g_verbose)
                    fprintf(stderr, "auth: fp=%s role=%s url=%s\n", fp_hex, role, url);

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

                if (strncmp(ctx->target_url, "/v1/admin", 9) == 0 &&
                    strcmp(role, "admin") != 0) {
                    return send_error(conn, 403, "Admin access required");
                }
            }
        }

        ctx->authed = 1;
        return MHD_YES;
    }

    if (!ctx->authed) {
        return send_error(conn, 401, "Client certificate required");
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
                if (!json) return send_error(conn, 400, "Invalid JSON");
                cJSON *name = cJSON_GetObjectItem(json, "name");
                if (!name || !cJSON_IsString(name) || !name->valuestring[0]) {
                    cJSON_Delete(json);
                    return send_error(conn, 400, "Missing cluster name");
                }
                char cfg_key[128];
                snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", name->valuestring);
                char *js = cJSON_PrintUnformatted(json);
                cJSON_Delete(json);
                db_config_set(g_db, cfg_key, js);
                if (g_verbose) fprintf(stderr, "cluster set: key=%s len=%zu\n", cfg_key, strlen(js));
                free(js);
                return send_json(conn, 200, "{\"ok\":true}");
            }

            if (strcmp(ctx->method, "GET") == 0) {
                if (strncmp(ctx->target_url, "/v1/admin/clusters/", 19) == 0) {
                    const char *cn = ctx->target_url + 19;
                    if (cn[0]) {
                        char cfg_key[128], val[65536] = {0};
                        snprintf(cfg_key, sizeof(cfg_key), "cluster_%s", cn);
                        if (db_config_get(g_db, cfg_key, val, sizeof(val)) == ZEP_ERR_OK)
                            return send_json(conn, 200, val);
                    }
                    return send_error(conn, 404, "Not found");
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
                enum MHD_Result ret = send_json(conn, 200, js);
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
                    return send_json(conn, 200, "{\"ok\":true}");
                }
                return send_error(conn, 400, "Missing cluster name");
            }

            return send_error(conn, 404, "Cluster endpoint not found");
        }

        if (strcmp(ctx->method, "POST") == 0) {
            if (strcmp(ctx->target_url, "/v1/admin/nodes") == 0) {
                cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
                if (!json) return send_error(conn, 400, "Invalid JSON");
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
                            return send_error(conn, 400, "Cluster not found");
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
                return ok ? send_json(conn, 200, "{\"ok\":true}")
                          : send_error(conn, 400, "Bad request");
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
            enum MHD_Result ret = send_json(conn, 200, js);
            free(js);
            storage_free_list(names, count);
            return ret;
        }

        if (strcmp(ctx->method, "DELETE") == 0 && strncmp(ctx->target_url, "/v1/admin/nodes/", 16) == 0) {
            const char *cn = ctx->target_url + 16;
            if (cn[0]) {
                db_auth_remove(g_db, cn);
                return send_json(conn, 200, "{\"ok\":true}");
            }
            return send_error(conn, 400, "Missing node name");
        }

        if (strcmp(ctx->method, "GET") == 0 &&
            strncmp(ctx->target_url, "/v1/admin/config", 16) == 0) {
            const char *key = ctx->target_url + 16;
            if (*key == '/') key++;
            if (key[0]) {
                char val[65536] = {0};
                if (db_config_get(g_db, key, val, sizeof(val)) == ZEP_ERR_OK)
                    return send_json(conn, 200, val);
                return send_json(conn, 200, "null");
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
            enum MHD_Result ret = send_json(conn, 200, js);
            free(js);
            return ret;
        }

        if (strcmp(ctx->method, "DELETE") == 0 &&
            strncmp(ctx->target_url, "/v1/admin/config/", 17) == 0) {
            const char *key = ctx->target_url + 17;
            if (key[0]) {
                db_config_set(g_db, key, "");
                return send_json(conn, 200, "{\"ok\":true}");
            }
            return send_error(conn, 400, "Missing key");
        }

        /* ── pipe: admin checks if node is connected (WS-only pipe) ── */
        if (strcmp(ctx->method, "GET") == 0 &&
            strcmp(ctx->target_url, "/v1/admin/pipe") == 0) {
            const char *node_param = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "node");
            if (!node_param || !node_param[0])
                return send_error(conn, 400, "Missing node parameter");
            if (!node_ws_find(node_param))
                return send_error(conn, 503, "Node not connected");
            return send_json(conn, 200, "{\"ok\":true}");
        }

        /* ── config set / suspend / resume / promote / rollback / snap ── */
        if (strcmp(ctx->method, "POST") == 0 || strcmp(ctx->method, "PUT") == 0) {
            const char *rest = ctx->target_url + 10;

            if (strncmp(rest, "config/", 7) == 0) {
                const char *key = rest + 7;
                if (!key[0]) return send_error(conn, 400, "Missing key");
                if (g_verbose)
                    fprintf(stderr, "config set: key=%s body_len=%zu body=%.*s\n",
                            key, ctx->body_len, (int)ctx->body_len, ctx->body);
                cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
                if (json) {
                    cJSON *val = cJSON_GetObjectItem(json, "value");
                    if (val && cJSON_IsString(val)) {
                        err_t ret = db_config_set(g_db, key, val->valuestring);
                        if (g_verbose)
                            fprintf(stderr, "config set: db_config_set returned %d\n", ret);
                    }
                    cJSON_Delete(json);
                } else if (g_verbose) {
                    fprintf(stderr, "config set: JSON parse failed\n");
                }
                return send_json(conn, 200, "{\"ok\":true}");
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
                    return send_json(conn, 200, "{\"ok\":true}");
                }
                sqlite3_prepare_v2(g_db,
                    "UPDATE auth SET suspended = 0", -1, &st, NULL);
                if (st) { sqlite3_step(st); sqlite3_finalize(st); }
                return send_json(conn, 200, "{\"ok\":true}");
            }

            if (strncmp(rest, "promote/", 8) == 0) {
                const char *new_master = rest + 8;
                if (!new_master[0]) return send_error(conn, 400, "Missing node");
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
                if (!cluster[0]) return send_error(conn, 400, "Node not in any cluster");
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
                return send_json(conn, 200, "{\"ok\":true}");
            }

            if (strncmp(rest, "rollback/", 9) == 0) {
                const char *snap = rest + 9;
                if (!snap[0]) return send_error(conn, 400, "Missing snapshot name");
                char key[256];
                snprintf(key, sizeof(key), "rollback_target");
                db_config_set(g_db, key, snap);
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(g_db,
                    "UPDATE auth SET suspended = 1", -1, &st, NULL);
                if (st) { sqlite3_step(st); sqlite3_finalize(st); }
                return send_json(conn, 200, "{\"ok\":true}");
            }

            if (strncmp(rest, "snap/", 5) == 0) {
                const char *snap_name = rest + 5;
                if (!snap_name[0]) return send_error(conn, 400, "Missing snapshot name");
                char key[256];
                snprintf(key, sizeof(key), "manual_snap_%s", snap_name);
                db_config_set(g_db, key, "pending");
                return send_json(conn, 200, "{\"ok\":true}");
            }

            if (strncmp(rest, "unsnap/", 7) == 0) {
                const char *snap_name = rest + 7;
                if (!snap_name[0]) return send_error(conn, 400, "Missing snapshot name");
                char key[256];
                snprintf(key, sizeof(key), "manual_snap_%s", snap_name);
                db_config_set(g_db, key, "");
                return send_json(conn, 200, "{\"ok\":true}");
            }
        }

        return send_error(conn, 404, "Admin endpoint not found");
    }

    /* ── WebSocket: node persistent connection ── */
    if (strncmp(ctx->target_url, "/v1/ws/node", 11) == 0) {
        const char *cn = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "cn");
        if (!cn || !cn[0]) return send_error(conn, 400, "Missing cn parameter");
        return ws_handle_node(conn, cn);
    }

    /* ── WebSocket: admin pipe connection ── */
    if (strncmp(ctx->target_url, "/v1/ws/pipe", 11) == 0) {
        const char *node_cn = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "node");
        if (!node_cn || !node_cn[0]) return send_error(conn, 400, "Missing node parameter");
        return ws_handle_pipe(conn, node_cn);
    }

    /* ── cron sync endpoint ── */
    if (strcmp(ctx->method, "GET") == 0 &&
        strcmp(ctx->target_url, "/v1/cron/sync") == 0) {
        cJSON *tasks = cJSON_CreateArray();

        char role[16] = {0}, cluster_name[64] = {0};
        int suspended = 0;
        if (ctx->node[0]) {
            sqlite3_stmt *st = NULL;
            sqlite3_prepare_v2(g_db,
                "SELECT role, cluster, suspended FROM auth WHERE cn = ?",
                -1, &st, NULL);
            if (st) {
                sqlite3_bind_text(st, 1, ctx->node, -1, SQLITE_STATIC);
                if (sqlite3_step(st) == SQLITE_ROW) {
                    const char *r = (const char *)sqlite3_column_text(st, 0);
                    const char *c = (const char *)sqlite3_column_text(st, 1);
                    suspended = sqlite3_column_int(st, 2);
                    snprintf(role, sizeof(role), "%s", r ? r : "");
                    snprintf(cluster_name, sizeof(cluster_name), "%s", c ? c : "");
                }
                sqlite3_finalize(st);
            }
        }

        time_t now = time(NULL);

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
                                        int interval_min = lbl->valueint;
                                        char cron_key[1024];
                                        snprintf(cron_key, sizeof(cron_key),
                                            "cron_last_%s_%s_%s",
                                            cluster_name, cluster_fs, lbl->string);
                                        char last_str[32] = {0};
                                        db_config_get(g_db, cron_key, last_str,
                                                      sizeof(last_str));
                                        time_t last = 0;
                                        if (last_str[0]) {
                                            struct tm tm = {0};
                                            if (strptime(last_str, "%Y-%m-%dT%H:%M:%SZ", &tm))
                                                last = timegm(&tm);
                                        }
                                        if (last == 0 || (now - last) >= interval_min * 60) {
                                            cJSON *t = cJSON_CreateObject();
                                            cJSON_AddStringToObject(t, "action", "push");
                                            cJSON_AddStringToObject(t, "cluster_fs", cluster_fs);
                                            cJSON_AddStringToObject(t, "label", lbl->string);
                                            cJSON_AddItemToArray(tasks, t);
                                        }
                                    }
                                }
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
                                const char *donor = NULL;
                                char donor_buf[64] = {0};
                                if (st2) {
                                    sqlite3_bind_text(st2, 1, cluster_name, -1, SQLITE_STATIC);
                                    if (sqlite3_step(st2) == SQLITE_ROW) {
                                        snprintf(donor_buf, sizeof(donor_buf), "%s",
                                                 (const char *)sqlite3_column_text(st2, 0));
                                        donor = donor_buf;
                                    }
                                    sqlite3_finalize(st2);
                                }
                                cJSON *t = cJSON_CreateObject();
                                cJSON_AddStringToObject(t, "action", "sync");
                                cJSON_AddStringToObject(t, "cluster_fs", cluster_fs);
                                if (donor) cJSON_AddStringToObject(t, "donor", donor);
                                cJSON_AddItemToArray(tasks, t);
                            }
                        }
                    }
                    cJSON_Delete(cj);
                }
            }
        }

        char *js = cJSON_PrintUnformatted(tasks);
        cJSON_Delete(tasks);
        enum MHD_Result ret = send_json(conn, 200, js);
        free(js);
        return ret;
    }

    if (strcmp(ctx->method, "POST") == 0 &&
        strcmp(ctx->target_url, "/v1/cron/ack") == 0) {
        cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
        if (json) {
            cJSON *guid = cJSON_GetObjectItem(json, "guid");
            if (guid && cJSON_IsString(guid) && ctx->node[0])
                db_ack_guid(g_db, ctx->node, guid->valuestring);
            cJSON_Delete(json);
        }
        return send_json(conn, 200, "{\"ok\":true}");
    }

    if (strcmp(ctx->method, "GET") == 0 &&
        strncmp(ctx->target_url, "/v1/cron/protected", 18) == 0) {
        cJSON *arr = cJSON_CreateArray();
        const char *cluster_param = strchr(ctx->target_url + 18, '=');
        if (!cluster_param) cluster_param = "";
        else cluster_param++;

        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(g_db,
            "SELECT last_ack_guid FROM auth WHERE cluster = ?1 AND role = 'client'",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_text(st, 1, cluster_param, -1, SQLITE_STATIC);
            while (sqlite3_step(st) == SQLITE_ROW) {
                const char *guid = (const char *)sqlite3_column_text(st, 0);
                if (guid && guid[0])
                    cJSON_AddItemToArray(arr, cJSON_CreateString(guid));
            }
            sqlite3_finalize(st);
        }
        /* also protect latest guid in chain */
        sqlite3_prepare_v2(g_db,
            "SELECT toguid FROM cluster_chain WHERE cluster_key = ?1 "
            "ORDER BY rowid DESC LIMIT 1",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_text(st, 1, cluster_param, -1, SQLITE_STATIC);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *guid = (const char *)sqlite3_column_text(st, 0);
                if (guid && guid[0])
                    cJSON_AddItemToArray(arr, cJSON_CreateString(guid));
            }
            sqlite3_finalize(st);
        }

        char *js = cJSON_PrintUnformatted(arr);
        cJSON_Delete(arr);
        enum MHD_Result ret = send_json(conn, 200, js);
        free(js);
        return ret;
    }

    if (strcmp(ctx->method, "PUT") == 0) {
        if (ctx->parsed >= 3 && ctx->prefix[0] && ctx->file[0]) {
            storage_ensure_dir(g_storage_root, ctx->node, ctx->prefix);

            if (strcmp(ctx->file, "meta") == 0) {
                char *path = NULL;
                if (asprintf(&path, "%s/%s/%s/meta.json",
                             g_storage_root, ctx->node, ctx->prefix) < 0)
                    return send_error(conn, 500, "OOM");
                FILE *f = fopen(path, "wb");
                if (f) {
                    fwrite(ctx->body, 1, ctx->body_len, f);
                    fclose(f);
                    if (g_verbose) printf("PUT meta: %s/%s (%zu bytes)\n",
                                          ctx->prefix, "meta.json", ctx->body_len);
                    free(path);
                    verify_snapshot(ctx->node, ctx->prefix);
                    return send_json(conn, 200, "{\"ok\":true}");
                }
                free(path);
                return send_error(conn, 500, "Failed to write meta.json");
            }

            int part = atoi(ctx->file);
            char *path = NULL;
            if (asprintf(&path, "%s/%s/%s/%04d",
                         g_storage_root, ctx->node, ctx->prefix, part) < 0)
                return send_error(conn, 500, "OOM");
            FILE *f = fopen(path, "wb");
            if (f) {
                fwrite(ctx->body, 1, ctx->body_len, f);
                fclose(f);
                if (g_verbose) printf("PUT blob: %s/%04d (%zu bytes)\n",
                                       ctx->prefix, part, ctx->body_len);
                free(path);
                verify_snapshot(ctx->node, ctx->prefix);
                return send_json(conn, 200, "{\"ok\":true}");
            }
            free(path);
            return send_error(conn, 500, "Failed to write blob");
        }
        return send_error(conn, 400, "Bad request");
    }

    if (strcmp(ctx->method, "GET") == 0) {
        if (strcmp(ctx->target_url, "/health") == 0) {
            return send_response(conn, 200, "text/plain", "ok", 2);
        }

        if (ctx->parsed == 1 && ctx->node[0] && !ctx->prefix[0]) {
            char **prefixes = NULL;
            int count = 0;
            storage_list_prefixes(g_storage_root, ctx->node, 0, &prefixes, &count);

            size_t cap = 4096;
            char *json = malloc(cap);
            if (!json) return MHD_NO;
            size_t pos = 0;
            pos += (size_t)snprintf(json + pos, cap - pos, "[\n");
            for (int i = 0; i < count; i++) {
                pos += (size_t)snprintf(json + pos, cap - pos,
                    "%s  \"%s\"%s\n",
                    (i > 0) ? ",\n" : "", prefixes[i], "");
            }
            pos += (size_t)snprintf(json + pos, cap - pos, "]\n");
            storage_free_list(prefixes, count);

            enum MHD_Result ret = send_json(conn, 200, json);
            free(json);
            return ret;
        }

        if (ctx->parsed >= 3 && ctx->prefix[0] && ctx->file[0]) {
            char *path = NULL;
            if (strcmp(ctx->file, "meta.json") == 0) {
                if (asprintf(&path, "%s/%s/%s/meta.json",
                             g_storage_root, ctx->node, ctx->prefix) < 0)
                    return send_error(conn, 500, "OOM");
            } else {
                int part = atoi(ctx->file);
                if (asprintf(&path, "%s/%s/%s/%04d",
                             g_storage_root, ctx->node, ctx->prefix, part) < 0)
                    return send_error(conn, 500, "OOM");
            }

            size_t flen = 0;
            char *data = read_file(path, &flen);
            free(path);
            if (!data) return send_error(conn, 404, "Not found");

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
        return send_error(conn, 404, "Not found");
    }

    return send_error(conn, 405, "Method not allowed");
}

static void sig_handler(int sig) {
    (void)sig;
    if (g_daemon) MHD_stop_daemon(g_daemon);
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
        char tmp_in[256], tmp_out[256], cmd[2048];
        snprintf(tmp_in, sizeof(tmp_in), "/tmp/zep-key-in-%d", getpid());
        snprintf(tmp_out, sizeof(tmp_out), "/tmp/zep-key-out-%d", getpid());
        FILE *tf = fopen(tmp_in, "w");
        if (tf) { fwrite(*data, 1, r, tf); fclose(tf); }
        snprintf(cmd, sizeof(cmd),
            "openssl rsa -in '%s' -passin pass:'%s' -out '%s' 2>/dev/null",
            tmp_in, g_key_password, tmp_out);
        if (system(cmd) == 0) {
            FILE *of = fopen(tmp_out, "r");
            if (of) {
                fseek(of, 0, SEEK_END);
                long osz = ftell(of);
                fseek(of, 0, SEEK_SET);
                free(*data);
                *data = malloc((size_t)osz + 1);
                if (*data) {
                    size_t or_ = fread(*data, 1, (size_t)osz, of);
                    (*data)[or_] = '\0';
                }
                fclose(of);
            }
        }
        unlink(tmp_in); unlink(tmp_out);
    }
    return 0;
}

static void usage_serve(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "  -p, --port PORT       Listen port (default: 8443)\n");
    fprintf(stderr, "  -s, --storage DIR     Storage directory (default: /var/lib/zep-air)\n");
    fprintf(stderr, "  -c, --cert FILE       TLS server certificate (PEM)\n");
    fprintf(stderr, "  -k, --key FILE        TLS server private key (PEM)\n");
    fprintf(stderr, "  -a, --ca FILE         CA certificate for client auth (optional)\n");
    fprintf(stderr, "  -D, --db FILE         SQLite database path (default: /var/lib/zep-air/zep-air.db)\n");
    fprintf(stderr, "  -S, --setup           Run setup mode: store CA + server + admin certs in DB, then exit\n");
    fprintf(stderr, "  -A, --admin-cert      Admin client certificate for setup mode (PEM)\n");
    fprintf(stderr, "  -P, --password PASS   Password for encrypted private keys\n");
    fprintf(stderr, "  -v, --verbose         Verbose output\n");
    fprintf(stderr, "  -h, --help            This help\n");
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
        {"setup",      no_argument,       0, 'S'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:s:c:k:a:A:D:P:Svh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': g_port = atoi(optarg); break;
            case 's': snprintf(g_storage_root, sizeof(g_storage_root), "%s", optarg); break;
            case 'c': snprintf(g_cert_path, sizeof(g_cert_path), "%s", optarg); break;
            case 'k': snprintf(g_key_path, sizeof(g_key_path), "%s", optarg); break;
            case 'a': snprintf(g_ca_path, sizeof(g_ca_path), "%s", optarg); break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'A': snprintf(g_admin_cert_path, sizeof(g_admin_cert_path), "%s", optarg); break;
            case 'P': snprintf(g_key_password, sizeof(g_key_password), "%s", optarg); break;
            case 'S': g_setup_mode = 1; break;
            case 'v': g_verbose = 1; break;
            case 'h': usage_serve(argv[0]); return 0;
            default:  usage_serve(argv[0]); return 1;
        }
    }

    char *cert_pem = NULL, *key_pem = NULL, *ca_pem = NULL;

    if (g_setup_mode) {
        if (!g_cert_path[0] || !g_ca_path[0] || !g_admin_cert_path[0]) {
            fprintf(stderr, "error: --setup requires --cert, --key, --ca, and --admin-cert\n");
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
            fprintf(stderr, "error: failed to load admin cert from %s\n", g_admin_cert_path);
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

    if (!g_cert_path[0] || !g_key_path[0]) {
        fprintf(stderr, "error: --cert and --key are required\n");
        return 1;
    }

    if (load_pem(g_cert_path, &cert_pem) != 0) return 1;
    if (load_pem(g_key_path, &key_pem) != 0) { free(cert_pem); return 1; }
    if (g_ca_path[0] && load_pem(g_ca_path, &ca_pem) != 0) {
        free(cert_pem); free(key_pem); return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (db_open(g_db_path, &g_db) != ZEP_ERR_OK) {
        free(cert_pem); free(key_pem); free(ca_pem);
        return 1;
    }
    db_init_tables(g_db);

    if (g_ca_path[0]) {
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

    unsigned int flags = MHD_USE_TLS | MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD | MHD_ALLOW_UPGRADE;

    g_daemon = MHD_start_daemon(flags, (unsigned int)g_port, NULL, NULL,
                                 &handle_request, NULL,
                                 MHD_OPTION_NOTIFY_COMPLETED, &completed_cb, NULL,
                                 MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                 MHD_OPTION_HTTPS_MEM_KEY, key_pem,
                                 MHD_OPTION_HTTPS_MEM_TRUST, ca_pem,
                                 MHD_OPTION_END);

    free(cert_pem);
    free(key_pem);
    free(ca_pem);

    if (!g_daemon) {
        fprintf(stderr, "Failed to start HTTPS server\n");
        return 1;
    }

    printf("zep-air-serve listening on port %d (TLS)\n", g_port);
    printf("Storage root: %s\n", g_storage_root);
    if (g_ca_path[0]) printf("Client certificate authentication enabled\n");

    while (g_daemon) {
        sleep(1);
    }

    printf("\nServer stopped.\n");
    db_close(g_db);
    return 0;
}

int main(int argc, char *argv[]) {
    return serve_main(argc, argv);
}

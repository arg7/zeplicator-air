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

struct pipe_chunk {
    struct pipe_chunk *next;
    unsigned char *data;
    size_t len;
    int part;
};

struct pipe_session {
    struct pipe_session *next;
    char token[33];
    char src_node[64];
    struct pipe_chunk *chunks_head;
    struct pipe_chunk *chunks_tail;
    int chunk_count;
    int done;
    int direction;
    int producer_done;
    uint64_t estimated_size;
    time_t created;
    time_t last_activity;
};

#define ZEP_PIPE_MAX_CHUNKS 2
static struct pipe_session *g_pipe_sessions = NULL;

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
    fread(decomp, 1, (size_t)dlen, dfp);
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

static void pipe_generate_token(char token[33]) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand((unsigned int)(tv.tv_sec ^ tv.tv_usec ^ getpid()));
    for (int i = 0; i < 32; i++)
        token[i] = (char)("0123456789abcdef"[rand() % 16]);
    token[32] = '\0';
}

static struct pipe_session *pipe_session_find(const char *token) {
    for (struct pipe_session *ps = g_pipe_sessions; ps; ps = ps->next)
        if (strcmp(ps->token, token) == 0) return ps;
    return NULL;
}

static struct pipe_session *pipe_session_create(const char *src_node,
                                                int direction) {
    struct pipe_session *ps = calloc(1, sizeof(*ps));
    if (!ps) return NULL;
    pipe_generate_token(ps->token);
    snprintf(ps->src_node, sizeof(ps->src_node), "%s", src_node);
    ps->direction = direction;
    ps->created = time(NULL);
    ps->last_activity = ps->created;
    ps->next = g_pipe_sessions;
    g_pipe_sessions = ps;
    return ps;
}

static int pipe_session_add_chunk(struct pipe_session *ps, int part,
                                   const void *data, size_t len) {
    if (ps->chunk_count >= ZEP_PIPE_MAX_CHUNKS) return -1;
    struct pipe_chunk *pc = calloc(1, sizeof(*pc));
    if (!pc) return -1;
    pc->data = malloc(len);
    if (!pc->data) { free(pc); return -1; }
    memcpy(pc->data, data, len);
    pc->len = len;
    pc->part = part;
    if (ps->chunks_tail) {
        ps->chunks_tail->next = pc;
        ps->chunks_tail = pc;
    } else {
        ps->chunks_head = ps->chunks_tail = pc;
    }
    ps->chunk_count++;
    ps->last_activity = time(NULL);
    return 0;
}

static struct pipe_chunk *pipe_session_pop_chunk(struct pipe_session *ps) {
    if (!ps->chunks_head) return NULL;
    struct pipe_chunk *pc = ps->chunks_head;
    ps->chunks_head = pc->next;
    if (!ps->chunks_head) ps->chunks_tail = NULL;
    ps->chunk_count--;
    ps->last_activity = time(NULL);
    return pc;
}

static void pipe_session_destroy(struct pipe_session *ps) {
    if (!ps) return;
    struct pipe_chunk *pc = ps->chunks_head;
    while (pc) {
        struct pipe_chunk *next = pc->next;
        free(pc->data);
        free(pc);
        pc = next;
    }
    free(ps);
}

static void pipe_sessions_cleanup(void) {
    time_t now = time(NULL);
    struct pipe_session *prev = NULL, *ps = g_pipe_sessions;
    while (ps) {
        struct pipe_session *next = ps->next;
        if ((now - ps->last_activity) > 300) {
            if (!ps->done && ps->src_node[0])
                db_set_suspended(g_db, ps->src_node, 0);
            char pipe_key[128];
            snprintf(pipe_key, sizeof(pipe_key), "pipe_task_%s", ps->src_node);
            db_config_set(g_db, pipe_key, "");
            if (prev) prev->next = next;
            else g_pipe_sessions = next;
            pipe_session_destroy(ps);
        } else {
            prev = ps;
        }
        ps = next;
    }
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
                                if (n >= sizeof(ctx->node)) n = sizeof(ctx->node) - 1;
                                memcpy(ctx->node, cn_start, n);
                                ctx->node[n] = '\0';
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

        /* ── pipe: admin sends chunk (recv direction) ── */
        if (strcmp(ctx->method, "PUT") == 0 &&
            strncmp(ctx->target_url, "/v1/admin/pipe/", 15) == 0) {
            const char *token_start = ctx->target_url + 15;
            const char *slash2 = strchr(token_start, '/');
            if (slash2 && strncmp(slash2 + 1, "chunk/", 6) == 0) {
                char token[64] = {0};
                size_t tok_len = (size_t)(slash2 - token_start);
                if (tok_len >= sizeof(token)) tok_len = sizeof(token) - 1;
                memcpy(token, token_start, tok_len);
                int part = atoi(slash2 + 7);
                pipe_sessions_cleanup();
                struct pipe_session *ps = pipe_session_find(token);
                if (!ps) return send_error(conn, 404, "Session not found or expired");
                if (ps->direction != 1)
                    return send_error(conn, 400, "Not a recv session");
                if (pipe_session_add_chunk(ps, part, ctx->body, ctx->body_len) != 0)
                    return send_error(conn, 503, "Pipe queue full, retry");
                return send_json(conn, 200, "{\"ok\":true}");
            }
        }

        /* ── pipe: admin initiates pipe session ── */
        if (strcmp(ctx->method, "POST") == 0 &&
            strcmp(ctx->target_url, "/v1/admin/pipe") == 0) {
            cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
            if (!json) return send_error(conn, 400, "Invalid JSON");

            cJSON *cmd_j    = cJSON_GetObjectItem(json, "command");
            cJSON *dir_j    = cJSON_GetObjectItem(json, "direction");
            cJSON *node_j   = cJSON_GetObjectItem(json, "node");
            cJSON *comp_j   = cJSON_GetObjectItem(json, "compress");
            cJSON *buf_j    = cJSON_GetObjectItem(json, "buffer");

            if (!cmd_j || !cJSON_IsString(cmd_j) || !cmd_j->valuestring[0]) {
                cJSON_Delete(json);
                return send_error(conn, 400, "Missing command");
            }
            const char *command = cmd_j->valuestring;
            int direction = (dir_j && cJSON_IsString(dir_j) &&
                             strcmp(dir_j->valuestring, "recv") == 0) ? 1 : 0;
            int compress = (comp_j && cJSON_IsTrue(comp_j)) ? 1 : 0;
            int buffer   = (buf_j  && cJSON_IsTrue(buf_j))  ? 1 : 0;

            char allow_list[256] = "zfs";
            db_config_get(g_db, "pipe_restrict", allow_list, sizeof(allow_list));
            if (allow_list[0] && strcmp(allow_list, "*") != 0) {
                char cmd_prefix[64] = {0};
                const char *sp = strchr(command, ' ');
                size_t plen = sp ? (size_t)(sp - command) : strlen(command);
                if (plen >= sizeof(cmd_prefix)) plen = sizeof(cmd_prefix) - 1;
                memcpy(cmd_prefix, command, plen);
                int is_ok = 0;
                char *list_copy = strdup(allow_list);
                if (list_copy) {
                    char *save = NULL;
                    char *tok = strtok_r(list_copy, ",", &save);
                    while (tok) {
                        while (*tok == ' ') tok++;
                        if (strcmp(tok, cmd_prefix) == 0) { is_ok = 1; break; }
                        tok = strtok_r(NULL, ",", &save);
                    }
                    free(list_copy);
                }
                if (!is_ok) {
                    cJSON_Delete(json);
                    return send_error(conn, 403, "Command not allowed by pipe_restrict");
                }
            }

            char src_node[64] = {0};
            if (node_j && cJSON_IsString(node_j) && node_j->valuestring[0]) {
                snprintf(src_node, sizeof(src_node), "%s", node_j->valuestring);
            } else {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(g_db,
                    "SELECT cn FROM auth WHERE role = 'client' AND suspended = 0 "
                    "LIMIT 1", -1, &st, NULL);
                if (st) {
                    if (sqlite3_step(st) == SQLITE_ROW)
                        snprintf(src_node, sizeof(src_node), "%s",
                                 (const char *)sqlite3_column_text(st, 0));
                    sqlite3_finalize(st);
                }
                if (!src_node[0]) {
                    sqlite3_prepare_v2(g_db,
                        "SELECT cn FROM auth WHERE role = 'master' AND suspended = 0 "
                        "LIMIT 1", -1, &st, NULL);
                    if (st) {
                        if (sqlite3_step(st) == SQLITE_ROW)
                            snprintf(src_node, sizeof(src_node), "%s",
                                     (const char *)sqlite3_column_text(st, 0));
                        sqlite3_finalize(st);
                    }
                }
            }

            if (!src_node[0]) {
                cJSON_Delete(json);
                return send_error(conn, 500, "No available node");
            }

            int suspended_now = 0;
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(g_db,
                    "SELECT suspended FROM auth WHERE cn = ?", -1, &st, NULL);
                if (st) {
                    sqlite3_bind_text(st, 1, src_node, -1, SQLITE_STATIC);
                    if (sqlite3_step(st) == SQLITE_ROW)
                        suspended_now = sqlite3_column_int(st, 0);
                    sqlite3_finalize(st);
                }
            }
            if (suspended_now) {
                cJSON_Delete(json);
                return send_error(conn, 409, "Target node already suspended");
            }

            db_set_suspended(g_db, src_node, 1);
            if (g_verbose)
                fprintf(stderr, "pipe: suspended node %s (dir=%s, cmd=%s)\n",
                        src_node, direction ? "recv" : "send", command);

            struct pipe_session *ps = pipe_session_create(src_node, direction);
            if (!ps) {
                db_set_suspended(g_db, src_node, 0);
                cJSON_Delete(json);
                return send_error(conn, 500, "Failed to create session");
            }

            const char *dir_str = direction ? "recv" : "send";
            cJSON *task_j = cJSON_CreateObject();
            cJSON_AddStringToObject(task_j, "action", "pipe");
            cJSON_AddStringToObject(task_j, "session", ps->token);
            cJSON_AddStringToObject(task_j, "direction", dir_str);
            cJSON_AddStringToObject(task_j, "command", command);
            if (compress) cJSON_AddBoolToObject(task_j, "compress", 1);
            if (buffer)   cJSON_AddBoolToObject(task_j, "buffer", 1);
            char *task_str = cJSON_PrintUnformatted(task_j);
            cJSON_Delete(task_j);
            cJSON_Delete(json);

            char pipe_key[128];
            snprintf(pipe_key, sizeof(pipe_key), "pipe_task_%s", src_node);
            db_config_set(g_db, pipe_key, task_str);
            free(task_str);

            char *resp = NULL;
            if (asprintf(&resp, "{\"session\":\"%s\"}", ps->token) < 0)
                return send_error(conn, 500, "OOM");
            enum MHD_Result ret = send_json(conn, 200, resp);
            free(resp);
            return ret;
        }

        /* ── pipe: admin signals done (recv direction) ── */
        if (strcmp(ctx->method, "POST") == 0 &&
            strncmp(ctx->target_url, "/v1/admin/pipe/", 15) == 0) {
            const char *token_start = ctx->target_url + 15;
            const char *slash2 = strchr(token_start, '/');
            if (slash2 && strncmp(slash2 + 1, "done", 4) == 0) {
                char token[64] = {0};
                size_t tok_len = (size_t)(slash2 - token_start);
                if (tok_len >= sizeof(token)) tok_len = sizeof(token) - 1;
                memcpy(token, token_start, tok_len);
                pipe_sessions_cleanup();
                struct pipe_session *ps = pipe_session_find(token);
                if (!ps) return send_error(conn, 404, "Session not found or expired");
                if (ps->direction != 1)
                    return send_error(conn, 400, "Not a recv session");
                ps->producer_done = 1;
                if (g_verbose)
                    fprintf(stderr, "pipe: session %s producer done\n", token);
                return send_json(conn, 200, "{\"ok\":true}");
            }
        }

        /* ── admin pipe poll ── */
        if (strcmp(ctx->method, "GET") == 0 &&
            strncmp(ctx->target_url, "/v1/admin/pipe/", 15) == 0) {
            const char *token = ctx->target_url + 15;
            if (!token[0]) return send_error(conn, 400, "Missing session token");
            pipe_sessions_cleanup();
            struct pipe_session *ps = pipe_session_find(token);
            if (!ps) return send_error(conn, 404, "Session not found or expired");
            struct pipe_chunk *pc = pipe_session_pop_chunk(ps);
            if (!pc) {
                if (ps->done) {
                    struct MHD_Response *resp = MHD_create_response_from_buffer(
                        0, "", MHD_RESPMEM_PERSISTENT);
                    MHD_add_response_header(resp, "X-Pipe-Done", "1");
                    MHD_add_response_header(resp, "Content-Type", "application/octet-stream");
                    enum MHD_Result ret = MHD_queue_response(conn, 200, resp);
                    MHD_destroy_response(resp);
                    return ret;
                }
                return send_error(conn, 204, "No chunks yet");
            }
            char size_buf[32];
            snprintf(size_buf, sizeof(size_buf), "%llu", (unsigned long long)ps->estimated_size);
            struct MHD_Response *resp = MHD_create_response_from_buffer(
                pc->len, pc->data, MHD_RESPMEM_MUST_FREE);
            free(pc);
            MHD_add_response_header(resp, "Content-Type", "application/octet-stream");
            MHD_add_response_header(resp, "X-Pipe-Chunk", "1");
            if (ps->estimated_size > 0)
                MHD_add_response_header(resp, "X-Pipe-Size", size_buf);
            enum MHD_Result ret = MHD_queue_response(conn, 200, resp);
            MHD_destroy_response(resp);
            return ret;
        }

        /* ── config set / suspend / resume / promote / rollback / snap ── */
        if (strcmp(ctx->method, "POST") == 0 || strcmp(ctx->method, "PUT") == 0) {
            const char *rest = ctx->target_url + 10;

            if (strncmp(rest, "config/", 7) == 0) {
                const char *key = rest + 7;
                if (!key[0]) return send_error(conn, 400, "Missing key");
                cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
                if (json) {
                    cJSON *val = cJSON_GetObjectItem(json, "value");
                    if (val && cJSON_IsString(val))
                        db_config_set(g_db, key, val->valuestring);
                    cJSON_Delete(json);
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

    /* ── pipe node endpoints (mTLS authenticated, not admin) ── */
    if (strncmp(ctx->target_url, "/v1/pipe/", 9) == 0) {
        const char *rest = ctx->target_url + 9;
        char token[64] = {0};
        const char *slash = strchr(rest, '/');
        if (slash) {
            size_t tok_len = (size_t)(slash - rest);
            if (tok_len >= sizeof(token)) tok_len = sizeof(token) - 1;
            memcpy(token, rest, tok_len);
        } else {
            snprintf(token, sizeof(token), "%s", rest);
        }

        struct pipe_session *ps = pipe_session_find(token);
        if (!ps) return send_error(conn, 404, "Session not found");

        /* GET /v1/pipe/<s> — node downloads next chunk (recv direction) */
        if (strcmp(ctx->method, "GET") == 0 && !slash) {
            if (ps->direction != 1)
                return send_error(conn, 400, "Not a recv session");
            struct pipe_chunk *pc = pipe_session_pop_chunk(ps);
            if (!pc) {
                if (ps->producer_done) {
                    struct MHD_Response *resp = MHD_create_response_from_buffer(
                        0, "", MHD_RESPMEM_PERSISTENT);
                    MHD_add_response_header(resp, "X-Pipe-Done", "1");
                    MHD_add_response_header(resp, "Content-Type",
                                            "application/octet-stream");
                    enum MHD_Result ret = MHD_queue_response(conn, 200, resp);
                    MHD_destroy_response(resp);
                    return ret;
                }
                return send_error(conn, 204, "No chunks yet");
            }
            struct MHD_Response *resp = MHD_create_response_from_buffer(
                pc->len, pc->data, MHD_RESPMEM_MUST_FREE);
            free(pc);
            MHD_add_response_header(resp, "Content-Type",
                                    "application/octet-stream");
            enum MHD_Result ret = MHD_queue_response(conn, 200, resp);
            MHD_destroy_response(resp);
            return ret;
        }

        if (strcmp(ctx->method, "PUT") == 0 && slash) {
            const char *sub = slash + 1;
            if (strncmp(sub, "meta", 4) == 0) {
                cJSON *json = cJSON_ParseWithLength((const char *)ctx->body, ctx->body_len);
                if (json) {
                    cJSON *sz = cJSON_GetObjectItem(json, "size");
                    if (sz && cJSON_IsNumber(sz))
                        ps->estimated_size = (uint64_t)sz->valuedouble;
                    cJSON_Delete(json);
                }
                return send_json(conn, 200, "{\"ok\":true}");
            }
            if (strncmp(sub, "chunk/", 6) == 0) {
                int part = atoi(sub + 6);
                if (pipe_session_add_chunk(ps, part, ctx->body, ctx->body_len) != 0)
                    return send_error(conn, 503, "Pipe queue full, retry");
                return send_json(conn, 200, "{\"ok\":true}");
            }
        }

        if (strcmp(ctx->method, "POST") == 0 && slash &&
            strncmp(slash + 1, "done", 4) == 0) {
            ps->done = 1;
            db_set_suspended(g_db, ps->src_node, 0);
            char pipe_key[128];
            snprintf(pipe_key, sizeof(pipe_key), "pipe_task_%s", ps->src_node);
            db_config_set(g_db, pipe_key, "");
            if (g_verbose)
                fprintf(stderr, "pipe: session %s done, resumed %s\n", token, ps->src_node);
            return send_json(conn, 200, "{\"ok\":true}");
        }

        return send_error(conn, 404, "Pipe endpoint not found");
    }

    /* ── cron sync endpoint ── */
    if (strcmp(ctx->method, "GET") == 0 &&
        strcmp(ctx->target_url, "/v1/cron/sync") == 0) {
        cJSON *tasks = cJSON_CreateArray();

        if (ctx->node[0]) {
            char pipe_key[128];
            snprintf(pipe_key, sizeof(pipe_key), "pipe_task_%s", ctx->node);
            char pipe_task_json[4096] = {0};
            if (db_config_get(g_db, pipe_key, pipe_task_json,
                              sizeof(pipe_task_json)) == ZEP_ERR_OK &&
                pipe_task_json[0]) {
                cJSON *pt = cJSON_Parse(pipe_task_json);
                if (pt) {
                    cJSON_AddItemToArray(tasks, pt);
                    char *js = cJSON_PrintUnformatted(tasks);
                    cJSON_Delete(tasks);
                    enum MHD_Result ret = send_json(conn, 200, js);
                    free(js);
                    return ret;
                }
            }
        }

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

    unsigned int flags = MHD_USE_TLS | MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD;

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

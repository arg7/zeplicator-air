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
#include <microhttpd.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

static void ssl_ctx_setup(void *cls) {
    (void)cls;
}

static char g_storage_root[ZEP_MAX_PATH] = "/var/lib/zep-air";
static char g_db_path[ZEP_MAX_PATH]       = "/var/lib/zep-air/zep-air.db";
static int  g_port = 8443;
static char g_cert_path[ZEP_MAX_PATH] = "";
static char g_key_path[ZEP_MAX_PATH] = "";
static char g_ca_path[ZEP_MAX_PATH] = "";
static int  g_verbose = 0;
static struct MHD_Daemon *g_daemon = NULL;
static sqlite3 *g_db = NULL;

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

    if (g_verbose) {
        printf("verify: cluster=%s toguid=%s fromguid=%s snap=%s\n",
               cluster_key, toguid, fromguid, meta.snapshot);
    }

    db_close(db);
    storage_meta_free(&meta);
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

        const union MHD_ConnectionInfo *info = MHD_get_connection_info(
            conn, MHD_CONNECTION_INFO_GNUTLS_CLIENT_CERT);
        int has_cert = (info && info->client_cert) ? 1 : 0;

        if (strcmp(url, "/health") == 0) {
            return send_response(conn, 200, "text/plain", "ok", 2);
        }

        if (!has_cert) {
            return send_error(conn, 401, "Client certificate required");
        }

        ctx->authed = 1;
        snprintf(ctx->node, sizeof(ctx->node), "cert-authenticated");

        parse_url(url, ctx);
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
        {"db",      required_argument, 0, 'D'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:s:c:k:a:D:vh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': g_port = atoi(optarg); break;
            case 's': snprintf(g_storage_root, sizeof(g_storage_root), "%s", optarg); break;
            case 'c': snprintf(g_cert_path, sizeof(g_cert_path), "%s", optarg); break;
            case 'k': snprintf(g_key_path, sizeof(g_key_path), "%s", optarg); break;
            case 'a': snprintf(g_ca_path, sizeof(g_ca_path), "%s", optarg); break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'v': g_verbose = 1; break;
            case 'h': usage_serve(argv[0]); return 0;
            default:  usage_serve(argv[0]); return 1;
        }
    }

    if (!g_cert_path[0] || !g_key_path[0]) {
        fprintf(stderr, "error: --cert and --key are required\n");
        return 1;
    }

    char *cert_pem = NULL, *key_pem = NULL, *ca_pem = NULL;
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
                        db_cert_store(g_db, "Zep-Air testing", ca_fp, "CA");
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
                                 MHD_OPTION_HTTPS_CERT_CALLBACK, &ssl_ctx_setup,
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

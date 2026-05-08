/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

static char g_server[512] = "https://master.zep.lan:8443";
static char g_cert_path[ZEP_MAX_PATH];
static char g_key_path[ZEP_MAX_PATH];
static char g_ca_path[ZEP_MAX_PATH];
static char g_key_password[128];
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

#define ZEP_ADMIN_PIPE_CHUNK (1024 * 1024)

static int cmd_pipe(int argc, char *argv[]) {
    const char *node = NULL;
    int progress = 0;
    int recv_mode = 0;
    int compress = 0;
    int buffer = 0;
    int cmd_start = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--recv") == 0)
            recv_mode = 1;
        else if (strcmp(argv[i], "--compress") == 0)
            compress = 1;
        else if (strcmp(argv[i], "--buffer") == 0)
            buffer = 1;
        else if (strcmp(argv[i], "--node") == 0 && i + 1 < argc)
            node = argv[++i];
        else if (strcmp(argv[i], "--progress") == 0)
            progress = 1;
        else if (strcmp(argv[i], "--") == 0) {
            cmd_start = i + 1;
            break;
        } else if (argv[i][0] != '-') {
            cmd_start = i;
            break;
        }
    }

    if (cmd_start < 0 || cmd_start >= argc) {
        fprintf(stderr, "Usage: zep-air-admin pipe [--recv] [--compress] [--buffer] [--node CN] [--progress] <command...>\n"
                        "  --recv      Admin→node direction (zfs recv on remote node)\n"
                        "  --compress  Apply pipe_zip_cmd / pipe_unzip_cmd compression\n"
                        "  --buffer    Apply pipe_send_buf_cmd / pipe_recv_buf_cmd buffering\n"
                        "  --node CN   Target node (default: auto-select)\n"
                        "  --progress  Print transfer progress to stderr\n"
                        "\nExamples:\n"
                        "  zep-air-admin pipe zfs send -R tank-prod/data\n"
                        "  zep-air-admin pipe --recv --compress dd if=/dev/urandom bs=1M count=10\n"
                        "  zep-air-admin pipe --compress --buffer --recv zfs recv -F -u tank-prod/data\n");
        return 1;
    }

    char cmd_buf[4096] = {0};
    for (int i = cmd_start; i < argc; i++) {
        if (i > cmd_start) strncat(cmd_buf, " ", sizeof(cmd_buf) - strlen(cmd_buf) - 1);
        strncat(cmd_buf, argv[i], sizeof(cmd_buf) - strlen(cmd_buf) - 1);
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "command", cmd_buf);
    if (recv_mode)       cJSON_AddStringToObject(json, "direction", "recv");
    if (compress)        cJSON_AddBoolToObject(json, "compress", 1);
    if (buffer)          cJSON_AddBoolToObject(json, "buffer", 1);
    if (node)            cJSON_AddStringToObject(json, "node", node);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    char url[1024];
    snprintf(url, sizeof(url), "%s/v1/admin/pipe", g_server);

    struct curl_buf resp = {0};
    CURL *curl = curl_easy_init();
    if (!curl) { free(body); return 1; }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, g_cert_path);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, g_key_path);
    curl_easy_setopt(curl, CURLOPT_CAINFO, g_ca_path);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    if (g_key_password[0])
        curl_easy_setopt(curl, CURLOPT_KEYPASSWD, g_key_password);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(body);

    if (rc != CURLE_OK) {
        fprintf(stderr, "pipe: curl error: %s\n", curl_easy_strerror(rc));
        free(resp.data);
        return 1;
    }
    if (http_code != 200) {
        fprintf(stderr, "pipe: HTTP %ld — %s\n", http_code, resp.data ? resp.data : "");
        free(resp.data);
        return 1;
    }

    cJSON *init_resp = cJSON_Parse(resp.data);
    free(resp.data);
    if (!init_resp) { fprintf(stderr, "pipe: invalid init response\n"); return 1; }
    cJSON *sess_j = cJSON_GetObjectItem(init_resp, "session");
    if (!sess_j || !cJSON_IsString(sess_j)) {
        cJSON_Delete(init_resp);
        fprintf(stderr, "pipe: no session in response\n");
        return 1;
    }
    char session[64];
    snprintf(session, sizeof(session), "%s", sess_j->valuestring);
    cJSON_Delete(init_resp);

    if (recv_mode) {
        unsigned char *buf = malloc(ZEP_ADMIN_PIPE_CHUNK + 4);
        if (!buf) { fprintf(stderr, "pipe: OOM\n"); return 1; }
        int part = 0;
        uint64_t sent = 0;

        if (g_verbose || progress)
            fprintf(stderr, "pipe: recv session %s, reading stdin...\n", session);

        for (;;) {
            size_t nread = fread(buf + 4, 1, ZEP_ADMIN_PIPE_CHUNK, stdin);
            if (nread == 0) break;

            uint32_t zer = 0;
            memcpy(buf, &zer, 4);

            int retries = 0;
            for (;;) {
                char put_url[1024];
                snprintf(put_url, sizeof(put_url),
                         "%s/v1/admin/pipe/%s/chunk/%04d",
                         g_server, session, part);
                struct curl_buf pr = {0};
                CURL *pc = curl_easy_init();
                if (!pc) { free(buf); return 1; }
                curl_easy_setopt(pc, CURLOPT_URL, put_url);
                curl_easy_setopt(pc, CURLOPT_WRITEFUNCTION, curl_write_cb);
                curl_easy_setopt(pc, CURLOPT_WRITEDATA, &pr);
                curl_easy_setopt(pc, CURLOPT_SSLCERT, g_cert_path);
                curl_easy_setopt(pc, CURLOPT_SSLKEY, g_key_path);
                curl_easy_setopt(pc, CURLOPT_CAINFO, g_ca_path);
                curl_easy_setopt(pc, CURLOPT_SSL_VERIFYPEER, 1L);
                curl_easy_setopt(pc, CURLOPT_SSL_VERIFYHOST, 2L);
                curl_easy_setopt(pc, CURLOPT_TIMEOUT, 30L);
                curl_easy_setopt(pc, CURLOPT_CONNECTTIMEOUT, 10L);
                if (g_key_password[0])
                    curl_easy_setopt(pc, CURLOPT_KEYPASSWD, g_key_password);
                curl_easy_setopt(pc, CURLOPT_POSTFIELDSIZE, (long)(nread + 4));
                curl_easy_setopt(pc, CURLOPT_POSTFIELDS, buf);
                curl_easy_setopt(pc, CURLOPT_CUSTOMREQUEST, "PUT");
                rc = curl_easy_perform(pc);
                curl_easy_getinfo(pc, CURLINFO_RESPONSE_CODE, &http_code);
                curl_easy_cleanup(pc);
                free(pr.data);

                if (rc != CURLE_OK) {
                    fprintf(stderr, "pipe: chunk %d upload: %s\n",
                            part, curl_easy_strerror(rc));
                    free(buf);
                    return 1;
                }
                if (http_code == 503) {
                    if (retries++ > 60) {
                        fprintf(stderr, "pipe: queue full too long\n");
                        free(buf);
                        return 1;
                    }
                    sleep(1);
                    continue;
                }
                if (http_code != 200) {
                    fprintf(stderr, "pipe: chunk %d HTTP %ld\n",
                            part, http_code);
                    free(buf);
                    return 1;
                }
                break;
            }
            sent += nread;
            part++;
            if (progress)
                fprintf(stderr, "\rpipe: %llu bytes sent (%d chunks)",
                        (unsigned long long)sent, part);
        }
        free(buf);

        char done_url[1024];
        snprintf(done_url, sizeof(done_url),
                 "%s/v1/admin/pipe/%s/done", g_server, session);
        struct curl_buf dr = {0};
        CURL *dc = curl_easy_init();
        if (dc) {
            curl_easy_setopt(dc, CURLOPT_URL, done_url);
            curl_easy_setopt(dc, CURLOPT_WRITEFUNCTION, curl_write_cb);
            curl_easy_setopt(dc, CURLOPT_WRITEDATA, &dr);
            curl_easy_setopt(dc, CURLOPT_SSLCERT, g_cert_path);
            curl_easy_setopt(dc, CURLOPT_SSLKEY, g_key_path);
            curl_easy_setopt(dc, CURLOPT_CAINFO, g_ca_path);
            curl_easy_setopt(dc, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(dc, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(dc, CURLOPT_TIMEOUT, 30L);
            curl_easy_setopt(dc, CURLOPT_CONNECTTIMEOUT, 10L);
            if (g_key_password[0])
                curl_easy_setopt(dc, CURLOPT_KEYPASSWD, g_key_password);
            curl_easy_setopt(dc, CURLOPT_CUSTOMREQUEST, "POST");
            rc = curl_easy_perform(dc);
            curl_easy_getinfo(dc, CURLINFO_RESPONSE_CODE, &http_code);
            curl_easy_cleanup(dc);
            free(dr.data);
        }

        if (progress)
            fprintf(stderr, "\npipe: recv complete — %llu bytes (%d chunks)\n",
                    (unsigned long long)sent, part);
        return 0;
    }

    uint64_t total_size = 0, received = 0;
    char poll_url[1024];
    snprintf(poll_url, sizeof(poll_url), "%s/v1/admin/pipe/%s", g_server, session);

    if (g_verbose || progress)
        fprintf(stderr, "pipe: session %s, waiting for chunks...\n", session);

    for (;;) {
        struct curl_buf pr = {0};
        CURL *pc = curl_easy_init();
        if (!pc) { fprintf(stderr, "pipe: curl init failed\n"); return 1; }
        curl_easy_setopt(pc, CURLOPT_URL, poll_url);
        curl_easy_setopt(pc, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(pc, CURLOPT_WRITEDATA, &pr);
        curl_easy_setopt(pc, CURLOPT_SSLCERT, g_cert_path);
        curl_easy_setopt(pc, CURLOPT_SSLKEY, g_key_path);
        curl_easy_setopt(pc, CURLOPT_CAINFO, g_ca_path);
        curl_easy_setopt(pc, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(pc, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(pc, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(pc, CURLOPT_CONNECTTIMEOUT, 10L);
        if (g_key_password[0])
            curl_easy_setopt(pc, CURLOPT_KEYPASSWD, g_key_password);

        rc = curl_easy_perform(pc);
        curl_easy_getinfo(pc, CURLINFO_RESPONSE_CODE, &http_code);

        curl_off_t cl = 0;
        curl_easy_getinfo(pc, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);

        curl_easy_cleanup(pc);

        if (rc != CURLE_OK) {
            fprintf(stderr, "pipe: curl error: %s\n", curl_easy_strerror(rc));
            free(pr.data);
            return 1;
        }

        if (http_code == 204) {
            free(pr.data);
            sleep(1);
            continue;
        }

        if (http_code != 200) {
            fprintf(stderr, "pipe: HTTP %ld — aborting\n", http_code);
            free(pr.data);
            return 1;
        }

        int is_done = (cl == 0);

        if (!is_done && pr.data && pr.len > 0) {
            if (pr.len >= 4) {
                uint32_t errlen;
                memcpy(&errlen, pr.data, 4);
                size_t stdout_len = pr.len - 4 - (size_t)errlen;
                if (stdout_len <= pr.len - 4) {
                    if (stdout_len > 0)
                        fwrite(pr.data + 4, 1, stdout_len, stdout);
                    if (errlen > 0)
                        fwrite(pr.data + 4 + stdout_len, 1, errlen, stderr);
                    fflush(stdout);
                    fflush(stderr);
                    received += stdout_len;
                }
            } else {
                fwrite(pr.data, 1, pr.len, stdout);
                fflush(stdout);
                received += pr.len;
            }
            if (total_size == 0) total_size = 1;
        }
        free(pr.data);

        if (is_done) {
            if (progress)
                fprintf(stderr, "\npipe: complete — %llu bytes\n",
                        (unsigned long long)received);
            break;
        }

        if (progress && total_size > 0) {
            fprintf(stderr, "\rpipe: %llu bytes received", (unsigned long long)received);
            fflush(stderr);
        }
    }
    return 0;
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
        "  pipe         Send/recv ZFS stream through the server (--recv for stdin→node)\n"
        "  snap         Manual snapshot create/destroy (--name NAME)\n"
        "  config       Server config get/set/list/rm\n"
        "\n"
        "Global options:\n"
        "  --server, -s URL   Server URL (default: https://master.zep.lan:8443)\n"
        "  --cert, -c FILE    Admin client certificate (PEM)\n"
        "  --key, -k FILE     Admin client key (PEM)\n"
        "  --ca, -C FILE      CA certificate (PEM)\n"
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
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            snprintf(g_server, sizeof(g_server), "%s", argv[++i]);
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
        } else {
            argv2[argc2++] = argv[i];
        }
    }
    argv2[argc2] = NULL;

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

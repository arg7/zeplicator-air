#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <curl/curl.h>

static char g_server[512] = "https://master.zep.lan:8443";
static char g_cert_path[ZEP_MAX_PATH];
static char g_key_path[ZEP_MAX_PATH];
static char g_ca_path[ZEP_MAX_PATH];
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
    if (g_verbose) curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    return curl;
}

static int do_post(const char *url, const char *json_body) {
    struct curl_buf resp = {0};
    CURL *curl = curl_init(&resp);
    if (!curl) return 1;

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

static int cmd_setup(int argc, char *argv[]) {
    char *ca_file = NULL, *cert_file = NULL, *key_file = NULL;

    static struct option opts[] = {
        {"ca",   required_argument, 0, 'C'},
        {"cert", required_argument, 0, 'c'},
        {"key",  required_argument, 0, 'k'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "C:c:k:", opts, NULL)) != -1) {
        switch (opt) {
            case 'C': ca_file = optarg; break;
            case 'c': cert_file = optarg; break;
            case 'k': key_file = optarg; break;
        }
    }
    if (!ca_file || !cert_file || !key_file) {
        fprintf(stderr, "Usage: zep-air-admin setup --ca <ca.crt> --cert <server.crt> --key <server.key>\n");
        return 1;
    }

    char *ca_pem = read_file_str(ca_file);
    char *cert_pem = read_file_str(cert_file);
    char *key_pem = read_file_str(key_file);
    if (!ca_pem || !cert_pem || !key_pem) {
        free(ca_pem); free(cert_pem); free(key_pem);
        return 1;
    }

    char *ca_esc = malloc(strlen(ca_pem) * 2 + 1);
    char *cert_esc = malloc(strlen(cert_pem) * 2 + 1);
    char *key_esc = malloc(strlen(key_pem) * 2 + 1);
    if (!ca_esc || !cert_esc || !key_esc) {
        free(ca_pem); free(cert_pem); free(key_pem);
        free(ca_esc); free(cert_esc); free(key_esc);
        return 1;
    }
    json_escape(ca_pem, ca_esc, strlen(ca_pem) * 2 + 1);
    json_escape(cert_pem, cert_esc, strlen(cert_pem) * 2 + 1);
    json_escape(key_pem, key_esc, strlen(key_pem) * 2 + 1);

    char *body = NULL;
    if (asprintf(&body,
        "{\"ca_cert\":\"%s\",\"server_cert\":\"%s\",\"server_key\":\"%s\"}",
        ca_esc, cert_esc, key_esc) < 0) {
        free(ca_pem); free(cert_pem); free(key_pem);
        free(ca_esc); free(cert_esc); free(key_esc);
        return 1;
    }
    free(ca_pem); free(cert_pem); free(key_pem);
    free(ca_esc); free(cert_esc); free(key_esc);

    char url[1024];
    snprintf(url, sizeof(url), "%s/v1/admin/setup", g_server);
    int rc = do_post(url, body);
    free(body);
    return rc;
}

static int cmd_join(int argc, char *argv[]) {
    char *role = NULL, *node = NULL, *cert_file = NULL;

    static struct option opts[] = {
        {"role", required_argument, 0, 'r'},
        {"node", required_argument, 0, 'n'},
        {"cert", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "r:n:c:", opts, NULL)) != -1) {
        switch (opt) {
            case 'r': role = optarg; break;
            case 'n': node = optarg; break;
            case 'c': cert_file = optarg; break;
        }
    }
    if (!role || !node || !cert_file) {
        fprintf(stderr, "Usage: zep-air-admin join --role master|client --node <name> --cert <cert.crt>\n");
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
    char *body = NULL;
    if (asprintf(&body,
        "{\"cn\":\"%s\",\"role\":\"%s\",\"pem\":\"%s\"}", node, role, esc) < 0) {
        free(pem); free(esc); return 1;
    }
    free(pem); free(esc);

    char url[1024];
    snprintf(url, sizeof(url), "%s/v1/admin/nodes", g_server);
    int rc = do_post(url, body);
    free(body);
    return rc;
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
        "  setup        Initial server setup (CA + server certs)\n"
        "  join         Register a master or client node\n"
        "  list-nodes   List registered nodes\n"
        "  remove-node  Remove a node\n"
        "\n"
        "Global options:\n"
        "  --server, -s URL   Server URL (default: https://master.zep.lan:8443)\n"
        "  --cert, -c FILE    Admin client certificate (PEM)\n"
        "  --key, -k FILE     Admin client key (PEM)\n"
        "  --ca, -C FILE      CA certificate (PEM)\n"
        "  --verbose, -v      Verbose output\n"
        "\n"
        "Setup options:\n"
        "  --ca FILE           CA certificate to upload\n"
        "  --cert FILE         Server certificate to upload\n"
        "  --key FILE          Server key to upload\n"
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
        fprintf(stderr, "error: --cert, --key, and --ca are required\n");
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    int rc = 1;
    if (strcmp(cmd, "setup") == 0)       rc = cmd_setup(sub_argc, sub_argv);
    else if (strcmp(cmd, "join") == 0)   rc = cmd_join(sub_argc, sub_argv);
    else if (strcmp(cmd, "list-nodes") == 0) rc = cmd_list_nodes(sub_argc, sub_argv);
    else if (strcmp(cmd, "remove-node") == 0) rc = cmd_remove_node(sub_argc, sub_argv);
    else { fprintf(stderr, "Unknown command: %s\n", cmd); usage(argv2[0]); }

    curl_global_cleanup();
    return rc;
}

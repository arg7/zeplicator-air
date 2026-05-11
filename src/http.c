/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "http.h"
#include "storage.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

struct resp_buf {
    char *data;
    size_t len;
    size_t cap;
};

static size_t write_cb(void *ptr, size_t sz, size_t nmemb, void *user) {
    struct resp_buf *rb = (struct resp_buf *)user;
    size_t total = sz * nmemb;
    if (rb->len + total + 1 > rb->cap) {
        size_t nc = rb->cap ? rb->cap * 2 : 65536;
        while (nc < rb->len + total + 1) nc *= 2;
        char *nd = realloc(rb->data, nc);
        if (!nd) return 0;
        rb->data = nd;
        rb->cap = nc;
    }
    memcpy(rb->data + rb->len, ptr, total);
    rb->len += total;
    rb->data[rb->len] = '\0';
    return total;
}

static CURL *http_init(const http_config_t *cfg, const char *url,
                       struct resp_buf *rb) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, rb);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, cfg->cert_path);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, cfg->key_path[0] ? cfg->key_path : cfg->cert_path);
    curl_easy_setopt(curl, CURLOPT_CAINFO, cfg->ca_path);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    if (cfg->key_password[0])
        curl_easy_setopt(curl, CURLOPT_KEYPASSWD, cfg->key_password);
    return curl;
}

static int http_do(CURL *curl, int keep) {
    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    char *eff_url = NULL;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    zep_log("http: %ld %s\n", http_code, eff_url ? eff_url : "?");
    if (!keep) curl_easy_cleanup(curl);
    if (rc != CURLE_OK) {
        zep_log( "http: %s\n", curl_easy_strerror(rc));
        return ZEP_ERR_NETWORK;
    }
    if (http_code >= 400) {
        zep_log( "http: status %ld\n", http_code);
        return ZEP_ERR_NETWORK;
    }
    return ZEP_ERR_OK;
}

err_t http_persistent_start(http_config_t *cfg) {
    if (cfg->curl) http_persistent_stop(cfg);
    cfg->curl = curl_easy_init();
    if (!cfg->curl) return ZEP_ERR_NETWORK;
    curl_easy_setopt(cfg->curl, CURLOPT_SSLCERT, cfg->cert_path);
    curl_easy_setopt(cfg->curl, CURLOPT_SSLKEY, cfg->key_path[0] ? cfg->key_path : cfg->cert_path);
    curl_easy_setopt(cfg->curl, CURLOPT_CAINFO, cfg->ca_path);
    curl_easy_setopt(cfg->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(cfg->curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(cfg->curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(cfg->curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(cfg->curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(cfg->curl, CURLOPT_KEEP_SENDING_ON_ERROR, 1L);
    {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Connection: keep-alive");
        curl_easy_setopt(cfg->curl, CURLOPT_HTTPHEADER, headers);
    }
    if (cfg->key_password[0])
        curl_easy_setopt(cfg->curl, CURLOPT_KEYPASSWD, cfg->key_password);
    return ZEP_ERR_OK;
}

void http_persistent_stop(http_config_t *cfg) {
    if (cfg->curl) { curl_easy_cleanup(cfg->curl); cfg->curl = NULL; }
}

static CURL *http_reuse(http_config_t *cfg, const char *url, struct resp_buf *rb) {
    if (cfg->curl) {
        curl_easy_setopt(cfg->curl, CURLOPT_URL, url);
        curl_easy_setopt(cfg->curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(cfg->curl, CURLOPT_WRITEDATA, rb);
        curl_easy_setopt(cfg->curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(cfg->curl, CURLOPT_POSTFIELDS, NULL);
        curl_easy_setopt(cfg->curl, CURLOPT_POSTFIELDSIZE, 0L);
        curl_easy_setopt(cfg->curl, CURLOPT_CUSTOMREQUEST, NULL);
        curl_easy_setopt(cfg->curl, CURLOPT_UPLOAD, 0L);
        curl_easy_setopt(cfg->curl, CURLOPT_NOBODY, 0L);
        return cfg->curl;
    }
    return NULL;
}

err_t http_put_blob(const http_config_t *cfg, const char *node,
                    const char *prefix, int part,
                    const void *data, size_t len) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/nodes/%s/snapshots/%s/blobs/%04d",
                 cfg->server_url, node, prefix, part) < 0)
        return ZEP_ERR_SYS;

    struct resp_buf rb = {0};
    CURL *curl = http_reuse((http_config_t *)cfg, url, &rb);
    if (!curl) {
        curl = http_init(cfg, url, &rb);
        if (!curl) { free(url); return ZEP_ERR_NETWORK; }
    }
    free(url);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0);
    free(rb.data);
    return rc;
}

err_t http_put_meta(const http_config_t *cfg, const char *node,
                    const char *prefix, const snapshot_meta_t *meta) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/nodes/%s/snapshots/%s/meta",
                 cfg->server_url, node, prefix) < 0)
        return ZEP_ERR_SYS;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "snapshot", meta->snapshot);
    cJSON_AddStringToObject(json, "guid", meta->guid);
    cJSON_AddStringToObject(json, "base_guid", meta->base_guid);
    cJSON_AddStringToObject(json, "label", meta->label);
    cJSON_AddStringToObject(json, "cluster_fs", meta->cluster_fs);
    cJSON_AddStringToObject(json, "created", meta->created);
    cJSON_AddStringToObject(json, "host", meta->host);
    cJSON_AddNumberToObject(json, "stream_size", (double)meta->stream_size);
    cJSON_AddNumberToObject(json, "blob_count", meta->blob_count);
    cJSON *blobs = cJSON_AddArrayToObject(json, "blobs");
    for (int i = 0; i < meta->blob_count; i++) {
        cJSON *b = cJSON_CreateObject();
        cJSON_AddNumberToObject(b, "part", i);
        cJSON_AddNumberToObject(b, "size", (double)meta->blobs[i].size);
        cJSON_AddStringToObject(b, "sha256", meta->blobs[i].sha256);
        cJSON_AddItemToArray(blobs, b);
    }
    char *js_str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    zep_log( "http_put_meta: cluster_fs='%s' url=%s/%s body=%s\n",
            meta->cluster_fs, node, prefix, js_str);

    struct resp_buf rb = {0};
    CURL *curl = http_reuse((http_config_t *)cfg, url, &rb);
    if (!curl) {
        curl = http_init(cfg, url, &rb);
        if (!curl) { free(url); free(js_str); return ZEP_ERR_NETWORK; }
    }
    free(url);

    size_t jlen = strlen(js_str);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)jlen);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, js_str);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0);
    free(js_str);
    free(rb.data);
    return rc;
}

err_t http_get_meta(const http_config_t *cfg, const char *node,
                    const char *prefix, snapshot_meta_t *meta) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/nodes/%s/snapshots/%s/meta.json",
                 cfg->server_url, node, prefix) < 0)
        return ZEP_ERR_SYS;

    struct resp_buf rb = {0};
    CURL *curl = http_reuse((http_config_t *)cfg, url, &rb);
    if (!curl) {
        curl = http_init(cfg, url, &rb);
        if (!curl) { free(url); return ZEP_ERR_NETWORK; }
    }
    free(url);

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0);
    if (rc != ZEP_ERR_OK) { free(rb.data); return rc; }

    /* parse JSON in the same way storage_read_meta does */
    cJSON *json = cJSON_Parse(rb.data);
    free(rb.data);
    if (!json) return ZEP_ERR_JSON;

    memset(meta, 0, sizeof(*meta));

    #define GET_STR(field, name) do { \
        cJSON *item = cJSON_GetObjectItem(json, name); \
        if (item && cJSON_IsString(item)) snprintf(meta->field, sizeof(meta->field), "%s", item->valuestring); \
    } while(0)

    GET_STR(snapshot, "snapshot");
    GET_STR(guid, "guid");
    GET_STR(base_guid, "base_guid");
    GET_STR(label, "label");
    GET_STR(cluster_fs, "cluster_fs");
    GET_STR(created, "created");
    GET_STR(host, "host");

    cJSON *item = cJSON_GetObjectItem(json, "stream_size");
    if (item && cJSON_IsNumber(item)) meta->stream_size = (uint64_t)item->valuedouble;

    item = cJSON_GetObjectItem(json, "blob_count");
    if (item && cJSON_IsNumber(item)) meta->blob_count = item->valueint;

    cJSON *blobs_arr = cJSON_GetObjectItem(json, "blobs");
    if (blobs_arr && cJSON_IsArray(blobs_arr) && meta->blob_count > 0) {
        meta->blobs = calloc((size_t)meta->blob_count, sizeof(blob_info_t));
        if (meta->blobs) {
            int i = 0;
            cJSON *b;
            cJSON_ArrayForEach(b, blobs_arr) {
                if (i >= meta->blob_count) break;
                cJSON *p = cJSON_GetObjectItem(b, "part");
                cJSON *s = cJSON_GetObjectItem(b, "size");
                cJSON *h = cJSON_GetObjectItem(b, "sha256");
                if (p && cJSON_IsNumber(p)) snprintf(meta->blobs[i].part, sizeof(meta->blobs[i].part), "%04d", p->valueint);
                if (s && cJSON_IsNumber(s)) meta->blobs[i].size = (size_t)s->valuedouble;
                if (h && cJSON_IsString(h)) snprintf(meta->blobs[i].sha256, sizeof(meta->blobs[i].sha256), "%s", h->valuestring);
                i++;
            }
        }
    }
    cJSON_Delete(json);
    return ZEP_ERR_OK;
}

err_t http_get_blob(const http_config_t *cfg, const char *node,
                    const char *prefix, int part,
                    void **data, size_t *len) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/nodes/%s/snapshots/%s/blobs/%04d",
                 cfg->server_url, node, prefix, part) < 0)
        return ZEP_ERR_SYS;

    struct resp_buf rb = {0};
    CURL *curl = http_reuse((http_config_t *)cfg, url, &rb);
    if (!curl) {
        curl = http_init(cfg, url, &rb);
        if (!curl) { free(url); return ZEP_ERR_NETWORK; }
    }
    free(url);

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0);
    if (rc != ZEP_ERR_OK || !rb.data) {
        free(rb.data);
        return rc != ZEP_ERR_OK ? rc : ZEP_ERR_STORAGE;
    }

    *data = rb.data;
    *len = rb.len;
    return ZEP_ERR_OK;
}

err_t http_get_blob_by_guid(const http_config_t *cfg, const char *guid,
                            int part, void **data, size_t *len) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/blobs/%s/%04d",
                 cfg->server_url, guid, part) < 0)
        return ZEP_ERR_SYS;

    struct resp_buf rb = {0};
    CURL *curl = http_reuse((http_config_t *)cfg, url, &rb);
    if (!curl) {
        curl = http_init(cfg, url, &rb);
        if (!curl) { free(url); return ZEP_ERR_NETWORK; }
    }
    free(url);

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0);
    if (rc != ZEP_ERR_OK || !rb.data) {
        free(rb.data);
        return rc != ZEP_ERR_OK ? rc : ZEP_ERR_STORAGE;
    }

    *data = rb.data;
    *len = rb.len;
    return ZEP_ERR_OK;
}

err_t http_list_snapshots(const http_config_t *cfg, const char *node,
                          int limit, char ***prefixes, int *count) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/nodes/%s/snapshots",
                 cfg->server_url, node) < 0)
        return ZEP_ERR_SYS;

    struct resp_buf rb = {0};
    CURL *curl = http_reuse((http_config_t *)cfg, url, &rb);
    if (!curl) {
        curl = http_init(cfg, url, &rb);
        if (!curl) { free(url); return ZEP_ERR_NETWORK; }
    }
    free(url);

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0);
    if (rc != ZEP_ERR_OK || !rb.data) {
        free(rb.data);
        *count = 0;
        *prefixes = NULL;
        return rc != ZEP_ERR_OK ? rc : ZEP_ERR_OK;
    }

    cJSON *json = cJSON_Parse(rb.data);
    free(rb.data);
    if (!json || !cJSON_IsArray(json)) {
        if (json) cJSON_Delete(json);
        *count = 0;
        *prefixes = NULL;
        return ZEP_ERR_OK;
    }

    int cap = limit > 0 ? limit : 64;
    int cnt = 0;
    char **list = calloc((size_t)cap, sizeof(char *));
    if (!list) { cJSON_Delete(json); return ZEP_ERR_SYS; }

    cJSON *item;
    cJSON_ArrayForEach(item, json) {
        if (limit > 0 && cnt >= limit) break;
        if (cJSON_IsString(item)) {
            if (cnt >= cap) {
                cap *= 2;
                char **nl = realloc(list, (size_t)cap * sizeof(char *));
                if (!nl) { storage_free_list(list, cnt); cJSON_Delete(json); return ZEP_ERR_SYS; }
                list = nl;
            }
            list[cnt++] = strdup(item->valuestring);
        }
    }
    cJSON_Delete(json);
    *prefixes = list;
    *count = cnt;
    return ZEP_ERR_OK;
}

char *http_get_json(const http_config_t *cfg, const char *path) {
    char *url = NULL;
    if (asprintf(&url, "%s%s", cfg->server_url, path) < 0)
        return NULL;

    struct resp_buf rb = {0};
    CURL *curl = http_reuse((http_config_t *)cfg, url, &rb);
    if (!curl) {
        curl = http_init(cfg, url, &rb);
        if (!curl) { free(url); return NULL; }
    }
    free(url);

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0);
    if (rc != ZEP_ERR_OK || !rb.data) {
        free(rb.data);
        return NULL;
    }
    return rb.data;
}

err_t http_post_json(const http_config_t *cfg, const char *path, const char *body) {
    char *url = NULL;
    if (asprintf(&url, "%s%s", cfg->server_url, path) < 0)
        return ZEP_ERR_SYS;

    struct resp_buf rb = {0};
    CURL *curl = http_reuse((http_config_t *)cfg, url, &rb);
    if (!curl) {
        curl = http_init(cfg, url, &rb);
        if (!curl) { free(url); return ZEP_ERR_SYS; }
    }
    free(url);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0);
    free(rb.data);
    return rc;
}

err_t http_put_pipe_chunk(const http_config_t *cfg, const char *session,
                          int part, const void *data, size_t len) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/pipe/%s/chunk/%04d",
                 cfg->server_url, session, part) < 0)
        return ZEP_ERR_SYS;

    for (int retry = 0; retry < 120; retry++) {
        struct resp_buf rb = {0};
        CURL *curl = http_init(cfg, url, &rb);
        if (!curl) { free(url); return ZEP_ERR_NETWORK; }

        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

        CURLcode crc = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);
        free(rb.data);

        if (crc != CURLE_OK) {
            zep_log( "http_put_chunk: %s\n", curl_easy_strerror(crc));
            free(url);
            return ZEP_ERR_NETWORK;
        }
        if (http_code == 503) {
            sleep(1);
            continue;
        }
        free(url);
        if (http_code >= 400) {
            zep_log( "http_put_chunk: HTTP %ld\n", http_code);
            return ZEP_ERR_NETWORK;
        }
        return ZEP_ERR_OK;
    }
    free(url);
    zep_log( "http_put_chunk: too many retries\n");
    return ZEP_ERR_NETWORK;
}

err_t http_put_pipe_meta(const http_config_t *cfg, const char *session,
                         uint64_t size) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/pipe/%s/meta", cfg->server_url, session) < 0)
        return ZEP_ERR_SYS;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "size", (double)size);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    struct resp_buf rb = {0};
    CURL *curl = http_init(cfg, url, &rb);
    free(url);
    if (!curl) { free(body); return ZEP_ERR_NETWORK; }

    size_t jlen = strlen(body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)jlen);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

    int rc = http_do(curl, 0);
    free(body);
    free(rb.data);
    return rc;
}

err_t http_post_pipe_done(const http_config_t *cfg, const char *session) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/pipe/%s/done", cfg->server_url, session) < 0)
        return ZEP_ERR_SYS;

    struct resp_buf rb = {0};
    CURL *curl = http_init(cfg, url, &rb);
    free(url);
    if (!curl) return ZEP_ERR_NETWORK;

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    int rc = http_do(curl, 0);
    free(rb.data);
    return rc;
}

err_t http_get_pipe_chunk(const http_config_t *cfg, const char *session,
                          void **data, size_t *len, int *is_done) {
    char *url = NULL;
    if (asprintf(&url, "%s/v1/pipe/%s", cfg->server_url, session) < 0)
        return ZEP_ERR_SYS;

    *data = NULL;
    *len = 0;
    *is_done = 0;

    struct resp_buf rb = {0};
    CURL *curl = http_init(cfg, url, &rb);
    free(url);
    if (!curl) return ZEP_ERR_NETWORK;

    CURLcode crc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (crc != CURLE_OK) {
        zep_log( "http_get_pipe_chunk: %s\n", curl_easy_strerror(crc));
        free(rb.data);
        return ZEP_ERR_NETWORK;
    }

    if (http_code == 204) {
        free(rb.data);
        return ZEP_ERR_NOT_FOUND;
    }

    if (http_code == 200) {
        if (rb.data && rb.len > 0) {
            *data = rb.data;
            *len = rb.len;
            return ZEP_ERR_OK;
        }
        *is_done = 1;
        free(rb.data);
        return ZEP_ERR_OK;
    }

    zep_log( "http_get_pipe_chunk: HTTP %ld\n", http_code);
    free(rb.data);
    return ZEP_ERR_NETWORK;
}

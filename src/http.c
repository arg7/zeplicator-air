/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "http.h"
#include "audit.h"
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

static int http_do(CURL *curl, int keep, const char *method) {
    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    char *eff_url = NULL;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    zep_log("http: %ld %s\n", http_code, eff_url ? eff_url : "?");

    /* audit the HTTP call */
    if (eff_url) {
        audit_log(AUDIT_EVT_HTTP, method ? method : "http", eff_url, (int)http_code);
    }

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

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0, "GET");
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

    int rc = http_do(curl, curl == cfg->curl ? 1 : 0, "POST");
    free(rb.data);
    return rc;
}



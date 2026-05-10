/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "storage.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <cjson/cJSON.h>

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
    if (mkdir(path, 0755) != 0) {
        char tmp[ZEP_MAX_PATH];
        snprintf(tmp, sizeof(tmp), "%s", path);
        char *p = tmp;
        if (*p == '/') p++;
        while (*p) {
            if (*p == '/') {
                *p = '\0';
                mkdir(tmp, 0755);
                *p = '/';
            }
            p++;
        }
        return mkdir(tmp, 0755);
    }
    return 0;
}

err_t storage_ensure_dir(const char *root, const char *node, const char *prefix) {
    char path[ZEP_MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s/%s", root, node, prefix);
    if (ensure_dir(path) != 0) {
        fprintf(stderr, "storage_ensure_dir: failed to create %s: %s\n", path, strerror(errno));
        return ZEP_ERR_STORAGE;
    }
    return ZEP_ERR_OK;
}

err_t storage_write_meta(const char *root, const char *node, const char *prefix,
                         const snapshot_meta_t *meta) {
    cJSON *json = cJSON_CreateObject();
    if (!json) return ZEP_ERR_JSON;

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

    char *js_str = cJSON_Print(json);
    cJSON_Delete(json);
    if (!js_str) return ZEP_ERR_JSON;

    char path[ZEP_MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s/%s/meta.json", root, node, prefix);

    FILE *f = fopen(path, "w");
    if (!f) {
        free(js_str);
        fprintf(stderr, "storage_write_meta: fopen %s: %s\n", path, strerror(errno));
        return ZEP_ERR_STORAGE;
    }
    fputs(js_str, f);
    fclose(f);
    free(js_str);
    return ZEP_ERR_OK;
}

err_t storage_read_meta(const char *root, const char *node, const char *prefix,
                        snapshot_meta_t *meta) {
    char path[ZEP_MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s/%s/meta.json", root, node, prefix);

    FILE *f = fopen(path, "r");
    if (!f) return ZEP_ERR_STORAGE;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) { fclose(f); return ZEP_ERR_STORAGE; }

    char *buf = malloc((size_t)fsize + 1);
    if (!buf) { fclose(f); return ZEP_ERR_SYS; }

    size_t nread = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    buf[nread] = '\0';

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    if (!json) return ZEP_ERR_JSON;

    memset(meta, 0, sizeof(*meta));

    cJSON *item;
    #define GET_STR(field, name) do { \
        item = cJSON_GetObjectItem(json, name); \
        if (item && cJSON_IsString(item)) snprintf(meta->field, sizeof(meta->field), "%s", item->valuestring); \
    } while(0)

    GET_STR(snapshot, "snapshot");
    GET_STR(guid, "guid");
    GET_STR(base_guid, "base_guid");
    GET_STR(label, "label");
    GET_STR(cluster_fs, "cluster_fs");
    GET_STR(created, "created");
    GET_STR(host, "host");

    item = cJSON_GetObjectItem(json, "stream_size");
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

err_t storage_write_blob(const char *root, const char *node, const char *prefix,
                         int part, const void *data, size_t len) {
    char path[ZEP_MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s/%s/%04d", root, node, prefix, part);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "storage_write_blob: fopen %s: %s\n", path, strerror(errno));
        return ZEP_ERR_STORAGE;
    }
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    if (written != len) return ZEP_ERR_STORAGE;
    return ZEP_ERR_OK;
}

err_t storage_read_blob(const char *root, const char *node, const char *prefix,
                        int part, void **data, size_t *len) {
    char path[ZEP_MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s/%s/%04d", root, node, prefix, part);

    FILE *f = fopen(path, "rb");
    if (!f) return ZEP_ERR_STORAGE;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 0) { fclose(f); return ZEP_ERR_STORAGE; }

    *data = malloc((size_t)fsize);
    if (!*data) { fclose(f); return ZEP_ERR_SYS; }

    *len = fread(*data, 1, (size_t)fsize, f);
    fclose(f);
    return ZEP_ERR_OK;
}

err_t storage_list_prefixes(const char *root, const char *node, int limit,
                            char ***prefixes, int *count) {
    char path[ZEP_MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s", root, node);

    DIR *d = opendir(path);
    if (!d) {
        *count = 0;
        *prefixes = NULL;
        return ZEP_ERR_OK;
    }

    int cap = limit > 0 ? limit : 64;
    int cnt = 0;
    char **list = calloc((size_t)cap, sizeof(char *));
    if (!list) { closedir(d); return ZEP_ERR_SYS; }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && (limit <= 0 || cnt < limit)) {
        if (ent->d_name[0] == '.') continue;
        if (cnt >= cap) {
            cap *= 2;
            char **nlist = realloc(list, (size_t)cap * sizeof(char *));
            if (!nlist) {
                for (int i = 0; i < cnt; i++) free(list[i]);
                free(list);
                closedir(d);
                return ZEP_ERR_SYS;
            }
            list = nlist;
        }
        list[cnt++] = strdup(ent->d_name);
    }
    closedir(d);

    *prefixes = list;
    *count = cnt;
    return ZEP_ERR_OK;
}

void storage_free_list(char **list, int count) {
    for (int i = 0; i < count; i++) free(list[i]);
    free(list);
}

void storage_meta_free(snapshot_meta_t *meta) {
    if (meta) {
        free(meta->blobs);
        memset(meta, 0, sizeof(*meta));
    }
}

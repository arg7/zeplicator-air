/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "pipeline.h"
#include "storage.h"
#include "zfs.h"
#include "http.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

err_t pipeline_resolve_fs(const char *cluster_fs, const char *mapping,
                          char *local_fs, size_t len) {
    if (!cluster_fs || !mapping) return ZEP_ERR_NOT_FOUND;
    const char *p = mapping;
    while (*p) {
        const char *colon = strchr(p, ':');
        if (!colon) break;
        size_t cf_len = (size_t)(colon - p);
        if (strncmp(p, cluster_fs, cf_len) == 0 && (size_t)strlen(cluster_fs) == cf_len) {
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= len) n = len - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            return ZEP_ERR_OK;
        }
        const char *comma = strchr(colon, ',');
        p = comma ? comma + 1 : colon + strlen(colon);
    }
    return ZEP_ERR_NOT_FOUND;
}

int pipeline_has_mapping(const char *cluster_fs, const char *mapping) {
    char buf[512];
    return pipeline_resolve_fs(cluster_fs, mapping, buf, sizeof(buf)) == ZEP_ERR_OK;
}

err_t pipeline_for_each_fs(const char *mapping,
                           void (*cb)(const char *cluster_fs, const char *local_fs,
                                      void *user), void *user) {
    if (!mapping || !mapping[0]) return ZEP_ERR_NOT_FOUND;
    const char *p = mapping;
    while (*p) {
        const char *colon = strchr(p, ':');
        if (!colon) break;
        char cf[256], lf[256];
        size_t cf_len = (size_t)(colon - p);
        if (cf_len >= sizeof(cf)) cf_len = sizeof(cf) - 1;
        memcpy(cf, p, cf_len); cf[cf_len] = '\0';

        const char *start = colon + 1;
        const char *end = strchr(start, ',');
        if (!end) end = start + strlen(start);
        const char *paren = strchr(start, '(');
        size_t lf_len = paren ? (size_t)(paren - start) : (size_t)(end - start);
        if (lf_len >= sizeof(lf)) lf_len = sizeof(lf) - 1;
        memcpy(lf, start, lf_len); lf[lf_len] = '\0';

        cb(cf, lf, user);

        const char *comma = strchr(colon, ',');
        p = comma ? comma + 1 : colon + strlen(colon);
    }
    return ZEP_ERR_OK;
}

static void sha256_hex(const unsigned char *data, size_t len, char hex[65]) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, &hlen);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hlen; i++)
        sprintf(hex + i * 2, "%02x", hash[i]);
    hex[hlen * 2] = '\0';
}

static void iso8601_now(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
}


static err_t find_base_snapshot(const char *fs, const char *base_guid, char *snap_name, size_t len) {
    if (!base_guid || !base_guid[0]) return ZEP_ERR_NOT_FOUND;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zfs list -Hp -t snapshot -o name,guid '%s' 2>/dev/null", fs);

    FILE *p = popen(cmd, "r");
    if (!p) return ZEP_ERR_ZFS;

    char line[1024];
    while (fgets(line, sizeof(line), p)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        char *guid_str = tab + 1;
        size_t glen = strlen(guid_str);
        while (glen > 0 && (guid_str[glen - 1] == '\n' || guid_str[glen - 1] == '\r'))
            guid_str[--glen] = '\0';
        if (strcmp(guid_str, base_guid) == 0) {
            size_t sl = strlen(line);
            if (sl >= len) sl = len - 1;
            memcpy(snap_name, line, sl);
            snap_name[sl] = '\0';
            pclose(p);
            return ZEP_ERR_OK;
        }
    }
    pclose(p);
    return ZEP_ERR_NOT_FOUND;
}

err_t pipeline_push(const zep_config_t *cfg,
                    const http_config_t *http_cfg,
                    const char *fs, const char *label) {
    char base_guid[ZEP_MAX_GUID_LEN] = {0};
    char snap_name[ZEP_MAX_SNAPSHOT_NAME];
    char guid[ZEP_MAX_GUID_LEN];
    char base_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
    char created[32];
    snapshot_meta_t meta;
    memset(&meta, 0, sizeof(meta));

    if (!cfg->node_name[0]) {
        fprintf(stderr, "error: node_name not configured\n");
        return ZEP_ERR_DB;
    }
    if (!http_cfg->server_url[0]) {
        fprintf(stderr, "error: server_url not configured\n");
        return ZEP_ERR_DB;
    }

    zfs_get_latest_guid(fs, base_guid, sizeof(base_guid));

    err_t ret = zfs_snapshot_create(fs, label, snap_name, sizeof(snap_name));
    if (ret != ZEP_ERR_OK) {
        fprintf(stderr, "push: failed to create snapshot\n");
        return ret;
    }
    printf("Created snapshot: %s\n", snap_name);

    ret = zfs_get_snapshot_guid(snap_name, guid, sizeof(guid));
    if (ret != ZEP_ERR_OK) {
        fprintf(stderr, "push: failed to get snapshot guid\n");
        zfs_destroy_snapshot(snap_name);
        return ret;
    }

    if (base_guid[0] && strcmp(base_guid, guid) == 0) {
        base_guid[0] = '\0';
    }

    if (base_guid[0]) {
        ret = find_base_snapshot(fs, base_guid, base_snap, sizeof(base_snap));
        if (ret != ZEP_ERR_OK) {
            fprintf(stderr, "push: base snapshot not found for guid %s\n", base_guid);
            base_guid[0] = '\0';
            base_snap[0] = '\0';
        }
    }

    iso8601_now(created, sizeof(created));

    time_t now = time(NULL);
    uint32_t inv = zep_invert_ts(now);
    char prefix[ZEP_MAX_PATH];
    snprintf(prefix, sizeof(prefix), "%010u-%s", inv, guid);

    FILE *send_fp = NULL;
    ret = zfs_send_open(fs, base_snap[0] ? base_snap : NULL, snap_name,
                        cfg->send_all_snap,
                        cfg->send_options[0] ? cfg->send_options : NULL,
                        cfg->pipe_zip_cmd, cfg->pipe_send_buf_cmd,
                        &send_fp);
    if (ret != ZEP_ERR_OK) {
        zfs_destroy_snapshot(snap_name);
        return ret;
    }

    printf("Sending %s %s base...\n", snap_name, base_snap[0] ? "incremental" : "full");

    size_t chunk_size = cfg->chunk_size;
    unsigned char *buf = malloc(chunk_size);
    if (!buf) {
        zfs_send_close(send_fp);
        zfs_destroy_snapshot(snap_name);
        return ZEP_ERR_SYS;
    }

    #define MAX_BLOBS 65536
    blob_info_t *blobs = calloc(MAX_BLOBS, sizeof(blob_info_t));
    if (!blobs) {
        free(buf);
        zfs_send_close(send_fp);
        zfs_destroy_snapshot(snap_name);
        return ZEP_ERR_SYS;
    }

    int blob_count = 0;
    uint64_t stream_size = 0;

    while (1) {
        size_t nread = fread(buf, 1, chunk_size, send_fp);
        if (nread == 0) break;

        sha256_hex(buf, nread, blobs[blob_count].sha256);
        blobs[blob_count].size = nread;
        snprintf(blobs[blob_count].part, sizeof(blobs[blob_count].part), "%04d", blob_count);

        ret = http_put_blob(http_cfg, cfg->node_name, prefix,
                            blob_count, buf, nread);
        if (ret != ZEP_ERR_OK) {
            fprintf(stderr, "push: failed to upload blob %d\n", blob_count);
            break;
        }

        stream_size += nread;
        blob_count++;
        printf("  blob %04d: %zu bytes  sha256=%s\n", blob_count - 1, nread, blobs[blob_count - 1].sha256);

        if (blob_count >= MAX_BLOBS) {
            fprintf(stderr, "push: max blobs exceeded\n");
            ret = ZEP_ERR_SYS;
            break;
        }
    }
    free(buf);
    zfs_send_close(send_fp);

    if (ret != ZEP_ERR_OK || blob_count == 0) {
        free(blobs);
        zfs_destroy_snapshot(snap_name);
        return ret != ZEP_ERR_OK ? ret : ZEP_ERR_ZFS;
    }

    snprintf(meta.snapshot, sizeof(meta.snapshot), "%s", snap_name);
    snprintf(meta.guid, sizeof(meta.guid), "%s", guid);
    snprintf(meta.base_guid, sizeof(meta.base_guid), "%s", base_guid);
    snprintf(meta.label, sizeof(meta.label), "%s", label);
    snprintf(meta.created, sizeof(meta.created), "%s", created);
    snprintf(meta.host, sizeof(meta.host), "%s", cfg->node_name);
    meta.stream_size = stream_size;
    meta.blob_count = blob_count;
    meta.blobs = blobs;

    ret = http_put_meta(http_cfg, cfg->node_name, prefix, &meta);
    if (ret != ZEP_ERR_OK) {
        fprintf(stderr, "push: failed to upload meta.json\n");
        free(blobs);
        zfs_destroy_snapshot(snap_name);
        return ret;
    }

    printf("Push complete: %s  guid=%s  blobs=%d  size=%lu  prefix=%s\n",
           snap_name, guid, blob_count, (unsigned long)stream_size, prefix);

    free(blobs);
    return ZEP_ERR_OK;
}

err_t pipeline_pull(const zep_config_t *cfg,
                    const http_config_t *http_cfg,
                    const char *fs, const char *donor_node) {
    if (!http_cfg->server_url[0]) {
        fprintf(stderr, "error: server_url not configured\n");
        return ZEP_ERR_DB;
    }

    const char *node = donor_node && donor_node[0] ? donor_node : cfg->node_name;

    char local_guid[ZEP_MAX_GUID_LEN] = {0};
    zfs_get_latest_guid(fs, local_guid, sizeof(local_guid));

    char **prefixes = NULL;
    int prefix_count = 0;
    err_t ret = http_list_snapshots(http_cfg, node, 20, &prefixes, &prefix_count);
    if (ret != ZEP_ERR_OK) return ret;

    if (prefix_count == 0) {
        printf("No snapshots available from node '%s'\n", node);
        storage_free_list(prefixes, prefix_count);
        return ZEP_ERR_OK;
    }

    for (int i = prefix_count - 1; i >= 0; i--) {
        snapshot_meta_t meta;
        memset(&meta, 0, sizeof(meta));

        ret = http_get_meta(http_cfg, node, prefixes[i], &meta);
        if (ret != ZEP_ERR_OK) {
            fprintf(stderr, "pull: failed to read meta for %s\n", prefixes[i]);
            continue;
        }

        if (strcmp(meta.guid, local_guid) == 0) {
            storage_meta_free(&meta);
            continue;
        }

        int can_pull = (!local_guid[0] && !meta.base_guid[0])
                    || (strcmp(local_guid, meta.base_guid) == 0);
        if (!can_pull) {
            storage_meta_free(&meta);
            continue;
        }

        if (!meta.base_guid[0]) {
            char cmd[ZEP_MAX_PATH];
            snprintf(cmd, sizeof(cmd), "zfs set mountpoint=none '%s' 2>/dev/null", fs);
            system(cmd);
        }

        printf("Pulling %s  guid=%s  blobs=%d  size=%lu\n",
               meta.snapshot, meta.guid, meta.blob_count, (unsigned long)meta.stream_size);

        FILE *recv_fp = NULL;
        ret = zfs_recv_open(fs, meta.snapshot,
                            cfg->recv_options[0] ? cfg->recv_options : NULL,
                            cfg->pipe_unzip_cmd, cfg->pipe_recv_buf_cmd,
                            &recv_fp);
        if (ret != ZEP_ERR_OK) {
            fprintf(stderr, "pull: failed to open zfs recv\n");
            storage_meta_free(&meta);
            continue;
        }

        int ok = 1;
        for (int b = 0; b < meta.blob_count && ok; b++) {
            void *data = NULL;
            size_t len = 0;
                ret = http_get_blob(http_cfg, node, prefixes[i], b, &data, &len);
            if (ret != ZEP_ERR_OK) {
                fprintf(stderr, "pull: failed to read blob %d\n", b);
                ok = 0;
                break;
            }

            char computed[65];
            sha256_hex(data, len, computed);
            if (strcmp(computed, meta.blobs[b].sha256) != 0) {
                fprintf(stderr, "pull: checksum mismatch for blob %d\n  expected: %s\n  got:      %s\n",
                        b, meta.blobs[b].sha256, computed);
                free(data);
                ok = 0;
                break;
            }

            printf("  blob %04d: %zu bytes  sha256=%s OK\n", b, len, computed);

            size_t written = fwrite(data, 1, len, recv_fp);
            free(data);
            if (written != len) {
                fprintf(stderr, "pull: failed to write data to zfs recv\n");
                ok = 0;
                break;
            }
        }

        zfs_recv_close(recv_fp);

        if (ok) {
            zfs_get_latest_guid(fs, local_guid, sizeof(local_guid));
            printf("Pull complete: %s\n", meta.snapshot);
        }
        storage_meta_free(&meta);
    }

    storage_free_list(prefixes, prefix_count);
    return ZEP_ERR_OK;
}

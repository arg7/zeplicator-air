/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "pipeline.h"
#include "storage.h"
#include "zfs.h"
#include "http.h"
#include "db.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <cjson/cJSON.h>

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

err_t pipeline_reverse_fs(const char *mapping, const char *local_fs,
                          char *cluster_fs, size_t len) {
    if (!mapping || !local_fs) return ZEP_ERR_NOT_FOUND;
    const char *p = mapping;
    while (*p) {
        const char *colon = strchr(p, ':');
        if (!colon) break;
        const char *start = colon + 1;
        const char *comma = strchr(colon, ',');
        const char *end = comma ? comma : start + strlen(start);
        const char *paren = strchr(start, '(');
        size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
        if (strlen(local_fs) == n && strncmp(start, local_fs, n) == 0) {
            size_t cf_len = (size_t)(colon - p);
            if (cf_len >= len) cf_len = len - 1;
            memcpy(cluster_fs, p, cf_len);
            cluster_fs[cf_len] = '\0';
            return ZEP_ERR_OK;
        }
        p = comma ? comma + 1 : colon + strlen(colon);
    }
    return ZEP_ERR_NOT_FOUND;
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
                    const char *fs, const char *label,
                    const char *cluster_fs, sqlite3 *db) {
    char base_guid[ZEP_MAX_GUID_LEN] = {0};
    char snap_name[ZEP_MAX_SNAPSHOT_NAME];
    char guid[ZEP_MAX_GUID_LEN];
    char base_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
    char created[32];
    char resume_token[ZEP_MAX_LINE] = {0};
    int chunk_start = 0;
    int prev_blob_count = 0;
    uint64_t prev_stream_size = 0;
    blob_info_t *prev_blobs = NULL;
    int is_resume = 0;
    int resume_done = 0;
    snapshot_meta_t meta;
    memset(&meta, 0, sizeof(meta));

    if (!cfg->node_name[0]) {
        zep_log( "error: node_name not configured\n");
        return ZEP_ERR_DB;
    }
    if (!http_cfg->server_url[0]) {
        zep_log( "error: server_url not configured\n");
        return ZEP_ERR_DB;
    }

    /* ── check for interrupted push (resume) ── */
    if (cfg->resume && db) {
        char state_key[320];
        snprintf(state_key, sizeof(state_key), "push_state_%s_%s",
                 cluster_fs ? cluster_fs : fs, label);
        char state_buf[ZEP_MAX_LINE * 2];
        if (db_config_get(db, state_key, state_buf, sizeof(state_buf)) == ZEP_ERR_OK
            && state_buf[0]) {
            char *save = NULL;
            char *s = strdup(state_buf);
            if (!s) goto new_push;
            char *tok = strtok_r(s, ":", &save);
            char stored_prefix[ZEP_MAX_PATH] = {0};
            char stored_snap[ZEP_MAX_SNAPSHOT_NAME] = {0};
            char stored_base[ZEP_MAX_SNAPSHOT_NAME] = {0};
            if (tok) snprintf(stored_prefix, sizeof(stored_prefix), "%s", tok);
            tok = strtok_r(NULL, ":", &save);
            if (tok) snprintf(stored_snap, sizeof(stored_snap), "%s", tok);
            tok = strtok_r(NULL, ":", &save);
            if (tok && tok[0]) snprintf(stored_base, sizeof(stored_base), "%s", tok);
            free(s);

            if (stored_prefix[0] && stored_snap[0]) {
                char *status_url = NULL;
                if (asprintf(&status_url, "/v1/nodes/%s/snapshots/%s/status",
                             cfg->node_name, stored_prefix) < 0)
                    goto new_push;
                char *status_json = http_get_json(http_cfg, status_url);
                free(status_url);

                if (status_json) {
                    cJSON *status_obj = cJSON_Parse(status_json);
                    free(status_json);
                    if (status_obj) {
                        cJSON *comp = cJSON_GetObjectItem(status_obj, "complete");
                        if (cJSON_IsTrue(comp)) {
                            cJSON_Delete(status_obj);
                            db_config_set(db, state_key, "");
                            goto new_push;
                        }
                        cJSON *rt = cJSON_GetObjectItem(status_obj, "resume_token");
                        cJSON *cs = cJSON_GetObjectItem(status_obj, "chunk_start");
                        cJSON *pc = cJSON_GetObjectItem(status_obj, "previous_count");
                        cJSON *ps = cJSON_GetObjectItem(status_obj, "previous_size");
                        cJSON *pb = cJSON_GetObjectItem(status_obj, "previous_blobs");
                        if (rt && cJSON_IsString(rt) && rt->valuestring[0])
                            snprintf(resume_token, sizeof(resume_token), "%s", rt->valuestring);
                        if (cs && cJSON_IsNumber(cs))
                            chunk_start = cs->valueint;
                        if (pc && cJSON_IsNumber(pc))
                            prev_blob_count = pc->valueint;
                        if (ps && cJSON_IsNumber(ps))
                            prev_stream_size = (uint64_t)ps->valuedouble;
                        if (pb && cJSON_IsArray(pb) && prev_blob_count > 0) {
                            prev_blobs = calloc((size_t)prev_blob_count, sizeof(blob_info_t));
                            if (prev_blobs) {
                                for (int i = 0; i < prev_blob_count; i++) {
                                    cJSON *item = cJSON_GetArrayItem(pb, i);
                                    if (!item) continue;
                                    cJSON *ip = cJSON_GetObjectItem(item, "part");
                                    cJSON *is = cJSON_GetObjectItem(item, "size");
                                    cJSON *ih = cJSON_GetObjectItem(item, "sha256");
                                    if (ip && cJSON_IsNumber(ip))
                                        snprintf(prev_blobs[i].part, sizeof(prev_blobs[i].part),
                                                 "%04d", ip->valueint);
                                    if (is && cJSON_IsNumber(is))
                                        prev_blobs[i].size = (size_t)is->valuedouble;
                                    if (ih && cJSON_IsString(ih))
                                        snprintf(prev_blobs[i].sha256, sizeof(prev_blobs[i].sha256),
                                                 "%s", ih->valuestring);
                                }
                            }
                        }
                        cJSON_Delete(status_obj);
                        is_resume = 1;
                    }
                }

                if (is_resume) {
                    snprintf(snap_name, sizeof(snap_name), "%s", stored_snap);
                    snprintf(base_snap, sizeof(base_snap), "%s", stored_base);
                    zfs_get_snapshot_guid(stored_snap, guid, sizeof(guid));
                    zfs_get_latest_guid(fs, base_guid, sizeof(base_guid));
                    if (base_guid[0] && strcmp(base_guid, guid) == 0)
                        base_guid[0] = '\0';
                    iso8601_now(created, sizeof(created));
                    goto skip_snapshot;
                }
            }
        }
    }

new_push:
    zfs_get_latest_guid(fs, base_guid, sizeof(base_guid));

    {
        err_t ret = zfs_snapshot_create(fs, label, snap_name, sizeof(snap_name));
        if (ret != ZEP_ERR_OK) {
        zep_log( "push: failed to create snapshot\n");
        free(prev_blobs);
        return ret;
    }
    printf("Created snapshot: %s\n", snap_name);

    ret = zfs_get_snapshot_guid(snap_name, guid, sizeof(guid));
    if (ret != ZEP_ERR_OK) {
        zep_log( "push: failed to get snapshot guid\n");
        zfs_destroy_snapshot(snap_name);
        free(prev_blobs);
        return ret;
    }

    if (base_guid[0] && strcmp(base_guid, guid) == 0)
        base_guid[0] = '\0';

    if (base_guid[0]) {
        ret = find_base_snapshot(fs, base_guid, base_snap, sizeof(base_snap));
        if (ret != ZEP_ERR_OK) {
            zep_log( "push: base snapshot not found for guid %s\n", base_guid);
            base_guid[0] = '\0';
            base_snap[0] = '\0';
        }
    }
    }

    iso8601_now(created, sizeof(created));

skip_snapshot:
    {
    char prefix[ZEP_MAX_PATH];
    if (is_resume) {
        char state_key[320];
        snprintf(state_key, sizeof(state_key), "push_state_%s_%s",
                 cluster_fs ? cluster_fs : fs, label);
        char state_buf[ZEP_MAX_LINE * 2];
        if (db && db_config_get(db, state_key, state_buf, sizeof(state_buf)) == ZEP_ERR_OK) {
            char *save = NULL, *st = strdup(state_buf);
            if (st) {
                char *tok = strtok_r(st, ":", &save);
                if (tok) snprintf(prefix, sizeof(prefix), "%s", tok);
                free(st);
            }
        }
        if (!prefix[0]) {
            time_t now = time(NULL);
            uint32_t inv = zep_invert_ts(now);
            snprintf(prefix, sizeof(prefix), "%010u-%s", inv, guid);
        }
    } else {
        time_t now = time(NULL);
        uint32_t inv = zep_invert_ts(now);
        snprintf(prefix, sizeof(prefix), "%010u-%s", inv, guid);
    }

    FILE *send_fp = NULL;
    err_t ret = zfs_send_open(fs, base_snap[0] ? base_snap : NULL, snap_name,
                        cfg->send_all_snap,
                        cfg->send_options[0] ? cfg->send_options : NULL,
                        NULL, cfg->push_buf_cmd,
                        resume_token[0] ? resume_token : NULL,
                        cfg->debug_inject_zfs_pipeline_cmd, &send_fp);
    if (ret != ZEP_ERR_OK) {
        if (!is_resume) zfs_destroy_snapshot(snap_name);
        free(prev_blobs);
        return ret;
    }

    printf("Sending %s %s base...\n", snap_name,
           base_snap[0] ? (is_resume ? "resume" : "incremental") : "full");

    size_t chunk_size = cfg->chunk_size;
    unsigned char *buf = malloc(chunk_size);
    if (!buf) {
        zfs_send_close(send_fp);
        if (!is_resume) zfs_destroy_snapshot(snap_name);
        free(prev_blobs);
        return ZEP_ERR_SYS;
    }

    #define MAX_BLOBS 65536
    blob_info_t *blobs = calloc(MAX_BLOBS, sizeof(blob_info_t));
    if (!blobs) {
        free(buf);
        zfs_send_close(send_fp);
        if (!is_resume) zfs_destroy_snapshot(snap_name);
        free(prev_blobs);
        return ZEP_ERR_SYS;
    }

    int blob_count = 0;
    uint64_t stream_size = 0;

    while (1) {
        size_t nread = fread(buf, 1, chunk_size, send_fp);
        if (nread == 0) break;

        char tmpname[] = "/tmp/zep-push-XXXXXX";
        int fd = mkstemp(tmpname);
        if (fd < 0) { ret = ZEP_ERR_SYS; break; }
        {
            size_t wr = 0;
            while (wr < nread) {
                ssize_t nw = write(fd, (const char *)buf + wr, nread - wr);
                if (nw <= 0) break;
                wr += (size_t)nw;
            }
        }
        close(fd);
        if (ret != ZEP_ERR_OK) { unlink(tmpname); break; }

        char comp_cmd[4096];
        if (cfg->push_zip_cmd[0])
            snprintf(comp_cmd, sizeof(comp_cmd), "%s '%s' 2>/dev/null",
                     cfg->push_zip_cmd, tmpname);
        else
            snprintf(comp_cmd, sizeof(comp_cmd), "cat '%s'", tmpname);

        FILE *comp_fp = popen(comp_cmd, "r");
        if (!comp_fp) { unlink(tmpname); ret = ZEP_ERR_SYS; break; }

        size_t comp_cap = nread + nread / 8 + 1024;
        unsigned char *comp_buf = malloc(comp_cap);
        if (!comp_buf) { pclose(comp_fp); unlink(tmpname); ret = ZEP_ERR_SYS; break; }
        size_t comp_len = 0;
        while (1) {
            if (comp_len + 65536 > comp_cap) {
                comp_cap *= 2;
                unsigned char *nb = realloc(comp_buf, comp_cap);
                if (!nb) { free(comp_buf); pclose(comp_fp); unlink(tmpname); ret = ZEP_ERR_SYS; break; }
                comp_buf = nb;
            }
            size_t nr = fread(comp_buf + comp_len, 1,
                              comp_cap - comp_len - 1, comp_fp);
            if (nr == 0) break;
            comp_len += nr;
        }
        int comp_rc = pclose(comp_fp);
        unlink(tmpname);
        if (ret != ZEP_ERR_OK) { free(comp_buf); break; }
        if (comp_rc != 0) { free(comp_buf); zep_log( "push: compression failed\n"); ret = ZEP_ERR_ZFS; break; }

        sha256_hex(comp_buf, comp_len, blobs[blob_count].sha256);
        blobs[blob_count].size = comp_len;
        snprintf(blobs[blob_count].part, sizeof(blobs[blob_count].part),
                 "%04d", chunk_start + blob_count);

        ret = http_put_blob(http_cfg, cfg->node_name, prefix,
                            chunk_start + blob_count, comp_buf, comp_len);
        free(comp_buf);
        if (ret != ZEP_ERR_OK) {
            zep_log( "push: failed to upload blob %d\n", chunk_start + blob_count);
            break;
        }

        stream_size += comp_len;
        blob_count++;
        printf("  blob %04d: %zu -> %zu bytes  sha256=%s\n",
               chunk_start + blob_count - 1, nread, comp_len,
               blobs[blob_count - 1].sha256);

        if (blob_count >= MAX_BLOBS) {
            zep_log( "push: max blobs exceeded\n");
            ret = ZEP_ERR_SYS;
            break;
        }
    }
    free(buf);
    {
        int send_rc = zfs_send_close(send_fp);
        send_fp = NULL;
        int send_exit = WIFEXITED(send_rc) ? WEXITSTATUS(send_rc) : -1;
        if (send_rc != 0 && ret == ZEP_ERR_OK) {
            if (is_resume && send_exit == 255) {
                zep_log("push: resume send complete (nothing more)\n");
                resume_done = 1;
            } else {
                zep_log("push: zfs send exited with code %d\n", send_rc);
                ret = ZEP_ERR_ZFS;
            }
        }
    }

    if ((ret != ZEP_ERR_OK || blob_count == 0) && !resume_done) {
        free(blobs);
        if (!is_resume && !(cfg->resume && db))
            zfs_destroy_snapshot(snap_name);
        /* save push state so next cycle can resume */
        if (cfg->resume && db) {
            char state_key[320], state_val[ZEP_MAX_LINE * 2];
            snprintf(state_key, sizeof(state_key), "push_state_%s_%s",
                     cluster_fs ? cluster_fs : fs, label);
            snprintf(state_val, sizeof(state_val), "%s:%s:%s",
                     prefix, snap_name, base_snap);
            db_config_set(db, state_key, state_val);
        }
        free(prev_blobs);
        return ret != ZEP_ERR_OK ? ret : ZEP_ERR_ZFS;
    }

    /* merge previous session blobs with this session */
    {
        int total_blob_count = prev_blob_count + blob_count;
        uint64_t total_stream_size = prev_stream_size + stream_size;
        blob_info_t *all_blobs = calloc((size_t)total_blob_count, sizeof(blob_info_t));
        if (!all_blobs) {
            free(blobs);
            if (!is_resume) zfs_destroy_snapshot(snap_name);
            free(prev_blobs);
            return ZEP_ERR_SYS;
        }
        for (int i = 0; i < prev_blob_count; i++)
            memcpy(&all_blobs[i], &prev_blobs[i], sizeof(blob_info_t));
        for (int i = 0; i < blob_count; i++)
            memcpy(&all_blobs[prev_blob_count + i], &blobs[i], sizeof(blob_info_t));

        snprintf(meta.snapshot, sizeof(meta.snapshot), "%s", snap_name);
        snprintf(meta.guid, sizeof(meta.guid), "%s", guid);
        snprintf(meta.base_guid, sizeof(meta.base_guid), "%s", base_guid);
        snprintf(meta.label, sizeof(meta.label), "%s", label);
        snprintf(meta.cluster_fs, sizeof(meta.cluster_fs), "%s", cluster_fs ? cluster_fs : "");
        snprintf(meta.created, sizeof(meta.created), "%s", created);
        snprintf(meta.host, sizeof(meta.host), "%s", cfg->node_name);
        meta.stream_size = total_stream_size;
        meta.blob_count = total_blob_count;
        meta.blobs = all_blobs;

        ret = http_put_meta(http_cfg, cfg->node_name, prefix, &meta);
        if (ret != ZEP_ERR_OK) {
            zep_log( "push: failed to upload meta.json\n");
            free(all_blobs);
            free(blobs);
            free(prev_blobs);
            /* save push state so next cycle can resume */
            if (cfg->resume && db) {
                char state_key[320], state_val[ZEP_MAX_LINE * 2];
                snprintf(state_key, sizeof(state_key), "push_state_%s_%s",
                         cluster_fs ? cluster_fs : fs, label);
                snprintf(state_val, sizeof(state_val), "%s:%s:%s",
                         prefix, snap_name, base_snap);
                db_config_set(db, state_key, state_val);
            }
            return ret;
        }

        printf("Push complete: %s  guid=%s  blobs=%d  size=%lu  prefix=%s\n",
               snap_name, guid, total_blob_count, (unsigned long)total_stream_size, prefix);

        free(all_blobs);
    }

    /* delete push state on success */
    if (cfg->resume && db) {
        char state_key[320];
        snprintf(state_key, sizeof(state_key), "push_state_%s_%s",
                 cluster_fs ? cluster_fs : fs, label);
        db_config_set(db, state_key, "");
    }

    free(blobs);
    free(prev_blobs);
    return ZEP_ERR_OK;
    }
}

err_t pipeline_pull(const zep_config_t *cfg,
                    const http_config_t *http_cfg,
                    const char *fs, const char *donor_node,
                    sqlite3 *db) {
    if (!http_cfg->server_url[0]) {
        zep_log( "error: server_url not configured\n");
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
            zep_log( "pull: failed to read meta for %s\n", prefixes[i]);
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
            if (system(cmd) == -1) {}
        }

        printf("Pulling %s  guid=%s  blobs=%d  size=%lu\n",
               meta.snapshot, meta.guid, meta.blob_count, (unsigned long)meta.stream_size);

        int resume_pull = 0;
        char state_key[320];
        snprintf(state_key, sizeof(state_key), "pull_state_%s_%s", fs, meta.label);

        if (cfg->resume && db) {
            char stored_guid[ZEP_MAX_GUID_LEN];
            int stored_blobs = 0;
            if (db_pull_state_load(db, state_key, stored_guid,
                                   sizeof(stored_guid), &stored_blobs)
                == ZEP_ERR_OK && stored_guid[0]) {
                if (strcmp(stored_guid, meta.guid) == 0) {
                    char token[ZEP_MAX_LINE];
                    if (zfs_get_recv_token(fs, token, sizeof(token))
                        == ZEP_ERR_OK && token[0]) {
                        zep_log("pull: resuming guid=%s blobs_done=%d token=%.20s...\n",
                               stored_guid, stored_blobs, token);
                        int rc = pipeline_resume_request(stored_guid, token, fs);
                        if (rc == 0) {
                            db_pull_state_clear(db, state_key);
                            zfs_get_latest_guid(fs, local_guid,
                                                sizeof(local_guid));
                            printf("Pull resume complete: %s\n", meta.snapshot);
                        } else {
                            zep_log("pull: resume failed rc=%d guid=%s\n",
                                   rc, stored_guid);
                        }
                        storage_meta_free(&meta);
                        continue;
                    } else {
                        db_pull_state_clear(db, state_key);
                        zfs_recv_abort(fs);
                    }
                } else {
                    db_pull_state_clear(db, state_key);
                }
            }
            db_pull_state_save(db, state_key, meta.guid, 0);
            resume_pull = 1;
        }

        FILE *recv_fp = NULL;
        ret = zfs_recv_open(fs, meta.snapshot,
                            cfg->recv_options[0] ? cfg->recv_options : NULL,
                            cfg->pull_unzip_cmd, cfg->pull_buf_cmd,
                            NULL, cfg->debug_inject_zfs_pipeline_cmd,
                            cfg->resume, &recv_fp);
        if (ret != ZEP_ERR_OK) {
            zep_log( "pull: failed to open zfs recv\n");
            storage_meta_free(&meta);
            continue;
        }

        int ok = 1;
        for (int b = 0; b < meta.blob_count && ok; b++) {
            void *data = NULL;
            size_t len = 0;
                ret = http_get_blob(http_cfg, node, prefixes[i], b, &data, &len);
            if (ret != ZEP_ERR_OK) {
                zep_log( "pull: failed to read blob %d\n", b);
                ok = 0;
                break;
            }

            char computed[65];
            sha256_hex(data, len, computed);
            if (strcmp(computed, meta.blobs[b].sha256) != 0) {
                zep_log( "pull: checksum mismatch for blob %d\n  expected: %s\n  got:      %s\n",
                        b, meta.blobs[b].sha256, computed);
                free(data);
                ok = 0;
                break;
            }

            printf("  blob %04d: %zu bytes  sha256=%s OK\n", b, len, computed);

            size_t written = fwrite(data, 1, len, recv_fp);
            free(data);
            if (written != len) {
                zep_log( "pull: failed to write data to zfs recv\n");
                ok = 0;
                break;
            }
            if (resume_pull && db)
                db_pull_state_save(db, state_key, meta.guid, b + 1);
        }

        int recv_rc = zfs_recv_close(recv_fp);
        if (recv_rc != 0 && ok) ok = 0;
        {
            char tok[ZEP_MAX_LINE];
            err_t tr = zfs_get_recv_token(fs, tok, sizeof(tok));
            zep_log("pull: after zfs_recv_close rc=%d ok=%d token_ret=%d token=%.40s...\n",
                   recv_rc, ok, tr, tok[0] ? tok : "(none)");
        }
        (void)recv_rc;

        if (ok) {
            if (resume_pull && db)
                db_pull_state_clear(db, state_key);
            zfs_get_latest_guid(fs, local_guid, sizeof(local_guid));
            printf("Pull complete: %s\n", meta.snapshot);
        }
        storage_meta_free(&meta);
    }

    storage_free_list(prefixes, prefix_count);
    return ZEP_ERR_OK;
}

err_t pipeline_pull_v2(const zep_config_t *cfg,
                       const http_config_t *http_cfg,
                       const char *fs, const char *donor_node,
                       cJSON *snapshots, sqlite3 *db) {
    (void)donor_node;
    if (!http_cfg->server_url[0]) {
        zep_log( "error: server_url not configured\n");
        return ZEP_ERR_DB;
    }
    if (!snapshots || !cJSON_IsArray(snapshots) || cJSON_GetArraySize(snapshots) == 0)
        return ZEP_ERR_OK;

    char local_guid[ZEP_MAX_GUID_LEN] = {0};
    zfs_get_latest_guid(fs, local_guid, sizeof(local_guid));
    zep_log( "pull_v2: local=%s fs=%s snap_count=%d\n",
           local_guid[0] ? local_guid : "(none)", fs,
           cJSON_GetArraySize(snapshots));

    int first_guid = 1;
    cJSON *snap;
    cJSON_ArrayForEach(snap, snapshots) {
        cJSON *g = cJSON_GetObjectItem(snap, "guid");
        cJSON *bg = cJSON_GetObjectItem(snap, "base_guid");
        if (!g || !cJSON_IsString(g)) continue;

        if (local_guid[0] && strcmp(g->valuestring, local_guid) == 0)
            continue;

        int is_full = (!bg->valuestring[0] || strcmp(bg->valuestring, "0") == 0);
        int can_pull = (!local_guid[0] && bg && cJSON_IsString(bg) && is_full)
                     || (bg && cJSON_IsString(bg) && strcmp(local_guid, bg->valuestring) == 0);
        if (first_guid) {
            first_guid = 0;
            zep_log( "pull_v2: first snap guid=%s base=%s can_pull=%d\n",
                   g->valuestring,
                   (bg && cJSON_IsString(bg)) ? bg->valuestring : "(none)",
                   can_pull);
        }
        if (!can_pull) continue;

        if (bg && cJSON_IsString(bg) && is_full) {
            char cmd[ZEP_MAX_PATH];
            snprintf(cmd, sizeof(cmd), "zfs set mountpoint=none '%s' 2>/dev/null", fs);
            if (system(cmd) == -1) {}
        }

        cJSON *blobs = cJSON_GetObjectItem(snap, "blobs");
        int blob_count = blobs ? cJSON_GetArraySize(blobs) : 0;
        if (blob_count == 0) continue;

        char snap_name[ZEP_MAX_SNAPSHOT_NAME] = {0};
        {
            cJSON *sn = cJSON_GetObjectItem(snap, "snapshot");
            if (sn && cJSON_IsString(sn))
                snprintf(snap_name, sizeof(snap_name), "%s", sn->valuestring);
            else
                snprintf(snap_name, sizeof(snap_name), "%s@pull-%s", fs, g->valuestring);
        }

        printf("Pulling guid=%s  blobs=%d\n", g->valuestring, blob_count);

        int resume_pull = 0;
        char state_key[320];
        {
            cJSON *lb = cJSON_GetObjectItem(snap, "label");
            const char *lbl = (lb && cJSON_IsString(lb)) ? lb->valuestring : g->valuestring;
            snprintf(state_key, sizeof(state_key), "pull_state_%s_%s", fs, lbl);
        }

        if (cfg->resume && db) {
            char stored_guid[ZEP_MAX_GUID_LEN];
            int stored_blobs = 0;
            if (db_pull_state_load(db, state_key, stored_guid,
                                   sizeof(stored_guid), &stored_blobs)
                == ZEP_ERR_OK && stored_guid[0]) {
                if (strcmp(stored_guid, g->valuestring) == 0) {
                    char token[ZEP_MAX_LINE];
                    if (zfs_get_recv_token(fs, token, sizeof(token))
                        == ZEP_ERR_OK && token[0]) {
                        zep_log("pull_v2: resuming guid=%s blobs_done=%d\n",
                               stored_guid, stored_blobs);
                        int rc = pipeline_resume_request(stored_guid, token, fs);
                        if (rc == 0) {
                            db_pull_state_clear(db, state_key);
                            zfs_get_latest_guid(fs, local_guid,
                                                sizeof(local_guid));
                            printf("Pull resume complete: guid=%s\n",
                                   g->valuestring);
                        } else {
                            zep_log("pull_v2: resume failed rc=%d guid=%s\n",
                                   rc, stored_guid);
                        }
                        continue;
                    } else {
                        db_pull_state_clear(db, state_key);
                        zfs_recv_abort(fs);
                    }
                } else {
                    db_pull_state_clear(db, state_key);
                }
            }
            db_pull_state_save(db, state_key, g->valuestring, 0);
            resume_pull = 1;
        }

        FILE *recv_fp = NULL;
        err_t ret = zfs_recv_open(fs, snap_name,
                                   cfg->recv_options[0] ? cfg->recv_options : NULL,
                                   cfg->pull_unzip_cmd, cfg->pull_buf_cmd,
                                   NULL, cfg->debug_inject_zfs_pipeline_cmd,
                                   cfg->resume, &recv_fp);
        if (ret != ZEP_ERR_OK) {
            zep_log( "pull_v2: recv_open FAILED fs=%s snap=%s unzip=%s\n",
                   fs, snap_name,
                   cfg->pull_unzip_cmd[0] ? cfg->pull_unzip_cmd : "(none)");
            continue;
        }

        int ok = 1;
        cJSON *b;
        cJSON_ArrayForEach(b, blobs) {
            cJSON *bp = cJSON_GetObjectItem(b, "part");
            cJSON *bh = cJSON_GetObjectItem(b, "sha256");
            if (!bp || !bh || !cJSON_IsString(bh)) continue;

            int part = bp->valueint;
            void *data = NULL;
            size_t len = 0;
            ret = http_get_blob_by_guid(http_cfg, g->valuestring, part, &data, &len);
            if (ret != ZEP_ERR_OK) {
                zep_log( "pull: failed to read blob %d for guid=%s\n", part, g->valuestring);
                ok = 0;
                break;
            }

            char computed[65];
            sha256_hex(data, len, computed);
            if (strcmp(computed, bh->valuestring) != 0) {
                zep_log( "pull: checksum mismatch for blob %d\n  expected: %s\n  got:      %s\n",
                        part, bh->valuestring, computed);
                free(data);
                ok = 0;
                break;
            }

            printf("  blob %04d: %zu bytes  sha256=%s OK\n", part, len, computed);

            size_t written = fwrite(data, 1, len, recv_fp);
            free(data);
            if (written != len) {
                zep_log( "pull: failed to write data to zfs recv\n");
                ok = 0;
                break;
            }
            if (resume_pull && db)
                db_pull_state_save(db, state_key, g->valuestring, part + 1);
        }

        int recv_rc = zfs_recv_close(recv_fp);
        printf("zfs_recv_close returned %d (ok=%d)\n", recv_rc, ok);
        if (recv_rc != 0 && ok) ok = 0;

        if (ok) {
            if (resume_pull && db)
                db_pull_state_clear(db, state_key);
            zfs_get_latest_guid(fs, local_guid, sizeof(local_guid));
            printf("Pull complete: guid=%s\n", g->valuestring);
        }
    }

    return ZEP_ERR_OK;
}

err_t pipeline_resolve_zfs_cmd(const char *cmd, const char *mapping,
                               char *out, size_t out_len) {
    if (!cmd || !mapping || !out || out_len == 0)
        return ZEP_ERR_SYS;
    const char *space = strchr(cmd, ' ');
    if (!space) {
        snprintf(out, out_len, "%s", cmd);
        return ZEP_ERR_OK;
    }
    int pos = (int)(space - cmd);
    memcpy(out, cmd, (size_t)pos);
    out[pos] = '\0';

    if (strcmp(out, "zfs") != 0) {
        snprintf(out, out_len, "%s", cmd);
        return ZEP_ERR_OK;
    }

    char *cmd_copy = strdup(cmd);
    if (!cmd_copy) return ZEP_ERR_SYS;

    int argc = 0;
    char *argv[64];
    char *save = NULL;
    char *tok = strtok_r(cmd_copy, " ", &save);
    while (tok && argc < 63) {
        argv[argc++] = tok;
        tok = strtok_r(NULL, " ", &save);
    }

    if (argc < 3) {
        free(cmd_copy);
        snprintf(out, out_len, "%s", cmd);
        return ZEP_ERR_OK;
    }

    int fs_idx = argc - 1;
    char fs_buf[ZEP_MAX_SNAPSHOT_NAME];
    const char *fs_arg = argv[fs_idx];

    char base_fs[ZEP_MAX_SNAPSHOT_NAME];
    const char *at = strchr(fs_arg, '@');
    if (at) {
        size_t n = (size_t)(at - fs_arg);
        if (n >= sizeof(base_fs)) n = sizeof(base_fs) - 1;
        memcpy(base_fs, fs_arg, n);
        base_fs[n] = '\0';
    } else {
        snprintf(base_fs, sizeof(base_fs), "%s", fs_arg);
    }

    char local_fs[ZEP_MAX_SNAPSHOT_NAME];
    if (pipeline_resolve_fs(base_fs, mapping, local_fs, sizeof(local_fs))
        == ZEP_ERR_OK) {
        if (at)
            snprintf(fs_buf, sizeof(fs_buf), "%s%s", local_fs, at);
        else
            snprintf(fs_buf, sizeof(fs_buf), "%s", local_fs);
        argv[fs_idx] = fs_buf;
    }

    size_t off = 0;
    for (int i = 0; i < argc; i++) {
        int n = snprintf(out + off, out_len - off, "%s%s",
                         i > 0 ? " " : "", argv[i]);
        if (n < 0 || (size_t)n >= out_len - off) break;
        off += (size_t)n;
    }

    free(cmd_copy);
    return ZEP_ERR_OK;
}

err_t pipeline_build_pipe_send(const char *command, int compress, int buffer,
                               const zep_config_t *cfg,
                               char *out, size_t out_len) {
    if (!command || !cfg || !out || out_len == 0) return ZEP_ERR_SYS;
    size_t off = 0;
    int n = snprintf(out, out_len, "%s", command);
    if (n < 0) return ZEP_ERR_SYS;
    off = (size_t)n;

    if (buffer && cfg->push_buf_cmd[0]) {
        n = snprintf(out + off, out_len - off, " | %s",
                     cfg->push_buf_cmd);
        if (n < 0 || (size_t)n >= out_len - off) return ZEP_ERR_SYS;
        off += (size_t)n;
    }
    if (compress && cfg->push_zip_cmd[0]) {
        n = snprintf(out + off, out_len - off, " | %s",
                     cfg->push_zip_cmd);
        if (n < 0 || (size_t)n >= out_len - off) return ZEP_ERR_SYS;
        off += (size_t)n;
    }
    return ZEP_ERR_OK;
}

err_t pipeline_build_pipe_recv(const char *command, int compress, int buffer,
                               const zep_config_t *cfg,
                               char *out, size_t out_len) {
    if (!command || !cfg || !out || out_len == 0) return ZEP_ERR_SYS;
    size_t off = 0;

    if (compress && cfg->pull_unzip_cmd[0]) {
        int n = snprintf(out, out_len, "%s", cfg->pull_unzip_cmd);
        if (n < 0) return ZEP_ERR_SYS;
        off = (size_t)n;
    }
    if (buffer && cfg->pull_buf_cmd[0]) {
        int n = snprintf(out + off, out_len - off, "%s%s",
                         off > 0 ? " | " : "",
                         cfg->pull_buf_cmd);
        if (n < 0 || (size_t)n >= out_len - off) return ZEP_ERR_SYS;
        off += (size_t)n;
    }
    int n = snprintf(out + off, out_len - off, "%s%s",
                     off > 0 ? " | " : "", command);
    if (n < 0 || (size_t)n >= out_len - off) return ZEP_ERR_SYS;
    return ZEP_ERR_OK;
}

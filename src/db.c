/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "db.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

#define SQL_BUSY_TIMEOUT 5000

err_t db_open(const char *path, sqlite3 **db) {
    int rc = sqlite3_open(path, db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_open: %s\n", sqlite3_errmsg(*db));
        return ZEP_ERR_DB;
    }
    sqlite3_busy_timeout(*db, SQL_BUSY_TIMEOUT);
    sqlite3_exec(*db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(*db, "PRAGMA foreign_keys=ON", NULL, NULL, NULL);
    return ZEP_ERR_OK;
}

void db_close(sqlite3 *db) {
    if (db) sqlite3_close(db);
}

err_t db_init_tables(sqlite3 *db) {
    const char *sql =
        "CREATE TABLE IF NOT EXISTS config ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS pushed ("
        "  guid        TEXT PRIMARY KEY,"
        "  snapshot    TEXT NOT NULL,"
        "  base_guid   TEXT,"
        "  label       TEXT NOT NULL,"
        "  created     TEXT NOT NULL,"
        "  pushed_at   TEXT NOT NULL DEFAULT (datetime('now')),"
        "  blob_count  INTEGER NOT NULL,"
        "  stream_size INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS pulled ("
        "  guid        TEXT PRIMARY KEY,"
        "  snapshot    TEXT NOT NULL,"
        "  base_guid   TEXT,"
        "  label       TEXT NOT NULL,"
        "  created     TEXT NOT NULL,"
        "  pulled_at   TEXT NOT NULL DEFAULT (datetime('now')),"
        "  donor_node  TEXT NOT NULL,"
        "  blob_count  INTEGER NOT NULL,"
        "  stream_size INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS auth ("
        "  cn          TEXT PRIMARY KEY,"
        "  fingerprint TEXT NOT NULL UNIQUE,"
        "  pem         TEXT NOT NULL,"
        "  role        TEXT NOT NULL DEFAULT 'client' CHECK(role IN ('server','admin','master','client')),"
        "  cluster     TEXT NOT NULL DEFAULT '',"
        "  mapping     TEXT NOT NULL DEFAULT '',"
        "  last_ack_guid TEXT DEFAULT '',"
        "  last_ack_at   TEXT DEFAULT '',"
        "  suspended     INTEGER NOT NULL DEFAULT 0,"
        "  pipe_active   INTEGER NOT NULL DEFAULT 0,"
        "  created_at    TEXT NOT NULL DEFAULT (datetime('now'))"
        ");"
        "CREATE TABLE IF NOT EXISTS snapshots ("
        "  cluster      TEXT NOT NULL,"
        "  node         TEXT NOT NULL,"
        "  guid         TEXT NOT NULL,"
        "  base_guid    TEXT NOT NULL DEFAULT '',"
        "  snapshot     TEXT NOT NULL,"
        "  label        TEXT NOT NULL DEFAULT '',"
        "  cluster_fs   TEXT NOT NULL DEFAULT '',"
        "  status       TEXT NOT NULL DEFAULT 'pending',"
        "  blob_count   INTEGER NOT NULL DEFAULT 0,"
        "  blob_size    INTEGER NOT NULL DEFAULT 0,"
        "  direction    TEXT NOT NULL DEFAULT 'push',"
        "  storage_base TEXT NOT NULL,"
        "  recorded_at  TEXT NOT NULL DEFAULT (datetime('now')),"
        "  UNIQUE(node, guid)"
        ");"
        "CREATE TABLE IF NOT EXISTS snapshot_upload ("
         "  guid          TEXT PRIMARY KEY,"
         "  node          TEXT NOT NULL DEFAULT '',"
         "  bytes_received BIGINT NOT NULL DEFAULT 0,"
         "  resume_token  TEXT NOT NULL DEFAULT '',"
         "  complete      INTEGER NOT NULL DEFAULT 0,"
         "  created_at    TEXT NOT NULL DEFAULT (datetime('now'))"
         ");";
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_init_tables: %s\n", err ? err : "unknown");
        sqlite3_free(err);
        return ZEP_ERR_DB;
    }
    sqlite3_exec(db, "ALTER TABLE auth ADD COLUMN pipe_active INTEGER NOT NULL DEFAULT 0",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE auth ADD COLUMN last_err TEXT DEFAULT ''",
                 NULL, NULL, NULL);
    /* One-shot migration: add created_at to snapshots if not exists */
    {
        char *merr = NULL;
        sqlite3_exec(db, "ALTER TABLE snapshots ADD COLUMN created_at TEXT",
                     NULL, NULL, &merr);
        if (merr) sqlite3_free(merr); /* ignore "duplicate column" */
    }
    return ZEP_ERR_OK;
}

err_t db_config_get(sqlite3 *db, const char *key, char *value, size_t len) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT value FROM config WHERE key = ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    err_t ret = ZEP_ERR_NOT_FOUND;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        snprintf(value, len, "%s", sqlite3_column_text(stmt, 0));
        ret = ZEP_ERR_OK;
    }
    sqlite3_finalize(stmt);
    return ret;
}

err_t db_config_set(sqlite3 *db, const char *key, const char *value) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_config_load(sqlite3 *db, zep_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->chunk_size = ZEP_DEFAULT_CHUNK_SZ;

    db_config_get(db, "cluster",     cfg->cluster,    sizeof(cfg->cluster));
    db_config_get(db, "mapping",     cfg->mapping,    sizeof(cfg->mapping));
    db_config_get(db, "storage_root", cfg->storage_root, sizeof(cfg->storage_root));
    db_config_get(db, "server_url",  cfg->server_url,  sizeof(cfg->server_url));
    db_config_get(db, "node_name",   cfg->node_name,   sizeof(cfg->node_name));
    db_config_get(db, "cert_path",   cfg->cert_path,   sizeof(cfg->cert_path));
    db_config_get(db, "key_path",    cfg->key_path,    sizeof(cfg->key_path));
    db_config_get(db, "ca_path",     cfg->ca_path,     sizeof(cfg->ca_path));
    db_config_get(db, "key_password", cfg->key_password, sizeof(cfg->key_password));
    db_config_get(db, "send_options", cfg->send_options, sizeof(cfg->send_options));
    db_config_get(db, "recv_options", cfg->recv_options, sizeof(cfg->recv_options));
    db_config_get(db, "push_zip_cmd", cfg->push_zip_cmd, sizeof(cfg->push_zip_cmd));
    db_config_get(db, "pull_unzip_cmd", cfg->pull_unzip_cmd, sizeof(cfg->pull_unzip_cmd));
    db_config_get(db, "push_buf_cmd", cfg->push_buf_cmd, sizeof(cfg->push_buf_cmd));
    db_config_get(db, "pull_buf_cmd", cfg->pull_buf_cmd, sizeof(cfg->pull_buf_cmd));
    db_config_get(db, "debug_inject_zfs_pipeline_cmd", cfg->debug_inject_zfs_pipeline_cmd, sizeof(cfg->debug_inject_zfs_pipeline_cmd));
    db_config_get(db, "pipe_allow", cfg->pipe_allow, sizeof(cfg->pipe_allow));

    if (!cfg->pipe_allow[0]) snprintf(cfg->pipe_allow, sizeof(cfg->pipe_allow), "zfs");

    {
        char buf[32];
        if (db_config_get(db, "send_all_snap", buf, sizeof(buf)) == ZEP_ERR_OK)
            cfg->send_all_snap = atoi(buf);
        else cfg->send_all_snap = 0;

        if (db_config_get(db, "chunk_size", buf, sizeof(buf)) == ZEP_ERR_OK) {
            long v = atol(buf);
            if (v > 0) cfg->chunk_size = (size_t)v;
        }

        if (db_config_get(db, "resume", buf, sizeof(buf)) == ZEP_ERR_OK)
            cfg->resume = atoi(buf);
        else cfg->resume = 0;
    }
    return ZEP_ERR_OK;
}


err_t db_cert_store(sqlite3 *db, const char *cn,
                    const char *fingerprint, const char *pem_data,
                    const char *role, const char *cluster,
                    const char *mapping) {
    const char *sql =
        "INSERT OR IGNORE INTO auth (cn, fingerprint, pem, role, cluster, mapping) "
        "VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, cn, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, fingerprint, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, pem_data, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, role, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, cluster, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, mapping, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_cert_lookup(sqlite3 *db, const char *cn,
                     char *fingerprint, size_t flen) {
    const char *sql = "SELECT fingerprint FROM auth WHERE cn = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, cn, -1, SQLITE_STATIC);
    err_t ret = ZEP_ERR_NOT_FOUND;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        snprintf(fingerprint, flen, "%s", sqlite3_column_text(stmt, 0));
        ret = ZEP_ERR_OK;
    }
    sqlite3_finalize(stmt);
    return ret;
}

err_t db_auth_list(sqlite3 *db, char ***names, int *count) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT cn FROM auth WHERE role IN ('master','client') ORDER BY role, cn", -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;

    int cap = 16, cnt = 0;
    char **list = calloc((size_t)cap, sizeof(char *));
    if (!list) return ZEP_ERR_SYS;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (cnt >= cap) {
            cap *= 2;
            char **nl = realloc(list, (size_t)cap * sizeof(char *));
            if (!nl) {
                for (int j = 0; j < cnt; j++) free(list[j]);
                free(list);
                sqlite3_finalize(stmt);
                return ZEP_ERR_SYS;
            }
            list = nl;
        }
        list[cnt++] = strdup((const char *)sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);
    *names = list;
    *count = cnt;
    return ZEP_ERR_OK;
}

err_t db_auth_remove(sqlite3 *db, const char *cn) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM auth WHERE cn = ?", -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, cn, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_auth_get_role_by_fp(sqlite3 *db, const char *fingerprint,
                              char *role, size_t len) {
    const char *sql = "SELECT role FROM auth WHERE fingerprint = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, fingerprint, -1, SQLITE_STATIC);
    err_t ret = ZEP_ERR_NOT_FOUND;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        snprintf(role, len, "%s", sqlite3_column_text(stmt, 0));
        ret = ZEP_ERR_OK;
    }
    sqlite3_finalize(stmt);
    return ret;
}

err_t db_set_suspended(sqlite3 *db, const char *cn, int val) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE auth SET suspended = ? WHERE cn = ?", -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_int(stmt, 1, val);
    sqlite3_bind_text(stmt, 2, cn, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_update_role(sqlite3 *db, const char *cn, const char *new_role) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE auth SET role = ? WHERE cn = ?", -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, new_role, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, cn, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_snapshot_insert(sqlite3 *db, const char *cluster, const char *node,
                         const char *guid, const char *base_guid,
                         const char *snapshot, const char *label,
                         const char *cluster_fs, int blob_count,
                         size_t blob_size, const char *direction,
                         const char *storage_base, const char *status) {
    const char *sql =
        "INSERT OR IGNORE INTO snapshots "
        "(cluster, node, guid, base_guid, snapshot, label, cluster_fs, "
        " status, blob_count, blob_size, direction, storage_base) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, cluster, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, node, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, guid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, base_guid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, snapshot, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, label, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, cluster_fs, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, status ? status : "pending", -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 9, blob_count);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)blob_size);
    sqlite3_bind_text(stmt, 11, direction, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 12, storage_base, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_snapshot_latest_guid(sqlite3 *db, const char *node,
                              const char *direction,
                              char *guid, size_t len) {
    const char *sql =
        "SELECT guid FROM snapshots WHERE node = ?1 AND direction = ?2 "
        "ORDER BY rowid DESC LIMIT 1";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, node, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, direction, -1, SQLITE_STATIC);
    err_t ret = ZEP_ERR_NOT_FOUND;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        snprintf(guid, len, "%s", sqlite3_column_text(stmt, 0));
        ret = ZEP_ERR_OK;
    }
    sqlite3_finalize(stmt);
    return ret;
}

char *db_snapshot_chain_json(sqlite3 *db, const char *cluster,
                              const char *master_cn,
                              const char *client_guid) {
    cJSON *arr = cJSON_CreateArray();

    const char *sql =
        "SELECT guid, base_guid, label, snapshot "
        "FROM snapshots "
        "WHERE node = ?1 AND cluster = ?2 AND direction = 'push' "
        "  AND status = 'verified' "
        "ORDER BY rowid";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        cJSON_Delete(arr);
        return NULL;
    }
    sqlite3_bind_text(stmt, 1, master_cn, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, cluster, -1, SQLITE_STATIC);

    int found = (!client_guid || !client_guid[0]);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *g = (const char *)sqlite3_column_text(stmt, 0);
        if (!found) {
            if (strcmp(g, client_guid) == 0) found = 1;
            continue;
        }
        cJSON *s = cJSON_CreateObject();
        cJSON_AddStringToObject(s, "guid", g);
        cJSON_AddStringToObject(s, "base_guid",
            (const char *)sqlite3_column_text(stmt, 1));
        const char *lb = (const char *)sqlite3_column_text(stmt, 2);
        if (lb && lb[0])
            cJSON_AddStringToObject(s, "label", lb);
        const char *sn = (const char *)sqlite3_column_text(stmt, 3);
        if (sn && sn[0])
            cJSON_AddStringToObject(s, "snapshot", sn);
        cJSON_AddItemToArray(arr, s);
    }
    sqlite3_finalize(stmt);

    int count = cJSON_GetArraySize(arr);
    if (count == 0) {
        cJSON_Delete(arr);
        return NULL;
    }
    char *js = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return js;
}


err_t db_common_ancestor(sqlite3 *db, const char *cluster,
                         char *guid, size_t len) {
    const char *sql =
        "SELECT guid FROM snapshots WHERE cluster = ?1 "
        "GROUP BY guid "
        "HAVING COUNT(DISTINCT node) = (SELECT COUNT(*) FROM auth WHERE cluster = ?1) "
        "ORDER BY MAX(rowid) DESC LIMIT 1";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, cluster, -1, SQLITE_STATIC);
    err_t ret = ZEP_ERR_NOT_FOUND;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        snprintf(guid, len, "%s", sqlite3_column_text(stmt, 0));
        ret = ZEP_ERR_OK;
    }
    sqlite3_finalize(stmt);
    return ret;
}

err_t db_snapshot_delete_node_guid(sqlite3 *db, const char *node,
                                    const char *guid) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM snapshots WHERE node = ? AND guid = ?",
            -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, node, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, guid, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

int db_node_pull_count(sqlite3 *db, const char *cluster, const char *node) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM snapshots "
            "WHERE node = ?1 AND cluster = ?2 AND direction = 'pull'",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(stmt, 1, node, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, cluster, -1, SQLITE_STATIC);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

err_t db_rotation_candidates(sqlite3 *db, const char *cluster,
                              const char *node, const char *mapping,
                              cJSON *cluster_json, cJSON *out) {
    if (!cluster_json) return ZEP_ERR_OK;

    cJSON *pools = cJSON_GetObjectItem(cluster_json, "pools");
    if (!pools) return ZEP_ERR_OK;

    cJSON *pool;
    cJSON_ArrayForEach(pool, pools) {
        cJSON *fs;
        cJSON_ArrayForEach(fs, pool) {
            char cluster_fs[512];
            snprintf(cluster_fs, sizeof(cluster_fs), "%s/%s",
                     pool->string, fs->string);

            cJSON *labels = cJSON_GetObjectItem(fs, "labels");
            if (!labels) continue;

            cJSON *lbl;
            cJSON_ArrayForEach(lbl, labels) {
                int retention = lbl->valueint;
                const char *label = lbl->string;
                if (!label || retention <= 0) continue;

                if (mapping && mapping[0]) {
                    const char *mp = mapping;
                    while (*mp) {
                        const char *colon = strchr(mp, ':');
                        if (!colon) break;

                        if ((size_t)(colon - mp) == strlen(cluster_fs) &&
                            strncmp(mp, cluster_fs, strlen(cluster_fs)) == 0) {

                            const char *comma = strchr(colon, ',');
                            const char *entry_end = comma ? comma :
                                colon + strlen(colon);
                            const char *paren = strchr(colon, '(');
                            const char *cp = paren ? strchr(paren, ')') : NULL;

                            if (paren && cp && cp < entry_end) {
                                const char *lp = paren + 1;
                                while (lp < cp) {
                                    const char *lc = strchr(lp, ':');
                                    const char *le = strchr(lp, ',');
                                    if (!le || le > cp) le = cp;
                                    if (lc && lc < le) {
                                        size_t ln = (size_t)(lc - lp);
                                        if (ln == strlen(label) &&
                                            strncmp(lp, label, ln) == 0) {
                                            int ov = atoi(lc + 1);
                                            if (ov > 0) retention = ov;
                                        }
                                    }
                                    lp = le;
                                    if (*lp == ',') lp++;
                                }
                            }
                            break;
                        }
                        const char *nc = strchr(colon, ',');
                        mp = nc ? nc + 1 : colon + strlen(colon);
                    }
                }

                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(db,
                        "SELECT guid, snapshot FROM snapshots "
                        "WHERE node = ?1 AND cluster_fs = ?2 "
                        "  AND label = ?3 AND cluster = ?4 "
                        "ORDER BY rowid ASC",
                        -1, &st, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(st, 1, node, -1, SQLITE_STATIC);
                    sqlite3_bind_text(st, 2, cluster_fs, -1, SQLITE_STATIC);
                    sqlite3_bind_text(st, 3, label, -1, SQLITE_STATIC);
                    sqlite3_bind_text(st, 4, cluster, -1, SQLITE_STATIC);

                    struct row_s {
                        char guid[ZEP_MAX_GUID_LEN];
                        char snapshot[ZEP_MAX_SNAPSHOT_NAME];
                    } *rows = NULL;
                    int rcount = 0, rcap = 0;

                    while (sqlite3_step(st) == SQLITE_ROW) {
                        if (rcount >= rcap) {
                            rcap = rcap ? rcap * 2 : 32;
                            rows = realloc(rows,
                                (size_t)rcap * sizeof(*rows));
                        }
                        snprintf(rows[rcount].guid,
                            sizeof(rows[rcount].guid), "%s",
                            (const char *)sqlite3_column_text(st, 0));
                        snprintf(rows[rcount].snapshot,
                            sizeof(rows[rcount].snapshot), "%s",
                            (const char *)sqlite3_column_text(st, 1));
                        rcount++;
                    }
                    sqlite3_finalize(st);

                    if (rcount > retention) {
                        int excess = rcount - retention;
                        for (int i = 0; i < excess && i < rcount; i++) {
                            cJSON *obj = cJSON_CreateObject();
                            cJSON_AddStringToObject(obj, "guid",
                                rows[i].guid);
                            cJSON_AddStringToObject(obj, "snapshot",
                                rows[i].snapshot);
                            cJSON_AddStringToObject(obj, "cluster_fs",
                                cluster_fs);
                            cJSON_AddStringToObject(obj, "label",
                                label);
                            cJSON_AddItemToArray(out, obj);
                        }
                    }
                    free(rows);
                }
            }
        }
    }
    return ZEP_ERR_OK;
}

err_t db_upload_get_offset(sqlite3 *db, const char *guid,
                            char *offset_buf, size_t len) {
    if (!offset_buf || !len) return ZEP_ERR_NOT_FOUND;
    offset_buf[0] = '\0';
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT bytes_received FROM snapshot_upload WHERE guid = ?1 AND complete = 0",
            -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, guid, -1, SQLITE_STATIC);
    int found = (sqlite3_step(stmt) == SQLITE_ROW);
    if (found) {
        int64_t bytes = sqlite3_column_int64(stmt, 0);
        snprintf(offset_buf, len, "%ld", (long)bytes);
    }
    sqlite3_finalize(stmt);
    return found ? ZEP_ERR_OK : ZEP_ERR_NOT_FOUND;
}

err_t db_upload_save_token(sqlite3 *db, const char *guid,
                            const char *node, const char *token, int64_t bytes) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO snapshot_upload "
            "(guid, node, bytes_received, resume_token, complete) "
            "VALUES (?1, ?2, ?3, ?4, 0)",
            -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, guid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, node ? node : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, bytes);
    sqlite3_bind_text(stmt, 4, token ? token : "", -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_upload_complete(sqlite3 *db, const char *guid) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM snapshot_upload WHERE guid = ?1",
            -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, guid, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

int db_upload_has_incomplete(sqlite3 *db, const char *node) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM snapshot_upload WHERE node = ?1 AND complete = 0 LIMIT 1",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(stmt, 1, node, -1, SQLITE_STATIC);
    int found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

err_t db_pull_state_save(sqlite3 *db, const char *key,
                         const char *guid, int blobs_done) {
    char val[ZEP_MAX_LINE];
    snprintf(val, sizeof(val), "%s:%d", guid, blobs_done);
    return db_config_set(db, key, val);
}

err_t db_pull_state_load(sqlite3 *db, const char *key,
                         char *guid, size_t guid_len, int *blobs_done) {
    if (guid) guid[0] = '\0';
    if (blobs_done) *blobs_done = 0;
    char val[ZEP_MAX_LINE];
    if (db_config_get(db, key, val, sizeof(val)) != ZEP_ERR_OK || !val[0])
        return ZEP_ERR_NOT_FOUND;

    char *save = NULL;
    char *s = strdup(val);
    if (!s) return ZEP_ERR_SYS;
    char *tok = strtok_r(s, ":", &save);
    if (tok && guid) snprintf(guid, guid_len, "%s", tok);
    tok = strtok_r(NULL, ":", &save);
    if (tok && blobs_done) *blobs_done = atoi(tok);
    free(s);
    return ZEP_ERR_OK;
}

void db_pull_state_clear(sqlite3 *db, const char *key) {
    db_config_set(db, key, "");
}

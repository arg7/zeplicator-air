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
        "CREATE TABLE IF NOT EXISTS cluster_chain ("
        "  cluster_key TEXT NOT NULL,"
        "  toguid      TEXT NOT NULL,"
        "  fromguid    TEXT NOT NULL DEFAULT '0',"
        "  snapshot    TEXT NOT NULL,"
        "  pushed_by   TEXT NOT NULL,"
        "  pushed_at   TEXT NOT NULL DEFAULT (datetime('now')),"
        "  UNIQUE(cluster_key, toguid)"
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
        "  blob_count   INTEGER NOT NULL DEFAULT 0,"
        "  blob_size    INTEGER NOT NULL DEFAULT 0,"
        "  direction    TEXT NOT NULL DEFAULT 'push',"
        "  storage_base TEXT NOT NULL,"
        "  recorded_at  TEXT NOT NULL DEFAULT (datetime('now')),"
        "  UNIQUE(node, guid)"
        ");"
        "CREATE TABLE IF NOT EXISTS blobs ("
        "  snapshot_guid TEXT NOT NULL,"
        "  part          INTEGER NOT NULL,"
        "  size          INTEGER NOT NULL,"
        "  sha256        TEXT NOT NULL,"
        "  storage_ref   TEXT NOT NULL,"
        "  UNIQUE(snapshot_guid, part)"
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
    }
    return ZEP_ERR_OK;
}

err_t db_push_record(sqlite3 *db, const snapshot_meta_t *meta) {
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO pushed (guid, snapshot, base_guid, label, created, blob_count, stream_size) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, meta->guid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, meta->snapshot, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, meta->base_guid[0] ? meta->base_guid : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, meta->label, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, meta->created, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt,  6, meta->blob_count);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)meta->stream_size);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_pull_record(sqlite3 *db, const snapshot_meta_t *meta, const char *donor) {
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO pulled (guid, snapshot, base_guid, label, created, donor_node, blob_count, stream_size) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, meta->guid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, meta->snapshot, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, meta->base_guid[0] ? meta->base_guid : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, meta->label, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, meta->created, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, donor, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt,  7, meta->blob_count);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)meta->stream_size);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

int db_was_pushed(sqlite3 *db, const char *guid) {
    sqlite3_stmt *stmt = NULL;
    int exists = 0;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM pushed WHERE guid = ?", -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(stmt, 1, guid, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) exists = 1;
    sqlite3_finalize(stmt);
    return exists;
}

int db_was_pulled(sqlite3 *db, const char *guid) {
    sqlite3_stmt *stmt = NULL;
    int exists = 0;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM pulled WHERE guid = ?", -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(stmt, 1, guid, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) exists = 1;
    sqlite3_finalize(stmt);
    return exists;
}

err_t db_list_pushed(sqlite3 *db, char ***guids, int *count) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT guid FROM pushed ORDER BY pushed_at DESC", -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;

    int cap = 16, cnt = 0;
    char **list = calloc((size_t)cap, sizeof(char *));
    if (!list) return ZEP_ERR_SYS;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (cnt >= cap) {
            cap *= 2;
            list = realloc(list, (size_t)cap * sizeof(char *));
            if (!list) return ZEP_ERR_SYS;
        }
        list[cnt++] = strdup((const char *)sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);
    *guids = list;
    *count = cnt;
    return ZEP_ERR_OK;
}

err_t db_list_pulled(sqlite3 *db, char ***guids, int *count) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT guid FROM pulled ORDER BY pulled_at DESC", -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;

    int cap = 16, cnt = 0;
    char **list = calloc((size_t)cap, sizeof(char *));
    if (!list) return ZEP_ERR_SYS;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (cnt >= cap) {
            cap *= 2;
            list = realloc(list, (size_t)cap * sizeof(char *));
            if (!list) return ZEP_ERR_SYS;
        }
        list[cnt++] = strdup((const char *)sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);
    *guids = list;
    *count = cnt;
    return ZEP_ERR_OK;
}

err_t db_chain_insert(sqlite3 *db, const char *cluster_key,
                      const char *toguid, const char *fromguid,
                      const char *snapshot, const char *pushed_by) {
    const char *sql =
        "INSERT OR IGNORE INTO cluster_chain "
        "(cluster_key, toguid, fromguid, snapshot, pushed_by) "
        "VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_chain_insert: %s\n", sqlite3_errmsg(db));
        return ZEP_ERR_DB;
    }
    sqlite3_bind_text(stmt, 1, cluster_key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, toguid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, fromguid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, snapshot, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, pushed_by, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_chain_latest(sqlite3 *db, const char *cluster_key,
                      char *guid, size_t len) {
    const char *sql =
        "SELECT toguid FROM cluster_chain WHERE cluster_key = ? "
        "ORDER BY rowid DESC LIMIT 1";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, cluster_key, -1, SQLITE_STATIC);
    err_t ret = ZEP_ERR_NOT_FOUND;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        snprintf(guid, len, "%s", sqlite3_column_text(stmt, 0));
        ret = ZEP_ERR_OK;
    }
    sqlite3_finalize(stmt);
    return ret;
}

err_t db_chain_common(sqlite3 *db, const char *cluster_key,
                      const char *client_guid,
                      char *common_guid, size_t len) {
    if (!client_guid || !client_guid[0] || strcmp(client_guid, "0") == 0)
        return ZEP_ERR_NOT_FOUND;

    const char *sql =
        "SELECT toguid FROM cluster_chain WHERE cluster_key = ? AND toguid = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, cluster_key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, client_guid, -1, SQLITE_STATIC);
    err_t ret = ZEP_ERR_NOT_FOUND;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        snprintf(common_guid, len, "%s", client_guid);
        ret = ZEP_ERR_OK;
    }
    sqlite3_finalize(stmt);
    return ret;
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

err_t db_ca_fingerprint(sqlite3 *db, char *fp, size_t len) {
    return db_cert_lookup(db, "Zep-Air testing", fp, len);
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

err_t db_ack_guid(sqlite3 *db, const char *cn, const char *guid) {
    const char *sql =
        "UPDATE auth SET last_ack_guid = ?, last_ack_at = datetime('now') WHERE cn = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, guid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, cn, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
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

err_t db_set_pipe_active(sqlite3 *db, const char *cn, int val) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE auth SET pipe_active = ? WHERE cn = ?", -1, &stmt, NULL) != SQLITE_OK)
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
                         const char *storage_base) {
    const char *sql =
        "INSERT OR IGNORE INTO snapshots "
        "(cluster, node, guid, base_guid, snapshot, label, cluster_fs, "
        " blob_count, blob_size, direction, storage_base) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
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
    sqlite3_bind_int(stmt, 8, blob_count);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)blob_size);
    sqlite3_bind_text(stmt, 10, direction, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 11, storage_base, -1, SQLITE_STATIC);
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

err_t db_snapshot_push_meta(sqlite3 *db, const char *guid,
                             char *snapshot, size_t sn_len,
                             char *label, size_t lbl_len,
                             char *cluster_fs, size_t cfs_len) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT snapshot, label, cluster_fs FROM snapshots "
            "WHERE guid = ?1 AND direction = 'push' LIMIT 1",
            -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, guid, -1, SQLITE_STATIC);
    err_t ret = ZEP_ERR_NOT_FOUND;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        snprintf(snapshot, sn_len, "%s",
            sqlite3_column_text(stmt, 0));
        snprintf(label, lbl_len, "%s",
            sqlite3_column_text(stmt, 1));
        snprintf(cluster_fs, cfs_len, "%s",
            sqlite3_column_text(stmt, 2));
        ret = ZEP_ERR_OK;
    }
    sqlite3_finalize(stmt);
    return ret;
}

char *db_blob_list_json(sqlite3 *db, const char *snapshot_guid) {
    const char *sql =
        "SELECT part, size, sha256 FROM blobs "
        "WHERE snapshot_guid = ?1 ORDER BY part";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(stmt, 1, snapshot_guid, -1, SQLITE_STATIC);
    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *b = cJSON_CreateObject();
        cJSON_AddNumberToObject(b, "part", sqlite3_column_int(stmt, 0));
        cJSON_AddNumberToObject(b, "size", sqlite3_column_int(stmt, 1));
        cJSON_AddStringToObject(b, "sha256",
            (const char *)sqlite3_column_text(stmt, 2));
        cJSON_AddItemToArray(arr, b);
    }
    sqlite3_finalize(stmt);
    char *js = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return js;
}

char *db_snapshot_chain_json(sqlite3 *db, const char *cluster,
                              const char *master_cn,
                              const char *client_guid) {
    cJSON *arr = cJSON_CreateArray();

    const char *sql =
        "SELECT guid, base_guid, blob_count, blob_size "
        "FROM snapshots "
        "WHERE node = ?1 AND cluster = ?2 AND direction = 'push' "
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

        char *bj = db_blob_list_json(db, g);
        if (bj) {
            cJSON *blist = cJSON_Parse(bj);
            if (blist) { cJSON_AddItemToObject(s, "blobs", blist); }
            free(bj);
        }
        cJSON_AddItemToArray(arr, s);
    }
    sqlite3_finalize(stmt);

    /* if client guid not found in chain, reset and return everything */
    if (!found && client_guid && client_guid[0]) {
        cJSON_Delete(arr);
        arr = cJSON_CreateArray();
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, master_cn, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, cluster, -1, SQLITE_STATIC);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *g = (const char *)sqlite3_column_text(stmt, 0);
                cJSON *s = cJSON_CreateObject();
                cJSON_AddStringToObject(s, "guid", g);
                cJSON_AddStringToObject(s, "base_guid",
                    (const char *)sqlite3_column_text(stmt, 1));
                char *bj = db_blob_list_json(db, g);
                if (bj) {
                    cJSON *blist = cJSON_Parse(bj);
                    if (blist) { cJSON_AddItemToObject(s, "blobs", blist); }
                    free(bj);
                }
                cJSON_AddItemToArray(arr, s);
            }
            sqlite3_finalize(stmt);
        }
    }

    int count = cJSON_GetArraySize(arr);
    if (count == 0) {
        cJSON_Delete(arr);
        return NULL;
    }
    char *js = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return js;
}

err_t db_blob_upsert(sqlite3 *db, const char *snapshot_guid, int part,
                     size_t size, const char *sha256,
                     const char *storage_ref) {
    const char *sql =
        "INSERT OR REPLACE INTO blobs (snapshot_guid, part, size, sha256, storage_ref) "
        "VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, snapshot_guid, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, part);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)size);
    sqlite3_bind_text(stmt, 4, sha256, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, storage_ref, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? ZEP_ERR_OK : ZEP_ERR_DB;
}

err_t db_blob_lookup(sqlite3 *db, const char *snapshot_guid, int part,
                     char *storage_ref, size_t ref_len) {
    const char *sql =
        "SELECT storage_ref FROM blobs WHERE snapshot_guid = ?1 AND part = ?2";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return ZEP_ERR_DB;
    sqlite3_bind_text(stmt, 1, snapshot_guid, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, part);
    err_t ret = ZEP_ERR_NOT_FOUND;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        snprintf(storage_ref, ref_len, "%s", sqlite3_column_text(stmt, 0));
        ret = ZEP_ERR_OK;
    }
    sqlite3_finalize(stmt);
    return ret;
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

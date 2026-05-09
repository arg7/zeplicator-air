/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "db.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    db_config_get(db, "pipe_zip_cmd", cfg->pipe_zip_cmd, sizeof(cfg->pipe_zip_cmd));
    db_config_get(db, "pipe_unzip_cmd", cfg->pipe_unzip_cmd, sizeof(cfg->pipe_unzip_cmd));
    db_config_get(db, "pipe_send_buf_cmd", cfg->pipe_send_buf_cmd, sizeof(cfg->pipe_send_buf_cmd));
    db_config_get(db, "pipe_recv_buf_cmd", cfg->pipe_recv_buf_cmd, sizeof(cfg->pipe_recv_buf_cmd));
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
    if (sqlite3_prepare_v2(db, "SELECT cn FROM auth ORDER BY role, cn", -1, &stmt, NULL) != SQLITE_OK)
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

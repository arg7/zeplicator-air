/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_DB_H
#define ZEP_AIR_DB_H

#include "common.h"
#include <sqlite3.h>
#include <cjson/cJSON.h>

err_t db_open(const char *path, sqlite3 **db);
void  db_close(sqlite3 *db);
err_t db_init_tables(sqlite3 *db);

err_t db_config_get(sqlite3 *db, const char *key, char *value, size_t len);
err_t db_config_set(sqlite3 *db, const char *key, const char *value);
err_t db_config_load(sqlite3 *db, zep_config_t *cfg);

err_t db_cert_store(sqlite3 *db, const char *cn,
                    const char *fingerprint, const char *pem_data,
                    const char *role, const char *cluster,
                    const char *mapping);
err_t db_cert_lookup(sqlite3 *db, const char *cn,
                     char *fingerprint, size_t flen);
err_t db_auth_list(sqlite3 *db, char ***names, int *count);
err_t db_auth_remove(sqlite3 *db, const char *cn);
err_t db_auth_get_role_by_fp(sqlite3 *db, const char *fingerprint,
                              char *role, size_t len);
err_t db_set_suspended(sqlite3 *db, const char *cn, int val);
err_t db_update_role(sqlite3 *db, const char *cn, const char *new_role);

err_t db_snapshot_insert(sqlite3 *db, const char *cluster, const char *node,
                         const char *guid, const char *base_guid,
                         const char *snapshot, const char *label,
                         const char *cluster_fs, int blob_count,
                         size_t blob_size, const char *direction,
                         const char *storage_base, const char *status);
char *db_snapshot_chain_json(sqlite3 *db, const char *cluster,
                             const char *master_cn,
                             const char *client_guid);
err_t db_snapshot_latest_guid(sqlite3 *db, const char *node,
                              const char *direction,
                              char *guid, size_t len);
err_t db_upload_get_offset(sqlite3 *db, const char *guid,
                            char *offset_buf, size_t len);
err_t db_upload_save_token(sqlite3 *db, const char *guid,
                            const char *node, const char *token, int64_t bytes);
err_t db_upload_complete(sqlite3 *db, const char *guid);

err_t db_common_ancestor(sqlite3 *db, const char *cluster,
                         char *guid, size_t len);
err_t db_snapshot_delete_node_guid(sqlite3 *db, const char *node,
                                    const char *guid);
int   db_node_pull_count(sqlite3 *db, const char *cluster, const char *node);
err_t db_rotation_candidates(sqlite3 *db, const char *cluster,
                              const char *node, const char *mapping,
                              cJSON *cluster_json, cJSON *out);

err_t db_upload_get_offset(sqlite3 *db, const char *guid,
                            char *offset_buf, size_t len);
err_t db_upload_save_token(sqlite3 *db, const char *guid,
                            const char *node, const char *token, int64_t bytes);
err_t db_upload_complete(sqlite3 *db, const char *guid);
int   db_upload_has_incomplete(sqlite3 *db, const char *node);

err_t db_pull_state_save(sqlite3 *db, const char *key,
                         const char *guid, int blobs_done);
err_t db_pull_state_load(sqlite3 *db, const char *key,
                         char *guid, size_t guid_len, int *blobs_done);
void  db_pull_state_clear(sqlite3 *db, const char *key);

#endif

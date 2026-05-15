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

err_t db_push_record(sqlite3 *db, const snapshot_meta_t *meta);
err_t db_pull_record(sqlite3 *db, const snapshot_meta_t *meta, const char *donor);
int   db_was_pushed(sqlite3 *db, const char *guid);
int   db_was_pulled(sqlite3 *db, const char *guid);
err_t db_list_pushed(sqlite3 *db, char ***guids, int *count);
err_t db_list_pulled(sqlite3 *db, char ***guids, int *count);

err_t db_chain_insert(sqlite3 *db, const char *cluster_key,
                      const char *toguid, const char *fromguid,
                      const char *snapshot, const char *pushed_by);
err_t db_chain_latest(sqlite3 *db, const char *cluster_key,
                      char *guid, size_t len);
err_t db_chain_common(sqlite3 *db, const char *cluster_key,
                      const char *client_guid,
                      char *common_guid, size_t len);

err_t db_cert_store(sqlite3 *db, const char *cn,
                    const char *fingerprint, const char *pem_data,
                    const char *role, const char *cluster,
                    const char *mapping);
err_t db_cert_lookup(sqlite3 *db, const char *cn,
                     char *fingerprint, size_t flen);
err_t db_ca_fingerprint(sqlite3 *db, char *fp, size_t len);
err_t db_auth_list(sqlite3 *db, char ***names, int *count);
err_t db_auth_remove(sqlite3 *db, const char *cn);
err_t db_auth_get_role_by_fp(sqlite3 *db, const char *fingerprint,
                              char *role, size_t len);
err_t db_ack_guid(sqlite3 *db, const char *cn, const char *guid);
err_t db_set_suspended(sqlite3 *db, const char *cn, int val);
err_t db_set_pipe_active(sqlite3 *db, const char *cn, int val);
err_t db_update_role(sqlite3 *db, const char *cn, const char *new_role);

err_t db_snapshot_insert(sqlite3 *db, const char *cluster, const char *node,
                         const char *guid, const char *base_guid,
                         const char *snapshot, const char *label,
                         const char *cluster_fs, int blob_count,
                         size_t blob_size, const char *direction,
                         const char *storage_base);
char *db_snapshot_chain_json(sqlite3 *db, const char *cluster,
                             const char *master_cn,
                             const char *client_guid);
err_t db_snapshot_latest_guid(sqlite3 *db, const char *node,
                              const char *direction,
                              char *guid, size_t len);
err_t db_blob_upsert(sqlite3 *db, const char *snapshot_guid, int part,
                     size_t size, const char *sha256,
                     const char *storage_ref);
err_t db_blob_lookup(sqlite3 *db, const char *snapshot_guid, int part,
                     char *storage_ref, size_t ref_len);
char *db_blob_list_json(sqlite3 *db, const char *snapshot_guid);

err_t db_common_ancestor(sqlite3 *db, const char *cluster,
                         char *guid, size_t len);
err_t db_snapshot_delete_node_guid(sqlite3 *db, const char *node,
                                    const char *guid);
int   db_node_pull_count(sqlite3 *db, const char *cluster, const char *node);
err_t db_rotation_candidates(sqlite3 *db, const char *cluster,
                              const char *node, const char *mapping,
                              cJSON *cluster_json, cJSON *out);
err_t db_snapshot_push_meta(sqlite3 *db, const char *guid,
                             char *snapshot, size_t sn_len,
                             char *label, size_t lbl_len,
                             char *cluster_fs, size_t cfs_len);

err_t db_upload_track(sqlite3 *db, const char *prefix, const char *node,
                       int total_chunks, const char *resume_token);
err_t db_upload_complete(sqlite3 *db, const char *prefix);
int   db_upload_has_incomplete(sqlite3 *db, const char *node);
err_t db_upload_get_prev(sqlite3 *db, const char *prefix,
                           int *prev_chunks, char *prev_token, size_t tlen);

err_t db_pull_state_save(sqlite3 *db, const char *key,
                         const char *guid, int blobs_done);
err_t db_pull_state_load(sqlite3 *db, const char *key,
                         char *guid, size_t guid_len, int *blobs_done);
void  db_pull_state_clear(sqlite3 *db, const char *key);

#endif

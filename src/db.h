#ifndef ZEP_AIR_DB_H
#define ZEP_AIR_DB_H

#include "common.h"
#include <sqlite3.h>

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
                    const char *role);
err_t db_cert_lookup(sqlite3 *db, const char *cn,
                     char *fingerprint, size_t flen);
err_t db_ca_fingerprint(sqlite3 *db, char *fp, size_t len);
err_t db_auth_list(sqlite3 *db, char ***names, int *count);
err_t db_auth_remove(sqlite3 *db, const char *cn);

#endif

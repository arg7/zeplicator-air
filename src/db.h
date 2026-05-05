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

#endif

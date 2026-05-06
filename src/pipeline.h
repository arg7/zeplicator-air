#ifndef ZEP_AIR_PIPELINE_H
#define ZEP_AIR_PIPELINE_H

#include "common.h"
#include "http.h"
#include <sqlite3.h>

err_t pipeline_push(sqlite3 *db, const zep_config_t *cfg,
                    const http_config_t *http_cfg,
                    const char *fs, const char *label);

err_t pipeline_pull(sqlite3 *db, const zep_config_t *cfg,
                    const http_config_t *http_cfg,
                    const char *fs, const char *donor_node);

err_t pipeline_resolve_fs(const char *cluster_fs, const char *mapping,
                          char *local_fs, size_t len);
int   pipeline_has_mapping(const char *cluster_fs, const char *mapping);
err_t pipeline_for_each_fs(const char *mapping,
                           void (*cb)(const char *cluster_fs, const char *local_fs,
                                      void *user), void *user);

#endif

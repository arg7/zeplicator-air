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

#endif

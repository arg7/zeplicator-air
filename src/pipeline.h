/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_PIPELINE_H
#define ZEP_AIR_PIPELINE_H

#include "common.h"
#include "http.h"
#include <cjson/cJSON.h>
#include <sqlite3.h>

err_t pipeline_push(const zep_config_t *cfg,
                    const http_config_t *http_cfg,
                    const char *fs, const char *label,
                    const char *cluster_fs, sqlite3 *db);

err_t pipeline_pull(const zep_config_t *cfg,
                    const http_config_t *http_cfg,
                    const char *fs, const char *donor_node,
                    sqlite3 *db);

err_t pipeline_resolve_fs(const char *cluster_fs, const char *mapping,
                          char *local_fs, size_t len);

err_t pipeline_reverse_fs(const char *mapping, const char *local_fs,
                          char *cluster_fs, size_t len);

int  pipeline_resume_request(const char *guid, const char *token, const char *fs);

#endif

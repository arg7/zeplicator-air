/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_PIPELINE_H
#define ZEP_AIR_PIPELINE_H

#include "common.h"
#include "http.h"
#include <cjson/cJSON.h>
#include <sqlite3.h>

err_t pipeline_resolve_fs(const char *cluster_fs, const char *mapping,
                          char *local_fs, size_t len);

int  pipeline_resume_request(const char *guid, const char *token, const char *fs);

#endif

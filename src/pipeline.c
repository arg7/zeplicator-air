/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "pipeline.h"
#include "zfs.h"
#include "http.h"
#include "db.h"
#include "audit.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sqlite3.h>
#include <cjson/cJSON.h>
#include <sys/wait.h>

err_t pipeline_resolve_fs(const char *cluster_fs, const char *mapping,
                          char *local_fs, size_t len) {
    if (!cluster_fs || !mapping) return ZEP_ERR_NOT_FOUND;
    const char *p = mapping;
    while (*p) {
        const char *colon = strchr(p, ':');
        if (!colon) break;
        size_t cf_len = (size_t)(colon - p);
        if (strncmp(p, cluster_fs, cf_len) == 0 && (size_t)strlen(cluster_fs) == cf_len) {
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= len) n = len - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            return ZEP_ERR_OK;
        }
        const char *comma = strchr(colon, ',');
        p = comma ? comma + 1 : colon + strlen(colon);
    }
    return ZEP_ERR_NOT_FOUND;
}



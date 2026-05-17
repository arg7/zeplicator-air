/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "common.h"
#include "db.h"
#include "audit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>

int g_logging = LOG_LEVEL_DEFAULT;

/* --- Logging level parsing and structured logging --- */

int zep_log_parse_mask(const char *str) {
    if (!str || !str[0]) return LOG_LEVEL_DEFAULT;
    int mask = 0;
    char buf[256];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *tok = strtok(buf, ",");
    while (tok) {
        for (char *p = tok; *p; p++) *p = toupper((unsigned char)*p);
        if (strcmp(tok, "DEBUG") == 0)    mask |= LOG_LEVEL_DEBUG;
        else if (strcmp(tok, "INFO") == 0) mask |= LOG_LEVEL_INFO;
        else if (strcmp(tok, "WARN") == 0) mask |= LOG_LEVEL_WARN;
        else if (strcmp(tok, "ERROR") == 0) mask |= LOG_LEVEL_ERROR;
        else if (strcmp(tok, "AUDIT") == 0) mask |= LOG_LEVEL_AUDIT;
        tok = strtok(NULL, ",");
    }
    return mask;
}

int zep_log_init(const char *db_path) {
    (void)db_path;
    if (g_logging == 0) g_logging = LOG_LEVEL_DEFAULT;
    return 0;
}

void zep_air_log(int level, const char *fmt, ...) {
    if (!(g_logging & level)) return;

    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

    const char *label;
    switch (level) {
        case LOG_LEVEL_DEBUG: label = "DEBUG"; break;
        case LOG_LEVEL_INFO:  label = "INFO";  break;
        case LOG_LEVEL_WARN:  label = "WARN";  break;
        case LOG_LEVEL_ERROR: label = "ERROR"; break;
        case LOG_LEVEL_AUDIT: label = "AUDIT"; break;
        default:              label = "???";   break;
    }

    va_list ap;
    va_start(ap, fmt);

    fprintf(stderr, "[%s] %s: ", ts, label);
    vfprintf(stderr, fmt, ap);
    fflush(stderr);

    va_end(ap);
}

/* --- Audit log file (JSON-lines, separate from --logging mask) --- */

static FILE *audit_fp = NULL;

static char *audit_timestamp(char *buf, size_t bufsz) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%S%z", &tm);
    return buf;
}

static void audit_escape(const char *src, char *dst, size_t dlen) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dlen - 2; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"'  || c == '\\' || c < 0x20) {
            if (j + 4 >= dlen) break;
            dst[j++] = '\\';
            if (c == '"')  { dst[j++] = '"'; continue; }
            if (c == '\\') { dst[j++] = '\\'; continue; }
            j += (size_t)snprintf(dst + j, dlen - j, "\\u%04x", c);
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

int audit_log_init(const char *path) {
    if (!path || !path[0]) return 0;
    audit_fp = fopen(path, "a");
    if (!audit_fp) {
        perror("audit-log: failed to open");
        return -1;
    }
    setvbuf(audit_fp, NULL, _IOLBF, 0);
    return 0;
}

void audit_log_close(void) {
    if (audit_fp) {
        fclose(audit_fp);
        audit_fp = NULL;
    }
}

int audit_log_write(const char *event, const char *type,
                    const char *cmd, int exit_code) {
    if (!audit_fp) return 0;

    char ts[32];
    char esc_cmd[8192];

    audit_escape(cmd, esc_cmd, sizeof(esc_cmd));

    fprintf(audit_fp, "{\"event\":\"%s\",\"ts\":\"%s\",\"type\":\"%s\",\"cmd\":\"%s\",\"rc\":%d}\n",
            event ? event : "unknown",
            audit_timestamp(ts, sizeof(ts)),
            type ? type : "unknown",
            esc_cmd,
            exit_code);

    return 0;
}

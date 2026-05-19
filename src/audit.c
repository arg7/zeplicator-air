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
    if (level == LOG_LEVEL_AUDIT) fputc('\n', stderr);
    fflush(stderr);

    va_end(ap);
}

int audit_log_init(const char *path) {
    (void)path;
    return 0;
}

void audit_log_close(void) {
}

/* Escape a string for safe inclusion in JSON */
static void audit_escape_str(const char *src, char *dst, size_t dlen) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dlen - 4; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\' || c < 0x20) {
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

int audit_log_write(const char *event, const char *type,
                    const char *cmd, int exit_code) {
    return audit_log_write2(event, type, cmd, exit_code, "");
}

int audit_log_write2(const char *event, const char *type,
                     const char *cmd, int exit_code,
                     const char *stderr_output) {
    char esc_cmd[8192], esc_stderr[2048];
    audit_escape_str(cmd, esc_cmd, sizeof(esc_cmd));
    audit_escape_str(stderr_output, esc_stderr, sizeof(esc_stderr));

    zep_log_audit("event=%s type=%s cmd=\"%s\" rc=%d stderr=\"%s\"",
                  event ? event : "unknown",
                  type ? type : "unknown",
                  esc_cmd, exit_code, esc_stderr);
    return 0;
}

/* Global thread-local temp file path for audit_popen pairing */
static char g_audit_tmp[512] = {0};

FILE *audit_popen(const char *cmd) {
    if (!cmd) return NULL;
    g_audit_tmp[0] = '\0';

    char tmp_path[512];
    int tmp_fd = mkstemp(tmp_path);
    if (tmp_fd < 0) {
        return popen(cmd, "r");
    }
    close(tmp_fd);
    snprintf(g_audit_tmp, sizeof(g_audit_tmp), "%s", tmp_path);

    /* Replace 2>/dev/null with 2>/tmp_path, or append 2>/tmp_path */
    char pipe_cmd[8192];
    size_t cmd_len = strlen(cmd);
    if (cmd_len >= 11 && strcmp(cmd + cmd_len - 11, " 2>/dev/null") == 0) {
        snprintf(pipe_cmd, sizeof(pipe_cmd), "%.*s 2>%s",
                 (int)(cmd_len - 11), cmd, tmp_path);
    } else {
        snprintf(pipe_cmd, sizeof(pipe_cmd), "%s 2>%s", cmd, tmp_path);
    }
    return popen(pipe_cmd, "r");
}

int audit_popen_result(FILE *fp, char *stderr_buf, size_t bufsz) {
    if (bufsz > 0) stderr_buf[0] = '\0';
    if (!fp) return -128;

    int rc = pclose(fp);
    if (!WIFEXITED(rc)) {
        /* Clean up temp file */
        if (g_audit_tmp[0]) { unlink(g_audit_tmp); g_audit_tmp[0] = '\0'; }
        return -128;
    }
    rc = WEXITSTATUS(rc);

    if (stderr_buf && bufsz > 0 && g_audit_tmp[0]) {
        FILE *sf = fopen(g_audit_tmp, "r");
        if (sf) {
            size_t n = fread(stderr_buf, 1, bufsz - 1, sf);
            stderr_buf[n] = '\0';
            while (n > 0 && (stderr_buf[n-1] == '\n' || stderr_buf[n-1] == '\r'))
                stderr_buf[--n] = '\0';
            fclose(sf);
        }
        unlink(g_audit_tmp);
        g_audit_tmp[0] = '\0';
    }
    return rc;
}

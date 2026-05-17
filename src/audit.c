/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "audit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
    /* enable line-buffered writes */
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

    /* JSON-lines: {"event":"exec","ts":"...","type":"zfs","cmd":"...","rc":0} */
    fprintf(audit_fp, "{\"event\":\"%s\",\"ts\":\"%s\",\"type\":\"%s\",\"cmd\":\"%s\",\"rc\":%d}\n",
            event ? event : "unknown",
            audit_timestamp(ts, sizeof(ts)),
            type ? type : "unknown",
            esc_cmd,
            exit_code);

    return 0;
}

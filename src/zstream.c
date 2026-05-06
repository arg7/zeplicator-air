/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "zstream.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

err_t zstream_parse(const void *data, size_t len,
                    char *toguid, size_t toguid_len,
                    char *fromguid, size_t fromguid_len) {
    if (!data || !len) return ZEP_ERR_SYS;

    toguid[0] = '\0';
    fromguid[0] = '\0';

    char tmpl[] = "/tmp/zep-stream-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) { perror("mkstemp"); return ZEP_ERR_SYS; }

    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, (const char *)data + written, len - written);
        if (n <= 0) { close(fd); unlink(tmpl); return ZEP_ERR_SYS; }
        written += (size_t)n;
    }
    close(fd);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "zstream dump -v '%s' 2>/dev/null", tmpl);
    FILE *zp = popen(cmd, "r");
    if (!zp) { unlink(tmpl); perror("popen"); return ZEP_ERR_ZFS; }

    char line[256];
    while (fgets(line, sizeof(line), zp)) {
        unsigned long long val;
        if (strstr(line, "toguid")) {
            if (sscanf(line, " toguid = %llu", &val) == 1)
                snprintf(toguid, toguid_len, "%llu", val);
        } else if (strstr(line, "fromguid")) {
            if (sscanf(line, " fromguid = %llu", &val) == 1)
                snprintf(fromguid, fromguid_len, "%llu", val);
        }
    }

    int rc = pclose(zp);
    unlink(tmpl);

    if (!toguid[0]) {
        fprintf(stderr, "zstream_parse: failed to extract toguid (zstreamdump rc=%d)\n", rc);
        return ZEP_ERR_ZFS;
    }

    /* fromguid = 0 means full send */
    if (!fromguid[0]) {
        snprintf(fromguid, fromguid_len, "0");
    }

    return ZEP_ERR_OK;
}

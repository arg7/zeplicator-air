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
    int has_begin = 0;
    while (fgets(line, sizeof(line), zp)) {
        unsigned long long val;
        if (strstr(line, "toguid")) {
            if (sscanf(line, " toguid = %llx", &val) == 1)
                snprintf(toguid, toguid_len, "%llu", val);
        } else if (strstr(line, "fromguid")) {
            if (sscanf(line, " fromguid = %llx", &val) == 1)
                snprintf(fromguid, fromguid_len, "%llu", val);
        }
        if (strstr(line, "DRR_BEGIN records")) {
            const char *p = strstr(line, "DRR_BEGIN records = ");
            unsigned long long cnt;
            if (p && sscanf(p, "DRR_BEGIN records = %llu", &cnt) == 1 && cnt > 0)
                has_begin = 1;
        }
    }

    int rc = pclose(zp);
    unlink(tmpl);

    if (!toguid[0]) {
        if (!has_begin) {
            /* Empty stream — no BEGIN record, treat as full send with zero guid */
            snprintf(toguid, toguid_len, "0");
            snprintf(fromguid, fromguid_len, "0");
            return ZEP_ERR_OK;
        }
        fprintf(stderr, "zstream_parse: failed to extract toguid (zstreamdump rc=%d)\n", rc);
        return ZEP_ERR_ZFS;
    }

    /* fromguid = 0 means full send */
    if (!fromguid[0]) {
        snprintf(fromguid, fromguid_len, "0");
    }

    return ZEP_ERR_OK;
}

err_t zstream_token_generate(const void *data, size_t len,
                              char *token_out, size_t token_len) {
    if (!data || !len || !token_out || !token_len)
        return ZEP_ERR_SYS;

    char tmpl[] = "/tmp/zep-token-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return ZEP_ERR_SYS;

    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, (const char *)data + written, len - written);
        if (n <= 0) { close(fd); unlink(tmpl); return ZEP_ERR_SYS; }
        written += (size_t)n;
    }
    close(fd);

    char cmd[1024];
    if (len >= 4 && ((const unsigned char *)data)[0] == 0x28 &&
        ((const unsigned char *)data)[1] == 0xB5 &&
        ((const unsigned char *)data)[2] == 0x2F &&
        ((const unsigned char *)data)[3] == 0xFD)
        snprintf(cmd, sizeof(cmd),
                 "zstd -d '%s' -c 2>/dev/null | zstream token -g", tmpl);
    else
        snprintf(cmd, sizeof(cmd),
                 "zstream token -g < '%s'", tmpl);
    FILE *p = popen(cmd, "r");
    if (!p) { unlink(tmpl); return ZEP_ERR_ZFS; }

    token_out[0] = '\0';
    if (!fgets(token_out, (int)token_len, p)) {
        pclose(p); unlink(tmpl); return ZEP_ERR_ZFS;
    }
    pclose(p);
    unlink(tmpl);

    size_t n = strlen(token_out);
    while (n > 0 && (token_out[n - 1] == '\n' || token_out[n - 1] == '\r'))
        token_out[--n] = '\0';

    return token_out[0] ? ZEP_ERR_OK : ZEP_ERR_ZFS;
}

err_t zstream_token_parse_offset(const char *token,
                                 uint64_t *offset_out) {
    if (!token || !token[0] || !offset_out) return ZEP_ERR_SYS;
    *offset_out = 0;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zstream token '%s' 2>/dev/null", token);
    FILE *p = popen(cmd, "r");
    if (!p) return ZEP_ERR_ZFS;

    char line[256];
    while (fgets(line, sizeof(line), p)) {
        char *key_end = NULL;
        long long val = 0;

        if ((key_end = strstr(line, "stream_offset")) != NULL ||
            (key_end = strstr(line, "offset")) != NULL) {
            char *eq = strchr(key_end, '=');
            if (eq) {
                val = strtoll(eq + 1, NULL, 0);
                *offset_out = (uint64_t)val;
                pclose(p);
                return ZEP_ERR_OK;
            }
        }
    }

    pclose(p);
    return ZEP_ERR_NOT_FOUND;
}

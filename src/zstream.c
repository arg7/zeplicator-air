/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "zstream.h"
#include "audit.h"
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
    if (!zp) { unlink(tmpl); audit_log(AUDIT_EVT_EXEC, "zstream", cmd, -127); return ZEP_ERR_ZFS; }

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
    audit_log(AUDIT_EVT_EXEC, "zstream", cmd, WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);

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

err_t zstream_token_parse_offset(const char *token,
                                  uint64_t *offset_out) {
    if (!token || !token[0] || !offset_out) return ZEP_ERR_SYS;
    *offset_out = 0;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zstream token '%s' 2>/dev/null", token);
    FILE *p = popen(cmd, "r");
    if (!p) { audit_log(AUDIT_EVT_EXEC, "zstream", cmd, -127); return ZEP_ERR_ZFS; }

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
                int rc = pclose(p);
                audit_log(AUDIT_EVT_EXEC, "zstream", cmd, WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
                return ZEP_ERR_OK;
            }
        }
    }

    int rc = pclose(p);
    audit_log(AUDIT_EVT_EXEC, "zstream", cmd, WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
    return ZEP_ERR_NOT_FOUND;
}

/* Build a cat pipeline for all .stream files, pipe to zstream dump -v.
 * Returns ZEP_ERR_OK if toguid extracted successfully. */
err_t zstream_join(const char *dir_path, const char *base_name,
                   int start_blob, int blob_count,
                   char *toguid_out, size_t toguid_len) {
    if (!dir_path || !base_name) return ZEP_ERR_SYS;
    if (toguid_out) { toguid_out[0] = '\0'; }

    /* Build command: cat dir/base_NNNN.stream dir/base_NNNN+1.stream ... | zstream dump -v - */
    char cmd[8192] = {0};
    int n = 0;

    for (int i = 0; i < blob_count; i++) {
        char bf[16];
        snprintf(bf, sizeof(bf), "%04u", (unsigned)(start_blob + i));
        char fpath[ZEP_MAX_PATH * 2 + 256];
        int fn = snprintf(fpath, sizeof(fpath), "%s/%s/%s",
                          dir_path, base_name, bf);
        if (fn < 0 || fn >= (int)sizeof(fpath)) return ZEP_ERR_SYS;

        n += snprintf(cmd + n, sizeof(cmd) - (size_t)n, "cat '%s' ", fpath);
        if (n < 0 || n >= (int)(sizeof(cmd) - 20)) return ZEP_ERR_SYS;

        if (i < blob_count - 1) {
            n += snprintf(cmd + n, sizeof(cmd) - (size_t)n, "| ");
        }
    }
    n += snprintf(cmd + n, sizeof(cmd) - (size_t)n, "| zstream dump -v -");

    FILE *dp = audit_popen(cmd);
    if (!dp) {
        audit_log(AUDIT_EVT_EXEC, "zstream", cmd, -127);
        return ZEP_ERR_ZFS;
    }

    char line[512];
    char tguid[ZEP_MAX_GUID_LEN] = {0};
    while (fgets(line, sizeof(line), dp)) {
        char *dl = line;
        while (*dl == ' ' || *dl == '\t') dl++;
        if (strncmp(dl, "toguid =", 8) == 0) {
            char *v = dl + 8;
            while (*v == ' ') v++;
            size_t len = strlen(v);
            while (len > 0 && (v[len-1]=='\n'||v[len-1]=='\r')) v[--len] = '\0';
            if (len > 0 && len < sizeof(tguid))
                snprintf(tguid, sizeof(tguid), "%s", v);
        }
    }

    int rc = audit_popen_result(dp, NULL, 0);
    audit_log(AUDIT_EVT_EXEC, "zstream", cmd, rc);

    /* Exit code 0 = valid, 2 = no DRR_END (truncated split — still valid for join) */
    if ((rc == 0 || rc == 2) && tguid[0]) {
        if (toguid_out && toguid_len > 0)
            snprintf(toguid_out, toguid_len, "%s", tguid);
        return ZEP_ERR_OK;
    }
    return ZEP_ERR_ZFS;
}

/* Validate a zstream token file (output of zstream token -g -i <file>).
 * A valid token file contains "valid = 1". A truncated one has "valid = 0".
 * Also accepts exit code 2 (no DRR_END) as valid for split chunks. */
err_t zstream_token_from_file(const char *token_file) {
    if (!token_file || !token_file[0]) return ZEP_ERR_SYS;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "zstream token -g -i '%s' 2>/dev/null", token_file);

    FILE *tp = audit_popen(cmd);
    if (!tp) {
        audit_log(AUDIT_EVT_EXEC, "zstream", cmd, -127);
        return ZEP_ERR_ZFS;
    }

    char line[256];
    int valid = 0;
    while (fgets(line, sizeof(line), tp)) {
        char *dl = line;
        while (*dl == ' ' || *dl == '\t') dl++;
        if (strstr(dl, "valid")) {
            char *eq = strchr(dl, '=');
            if (eq) {
                char *v = eq + 1;
                while (*v == ' ') v++;
                if (*v == '1') valid = 1;
            }
        }
    }

    int rc = audit_popen_result(tp, NULL, 0);
    audit_log(AUDIT_EVT_EXEC, "zstream", cmd, rc);

    /* Exit code 0 or 2 (no DRR_END) = valid for split chunks */
    if ((rc == 0 || rc == 2) && valid)
        return ZEP_ERR_OK;
    return ZEP_ERR_ZFS;
}

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
    snprintf(cmd, sizeof(cmd), "zstream dump -v '%s'", tmpl);
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
    snprintf(cmd, sizeof(cmd), "zstream token '%s'", token);
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

/* Reassemble all .stream files using zstream join.
 * Returns ZEP_ERR_OK if join succeeded. */
err_t zstream_join(const char *dir_path, const char *base_name,
                   int start_blob, int blob_count,
                   char *toguid_out, size_t toguid_len) {
    (void)base_name;
    (void)toguid_out;
    (void)toguid_len;
    if (!dir_path) return ZEP_ERR_SYS;
    if (toguid_out) { toguid_out[0] = '\0'; }

    char joined_path[ZEP_MAX_PATH * 2 + 256];
    snprintf(joined_path, sizeof(joined_path), "%s/joined.zfs", dir_path);
    unlink(joined_path);

    char cmd[8192] = {0};
    int n = snprintf(cmd, sizeof(cmd), "zstream join");

    for (int i = 0; i < blob_count; i++) {
        char fpath[ZEP_MAX_PATH * 2 + 256];
        int fn = snprintf(fpath, sizeof(fpath), "%s/%04u.stream",
                          dir_path, (unsigned)(start_blob + i));
        if (fn < 0 || fn >= (int)sizeof(fpath)) return ZEP_ERR_SYS;

        n += snprintf(cmd + n, sizeof(cmd) - (size_t)n, " -i '%s'", fpath);
        if (n < 0 || n >= (int)(sizeof(cmd) - 30)) return ZEP_ERR_SYS;
    }
    n += snprintf(cmd + n, sizeof(cmd) - (size_t)n, " > '%s'", joined_path);

    FILE *cp = audit_popen(cmd);
    if (!cp) {
        audit_log(AUDIT_EVT_EXEC, "zstream", cmd, -127);
        return ZEP_ERR_ZFS;
    }
    int join_rc = audit_popen_result(cp, NULL, 0);
    audit_log(AUDIT_EVT_EXEC, "zstream", cmd, join_rc);

    if (join_rc != 0) return ZEP_ERR_ZFS;

    return ZEP_ERR_OK;
}

/* Validate a zstream token file (output of zstream token -g -i <file>).
 * A valid token file contains "valid = 1". A truncated one has "valid = 0".
 * Also accepts exit code 2 (no DRR_END) as valid for split chunks. */
err_t zstream_token_from_file(const char *token_file) {
    if (!token_file || !token_file[0]) return ZEP_ERR_SYS;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "zstream token -g -i '%s' > /dev/null", token_file);

    FILE *tp = audit_popen(cmd);
    if (!tp) {
        audit_log(AUDIT_EVT_EXEC, "zstream", cmd, -127);
        return ZEP_ERR_ZFS;
    }

    int rc = audit_popen_result(tp, NULL, 0);
    audit_log(AUDIT_EVT_EXEC, "zstream", cmd, rc);

    /* Exit 0 = valid stream data, exit 1 = garbage (no DRR_BEGIN), exit 2 = complete (DRR_END) */
    if (rc == 0 || rc == 2)
        return ZEP_ERR_OK;
    return ZEP_ERR_ZFS;
}

/* Extract a zstream resume token from a file.
 * Runs `zstream token -g -i <filepath>`, captures stdout as token string. */
err_t zstream_token_extract(const char *filepath, char *token_out, size_t token_len) {
    if (!filepath || !token_out || token_len == 0) return ZEP_ERR_SYS;
    token_out[0] = '\0';

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "zstream token -g -i '%s'", filepath);

    char tmp[] = "/tmp/zep-token-XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) { perror("mkstemp"); return ZEP_ERR_SYS; }
    close(fd);

    char cmdfile[1024];
    snprintf(cmdfile, sizeof(cmdfile), "%s > '%s'", cmd, tmp);

    FILE *tp = audit_popen(cmdfile);
    if (!tp) {
        audit_log(AUDIT_EVT_EXEC, "zstream", cmdfile, -127);
        unlink(tmp);
        return ZEP_ERR_ZFS;
    }
    int rc = audit_popen_result(tp, NULL, 0);
    audit_log(AUDIT_EVT_EXEC, "zstream", cmdfile, rc);

    if (rc != 0) {
        unlink(tmp);
        return ZEP_ERR_ZFS;
    }

    FILE *tfp = fopen(tmp, "r");
    if (tfp) {
        size_t tn = fread(token_out, 1, token_len - 1, tfp);
        token_out[tn] = '\0';
        while (tn > 0 && (token_out[tn-1]=='\n' || token_out[tn-1]=='\r'))
            token_out[--tn] = '\0';
        fclose(tfp);
    }

    unlink(tmp);

    if (!token_out[0]) return ZEP_ERR_ZFS;
    return ZEP_ERR_OK;
}

/* Accumulative zstream join for resume push.
 * If assembled_in is non-empty: joins assembled_in + new_chunk -> assembled_out (zstream join head chunk).
 * If assembled_in is empty: sanitizes new_chunk (strips incomplete tail) -> assembled_out (zstream join "" chunk).
 * On success sets *complete to 1 if DRR_END found (join exit 0), 0 otherwise (exit 2).
 * Returns ZEP_ERR_OK on success, ZEP_ERR_ZFS on failure. */
err_t zstream_join_accumulative(const char *assembled_in,
                                const char *new_chunk,
                                const char *assembled_out,
                                int *complete) {
    if (!new_chunk || !assembled_out || !complete) return ZEP_ERR_SYS;
    *complete = 0;

    unlink(assembled_out);

    char cmd[8192] = {0};
    if (assembled_in && assembled_in[0]) {
        snprintf(cmd, sizeof(cmd), "zstream join '%s' '%s' > '%s'",
            assembled_in, new_chunk, assembled_out);
    } else {
        snprintf(cmd, sizeof(cmd), "zstream join '%s' > '%s'",
            new_chunk, assembled_out);
    }

    FILE *cp = audit_popen(cmd);
    if (!cp) {
        audit_log(AUDIT_EVT_EXEC, "zstream", cmd, -127);
        return ZEP_ERR_ZFS;
    }
    int join_rc = audit_popen_result(cp, NULL, 0);
    audit_log(AUDIT_EVT_EXEC, "zstream", cmd, join_rc);

    /* join exit 0 = DRR_END present (complete), 2 = no DRR_END (incomplete) */
    if (join_rc == 0) {
        *complete = 1;
        return ZEP_ERR_OK;
    }
    if (join_rc == 2) return ZEP_ERR_OK;
    return ZEP_ERR_ZFS;
}

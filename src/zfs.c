/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "zfs.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>

err_t zfs_snapshot_create(const char *fs, const char *label, char *out_name, size_t out_len) {
    char ts[20];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d-%H%M%S", &tm);

    int n = snprintf(out_name, out_len, "%s@zep_%s-%s", fs, label, ts);
    if (n < 0 || (size_t)n >= out_len) return ZEP_ERR_SYS;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zfs snapshot '%s' 2>&1", out_name);
    FILE *p = popen(cmd, "r");
    if (!p) return ZEP_ERR_ZFS;

    char errbuf[512] = {0};
    if (fread(errbuf, 1, sizeof(errbuf) - 1, p) == 0 && ferror(p)) {}
    int rc = pclose(p);
    if (rc != 0) {
        zep_log( "zfs snapshot failed: %s\n", errbuf);
        return ZEP_ERR_ZFS;
    }
    return ZEP_ERR_OK;
}

err_t zfs_snapshot_create_cluster(const char *fs, const char *cluster,
                                  const char *label, char *out_name, size_t out_len) {
    char ts[20];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d-%H%M%S", &tm);

    int n = snprintf(out_name, out_len, "%s@%s-%s-%s", fs, cluster, label, ts);
    if (n < 0 || (size_t)n >= out_len) return ZEP_ERR_SYS;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zfs snapshot '%s' 2>&1", out_name);
    FILE *p = popen(cmd, "r");
    if (!p) return ZEP_ERR_ZFS;

    char errbuf[512] = {0};
    if (fread(errbuf, 1, sizeof(errbuf) - 1, p) == 0 && ferror(p)) {}
    int rc = pclose(p);
    if (rc != 0) {
        zep_log( "zfs snapshot failed: %s\n", errbuf);
        return ZEP_ERR_ZFS;
    }
    return ZEP_ERR_OK;
}

err_t zfs_send_open(const char *fs, const char *from_snap, const char *to_snap,
                    int send_all, const char *extra_opts,
                    const char *zip_cmd, const char *buf_cmd,
                    const char *resume_token,
                    const char *debug_inject_cmd, FILE **fp) {
    (void)fs;
    char cmd[4096];

    if (resume_token && resume_token[0]) {
        (void)to_snap;
        snprintf(cmd, sizeof(cmd),
            "zfs send %s -t '%s' 2>/dev/null%s%s%s%s%s%s",
            extra_opts ? extra_opts : "",
            resume_token,
            buf_cmd && buf_cmd[0] ? " | " : "",
            buf_cmd && buf_cmd[0] ? buf_cmd : "",
            zip_cmd && zip_cmd[0] ? " | " : "",
            zip_cmd && zip_cmd[0] ? zip_cmd : "",
            debug_inject_cmd && debug_inject_cmd[0] ? " | " : "",
            debug_inject_cmd && debug_inject_cmd[0] ? debug_inject_cmd : "");
    } else if (from_snap && from_snap[0]) {
        snprintf(cmd, sizeof(cmd),
            "zfs send %s %s '%s' '%s' 2>/dev/null%s%s%s%s%s%s",
            extra_opts ? extra_opts : "",
            send_all ? "-I" : "-i",
            from_snap, to_snap,
            buf_cmd && buf_cmd[0] ? " | " : "",
            buf_cmd && buf_cmd[0] ? buf_cmd : "",
            zip_cmd && zip_cmd[0] ? " | " : "",
            zip_cmd && zip_cmd[0] ? zip_cmd : "",
            debug_inject_cmd && debug_inject_cmd[0] ? " | " : "",
            debug_inject_cmd && debug_inject_cmd[0] ? debug_inject_cmd : "");
    } else {
        snprintf(cmd, sizeof(cmd),
            "zfs send %s '%s' 2>/dev/null%s%s%s%s%s%s",
            extra_opts ? extra_opts : "", to_snap,
            buf_cmd && buf_cmd[0] ? " | " : "",
            buf_cmd && buf_cmd[0] ? buf_cmd : "",
            zip_cmd && zip_cmd[0] ? " | " : "",
            zip_cmd && zip_cmd[0] ? zip_cmd : "",
            debug_inject_cmd && debug_inject_cmd[0] ? " | " : "",
            debug_inject_cmd && debug_inject_cmd[0] ? debug_inject_cmd : "");
    }

    char popen_cmd[8192];
    if (debug_inject_cmd && debug_inject_cmd[0]) {
        snprintf(popen_cmd, sizeof(popen_cmd),
                 "bash -c 'set -o pipefail; %s'", cmd);
    } else {
        snprintf(popen_cmd, sizeof(popen_cmd), "%s", cmd);
    }
    zep_log("zfs send cmd: %s\n", popen_cmd);
    *fp = popen(popen_cmd, "r");
    if (!*fp) {
        perror("popen zfs send");
        return ZEP_ERR_ZFS;
    }
    return ZEP_ERR_OK;
}

int zfs_send_close(FILE *fp) {
    if (fp) {
        int rc = pclose(fp);
        if (rc != 0) {
            zep_log( "warning: zfs send exited with code %d\n", rc);
        }
        return rc;
    }
    return 0;
}

err_t zfs_recv_open(const char *fs, const char *snap,
                    const char *extra_opts,
                    const char *unzip_cmd, const char *buf_cmd, FILE **fp) {
    (void)snap;
    char cmd[4096];

    /* build: [unzip_cmd |] [buf_cmd |] zfs recv */
    int pos = 0;
    int need_pipe = 0;
    if (unzip_cmd && unzip_cmd[0]) {
        pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, "%s", unzip_cmd);
        need_pipe = 1;
    }
    if (buf_cmd && buf_cmd[0]) {
        if (need_pipe) pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, " | ");
        pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, "%s", buf_cmd);
        need_pipe = 1;
    }
    if (need_pipe)
        pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, " | ");
    snprintf(cmd + pos, sizeof(cmd) - (size_t)pos,
             "zfs recv %s -F -u '%s' 2>/dev/null",
             extra_opts ? extra_opts : "", fs);
    *fp = popen(cmd, "w");
    if (!*fp) {
        perror("popen zfs recv");
        return ZEP_ERR_ZFS;
    }
    return ZEP_ERR_OK;
}

void zfs_recv_close(FILE *fp) {
    if (fp) {
        int rc = pclose(fp);
        if (rc != 0) {
            zep_log( "warning: zfs recv exited with code %d\n", rc);
        }
    }
}

err_t zfs_get_snapshot_guid(const char *snapshot, char *guid, size_t len) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zfs get -Hp -o value guid '%s' 2>/dev/null", snapshot);

    FILE *p = popen(cmd, "r");
    if (!p) return ZEP_ERR_ZFS;

    if (!fgets(guid, (int)len, p)) {
        pclose(p);
        return ZEP_ERR_ZFS;
    }
    pclose(p);

    size_t slen = strlen(guid);
    while (slen > 0 && (guid[slen - 1] == '\n' || guid[slen - 1] == '\r'))
        guid[--slen] = '\0';
    return ZEP_ERR_OK;
}

err_t zfs_get_latest_guid(const char *fs, char *guid, size_t len) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "zfs list -Hp -t snapshot -o name -s creation '%s' 2>/dev/null | tail -1", fs);

    FILE *p = popen(cmd, "r");
    if (!p) return ZEP_ERR_ZFS;

    char line[512];
    if (!fgets(line, sizeof(line), p)) {
        pclose(p);
        return ZEP_ERR_NO_SNAPSHOTS;
    }
    pclose(p);

    size_t slen = strlen(line);
    while (slen > 0 && (line[slen - 1] == '\n' || line[slen - 1] == '\r'))
        line[--slen] = '\0';

    if (line[0] == '\0') return ZEP_ERR_NO_SNAPSHOTS;

    return zfs_get_snapshot_guid(line, guid, len);
}

err_t zfs_snapshot_exists(const char *fs, const char *snap) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "zfs list -Hp -t snapshot -o name '%s' 2>/dev/null | grep -Fx '%s' >/dev/null 2>&1",
        fs, snap);
    int rc = system(cmd);
    return rc == 0 ? ZEP_ERR_OK : ZEP_ERR_NOT_FOUND;
}

err_t zfs_destroy_snapshot(const char *snapshot) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zfs destroy '%s' 2>&1", snapshot);
    FILE *p = popen(cmd, "r");
    if (!p) return ZEP_ERR_ZFS;
    char errbuf[512] = {0};
    if (fread(errbuf, 1, sizeof(errbuf) - 1, p) == 0 && ferror(p)) {}
    int rc = pclose(p);
    if (rc != 0) {
        zep_log( "zfs destroy failed: %s\n", errbuf);
        return ZEP_ERR_ZFS;
    }
    return ZEP_ERR_OK;
}

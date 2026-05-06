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
    fread(errbuf, 1, sizeof(errbuf) - 1, p);
    int rc = pclose(p);
    if (rc != 0) {
        fprintf(stderr, "zfs snapshot failed: %s\n", errbuf);
        return ZEP_ERR_ZFS;
    }
    return ZEP_ERR_OK;
}

err_t zfs_send_open(const char *fs, const char *from_snap, const char *to_snap, FILE **fp) {
    (void)fs;
    char cmd[2048];
    if (from_snap && from_snap[0]) {
        snprintf(cmd, sizeof(cmd),
            "zfs send -p -i '%s' '%s' 2>/dev/null | zstd -c",
            from_snap, to_snap);
    } else {
        snprintf(cmd, sizeof(cmd),
            "zfs send -p '%s' 2>/dev/null | zstd -c",
            to_snap);
    }
    *fp = popen(cmd, "r");
    if (!*fp) {
        perror("popen zfs send");
        return ZEP_ERR_ZFS;
    }
    return ZEP_ERR_OK;
}

void zfs_send_close(FILE *fp) {
    if (fp) {
        int rc = pclose(fp);
        if (rc != 0) {
            fprintf(stderr, "warning: zfs send exited with code %d\n", rc);
        }
    }
}

err_t zfs_recv_open(const char *fs, const char *snap, FILE **fp) {
    (void)snap;
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "zstd -d 2>/dev/null | zfs recv -F -u '%s' 2>/dev/null",
        fs);
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
            fprintf(stderr, "warning: zfs recv exited with code %d\n", rc);
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
    fread(errbuf, 1, sizeof(errbuf) - 1, p);
    int rc = pclose(p);
    if (rc != 0) {
        fprintf(stderr, "zfs destroy failed: %s\n", errbuf);
        return ZEP_ERR_ZFS;
    }
    return ZEP_ERR_OK;
}

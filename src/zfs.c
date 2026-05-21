/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "zfs.h"
#include "audit.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>




static FILE *audit_popen_keep(const char *cmd) {
    audit_log(AUDIT_EVT_EXEC, "zfs", cmd, -128);
    return popen(cmd, "r");
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
    *fp = audit_popen_keep(popen_cmd);
    if (!*fp) {
        audit_log(AUDIT_EVT_EXEC, "zfs", popen_cmd, -127);
        perror("popen zfs send");
        return ZEP_ERR_ZFS;
    }
    return ZEP_ERR_OK;
}

int zfs_send_close(FILE *fp) {
    (void)fp;
    if (fp) {
        int rc = pclose(fp);
        if (rc != 0) {
            zep_log( "warning: zfs send exited with code %d\n", rc);
            audit_log(AUDIT_EVT_EXEC, "zfs", "zfs send (close)", rc);
        }
        return rc;
    }
    return 0;
}

err_t zfs_get_latest_guid(const char *fs, char *guid, size_t len) {
    if (!guid || !len || !fs) return ZEP_ERR_SYS;
    guid[0] = '\0';
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zfs list -H -o name,guid -s creation -t snap '%s' 2>/dev/null | tail -1", fs);
    FILE *p = popen(cmd, "r");
    if (!p) return ZEP_ERR_SYS;
    char line[1024];
    if (fgets(line, sizeof(line), p)) {
        char *tab = strchr(line, '\t');
        if (tab) {
            *tab = '\0';
            size_t glen = strlen(tab + 1);
            while (glen > 0 && ((tab+1)[glen-1]=='\n'||(tab+1)[glen-1]=='\r')) (tab+1)[--glen]='\0';
            snprintf(guid, len, "%s", tab + 1);
        }
    }
    pclose(p);
    return ZEP_ERR_OK;
}



/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_AUDIT_H
#define ZEP_AIR_AUDIT_H

#include <sys/types.h>
#include <stdio.h>
#include <time.h>

#define AUDIT_EVT_EXEC    "exec"
#define AUDIT_EVT_HTTP    "http"
#define AUDIT_EVT_CERT    "cert"
#define AUDIT_EVT_ZEP     "zep"

#define audit_init(p)      audit_log_init((p))
#define audit_close()      audit_log_close()
#define audit_log(e,t,c,r) audit_log_write((e),(t),(c),(r))

int  audit_log_init(const char *path);
void audit_log_close(void);
int  audit_log_write(const char *event, const char *type,
                     const char *cmd, int exit_code);

#endif

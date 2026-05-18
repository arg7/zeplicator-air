/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_AUDIT_H
#define ZEP_AIR_AUDIT_H

#include <sys/types.h>
#include <stdio.h>
#include <time.h>

#define AUDIT_EVT_EXEC    "exec"
#define AUDIT_EVT_HTTP    "http"
#define AUDIT_EVT_CERT    "cert"

#define audit_init(p)      audit_log_init((p))
#define audit_close()      audit_log_close()
#define audit_log(e,t,c,r) audit_log_write((e),(t),(c),(r))
#define audit_log_err(e,t,c,r,s) audit_log_write2((e),(t),(c),(r),(s))

int  audit_log_init(const char *path);
void audit_log_close(void);
int  audit_log_write(const char *event, const char *type,
                     const char *cmd, int exit_code);
int  audit_log_write2(const char *event, const char *type,
                      const char *cmd, int exit_code,
                      const char *stderr_output);

/* Run command via popen, capturing stderr to a temp file.
 * Returns FILE* for reading stdout.
 * After reading stdout and pclose'ing the FILE*, call
 *   audit_popen_result(fp, stderr_buf, bufsz)
 * to get exit_code and captured stderr.
 * The temp file is automatically cleaned up.
 */
FILE *audit_popen(const char *cmd);
int  audit_popen_result(FILE *fp, char *stderr_buf, size_t bufsz);

#endif

/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_ZFS_H
#define ZEP_AIR_ZFS_H

#include "common.h"
#include <stdio.h>

err_t zfs_send_open(const char *fs, const char *from_snap, const char *to_snap,
                    int send_all, const char *extra_opts,
                    const char *zip_cmd, const char *buf_cmd,
                    const char *resume_token,
                    const char *debug_inject_cmd, FILE **fp);
int   zfs_send_close(FILE *fp);
err_t zfs_get_latest_guid(const char *fs, char *guid, size_t len);

#endif

/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_ZFS_H
#define ZEP_AIR_ZFS_H

#include "common.h"
#include <stdio.h>

err_t zfs_snapshot_create(const char *fs, const char *label, char *out_name, size_t out_len);
err_t zfs_snapshot_create_cluster(const char *fs, const char *cluster,
                                  const char *label, char *out_name, size_t out_len);
err_t zfs_send_open(const char *fs, const char *from_snap, const char *to_snap,
                    int send_all, const char *extra_opts,
                    const char *zip_cmd, const char *buf_cmd,
                    const char *resume_token, FILE **fp);
void  zfs_send_close(FILE *fp);
err_t zfs_recv_open(const char *fs, const char *snap,
                    const char *extra_opts,
                    const char *unzip_cmd, const char *buf_cmd, FILE **fp);
void  zfs_recv_close(FILE *fp);
err_t zfs_get_snapshot_guid(const char *snapshot, char *guid, size_t len);
err_t zfs_get_latest_guid(const char *fs, char *guid, size_t len);
err_t zfs_snapshot_exists(const char *fs, const char *snap);
err_t zfs_destroy_snapshot(const char *snapshot);

#endif

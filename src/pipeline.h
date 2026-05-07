/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_PIPELINE_H
#define ZEP_AIR_PIPELINE_H

#include "common.h"
#include "http.h"

err_t pipeline_push(const zep_config_t *cfg,
                    const http_config_t *http_cfg,
                    const char *fs, const char *label);

err_t pipeline_pull(const zep_config_t *cfg,
                    const http_config_t *http_cfg,
                    const char *fs, const char *donor_node);

err_t pipeline_resolve_fs(const char *cluster_fs, const char *mapping,
                          char *local_fs, size_t len);
int   pipeline_has_mapping(const char *cluster_fs, const char *mapping);
err_t pipeline_for_each_fs(const char *mapping,
                           void (*cb)(const char *cluster_fs, const char *local_fs,
                                      void *user), void *user);
err_t pipeline_resolve_zfs_cmd(const char *cmd, const char *mapping,
                               char *out, size_t out_len);
err_t pipeline_build_pipe_send(const char *command, int compress, int buffer,
                               const zep_config_t *cfg,
                               char *out, size_t out_len);
err_t pipeline_build_pipe_recv(const char *command, int compress, int buffer,
                               const zep_config_t *cfg,
                               char *out, size_t out_len);

#endif

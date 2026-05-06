#ifndef ZEP_AIR_HTTP_H
#define ZEP_AIR_HTTP_H

#include "common.h"

typedef struct {
    char server_url[512];
    char cert_path[ZEP_MAX_PATH];
    char key_path[ZEP_MAX_PATH];
    char ca_path[ZEP_MAX_PATH];
} http_config_t;

err_t http_put_blob(const http_config_t *cfg, const char *node,
                    const char *prefix, int part,
                    const void *data, size_t len);
err_t http_put_meta(const http_config_t *cfg, const char *node,
                    const char *prefix, const snapshot_meta_t *meta);
err_t http_get_meta(const http_config_t *cfg, const char *node,
                    const char *prefix, snapshot_meta_t *meta);
err_t http_get_blob(const http_config_t *cfg, const char *node,
                    const char *prefix, int part,
                    void **data, size_t *len);
err_t http_list_snapshots(const http_config_t *cfg, const char *node,
                          int limit, char ***prefixes, int *count);
char *http_get_json(const http_config_t *cfg, const char *path);

#endif

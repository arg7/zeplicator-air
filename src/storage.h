#ifndef ZEP_AIR_STORAGE_H
#define ZEP_AIR_STORAGE_H

#include "common.h"

err_t storage_ensure_dir(const char *root, const char *node, const char *prefix);
err_t storage_write_meta(const char *root, const char *node, const char *prefix,
                         const snapshot_meta_t *meta);
err_t storage_read_meta(const char *root, const char *node, const char *prefix,
                        snapshot_meta_t *meta);
err_t storage_write_blob(const char *root, const char *node, const char *prefix,
                         int part, const void *data, size_t len);
err_t storage_read_blob(const char *root, const char *node, const char *prefix,
                        int part, void **data, size_t *len);
err_t storage_list_prefixes(const char *root, const char *node, int limit,
                            char ***prefixes, int *count);
void  storage_free_list(char **list, int count);
void  storage_meta_free(snapshot_meta_t *meta);

#endif

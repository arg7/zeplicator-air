/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_ZSTREAM_H
#define ZEP_AIR_ZSTREAM_H

#include "common.h"

err_t zstream_parse(const void *data, size_t len,
                    char *toguid, size_t toguid_len,
                    char *fromguid, size_t fromguid_len);

err_t zstream_token_parse_offset(const char *token,
                                  uint64_t *offset_out);

/* Join split .stream files into a complete zstream blob.
 * Returns ZEP_ERR_OK on success (exit 0 or 2), ZEP_ERR_ZFS otherwise.
 * Writes toguid to *toguid_out (may be NULL). */
err_t zstream_join(const char *dir_path, const char *base_name,
                   int start_blob, int blob_count,
                   char *toguid_out, size_t toguid_len);

/* Validate a zstream token file (zstream token -g -i output).
 * Returns ZEP_ERR_OK if the token is valid (stream has data),
 * ZEP_ERR_ZFS if truncated. */
err_t zstream_token_from_file(const char *token_file);

/* Extract a zstream resume token from a file.
 * Runs `zstream token -g -i <filepath>`, writes null-terminated token
 * to *token_out (up to token_len bytes). Returns ZEP_ERR_OK on success,
 * ZEP_ERR_ZFS if the command fails or produces no token. */
err_t zstream_token_extract(const char *filepath, char *token_out, size_t token_len);

/* Accumulative zstream join for resume push.
 * If assembled_in is non-empty: joins assembled_in + new_chunk → assembled_out.
 * If assembled_in is empty: sanitizes new_chunk (strips incomplete tail) → assembled_out.
 * On success sets *complete to 1 if DRR_END found (join exit 0), 0 otherwise.
 * Returns ZEP_ERR_OK on success, ZEP_ERR_ZFS on failure. */
err_t zstream_join_accumulative(const char *assembled_in,
                                const char *new_chunk,
                                const char *assembled_out,
                                int *complete);

#endif

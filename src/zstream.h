/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_ZSTREAM_H
#define ZEP_AIR_ZSTREAM_H

#include "common.h"

err_t zstream_parse(const void *data, size_t len,
                    char *toguid, size_t toguid_len,
                    char *fromguid, size_t fromguid_len);

err_t zstream_token_generate(const void *data, size_t len,
                              char *token_out, size_t token_len);

err_t zstream_token_parse_offset(const char *token,
                                 uint64_t *offset_out);

#endif

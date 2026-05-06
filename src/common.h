#ifndef ZEP_AIR_COMMON_H
#define ZEP_AIR_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define ZEP_VERSION           "0.1.0"
#define ZEP_DEFAULT_CHUNK_SZ  (10 * 1024 * 1024)
#define ZEP_MAX_GUID_LEN      64
#define ZEP_MAX_PATH          1024
#define ZEP_MAX_LINE          4096
#define ZEP_MAX_SNAPSHOT_NAME 512
#define ZEP_DB_FILENAME       "zep-air.db"
#define ZEP_MAX_UINT32_STR    "9999999999"
#define ZEP_MAX_UINT32        9999999999UL

#define ZEP_ERR_OK            0
#define ZEP_ERR_SYS           -1
#define ZEP_ERR_ZFS           -2
#define ZEP_ERR_STORAGE       -3
#define ZEP_ERR_DB            -4
#define ZEP_ERR_NETWORK       -5
#define ZEP_ERR_CERT          -6
#define ZEP_ERR_JSON          -7
#define ZEP_ERR_CHECKSUM      -8
#define ZEP_ERR_NO_SNAPSHOTS  -9
#define ZEP_ERR_NOT_FOUND     -10

typedef int8_t err_t;

typedef struct {
    char part[8];
    size_t size;
    char sha256[65];
} blob_info_t;

typedef struct {
    char snapshot[ZEP_MAX_SNAPSHOT_NAME];
    char guid[ZEP_MAX_GUID_LEN];
    char base_guid[ZEP_MAX_GUID_LEN];
    char label[64];
    char created[32];
    char host[64];
    uint64_t stream_size;
    int blob_count;
    blob_info_t *blobs;
} snapshot_meta_t;

typedef struct {
    char cluster[64];
    char mapping[2048];
    char storage_root[ZEP_MAX_PATH];
    char server_url[512];
    char node_name[64];
    char cert_path[ZEP_MAX_PATH];
    char key_path[ZEP_MAX_PATH];
    char ca_path[ZEP_MAX_PATH];
    char key_password[128];
    size_t chunk_size;
} zep_config_t;

static inline uint32_t zep_invert_ts(time_t t) {
    return (uint32_t)(ZEP_MAX_UINT32 - (uint64_t)t);
}

#endif

/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

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

/* Logging levels — bit flags for bitmask filtering */
#define LOG_LEVEL_NONE    0x00
#define LOG_LEVEL_DEBUG   0x01
#define LOG_LEVEL_INFO    0x02
#define LOG_LEVEL_WARN    0x04
#define LOG_LEVEL_ERROR   0x08
#define LOG_LEVEL_AUDIT   0x10
#define LOG_LEVEL_ALL     (LOG_LEVEL_DEBUG | LOG_LEVEL_INFO | LOG_LEVEL_WARN | LOG_LEVEL_ERROR | LOG_LEVEL_AUDIT)

/* Default logging: INFO + WARN + ERROR (matching old --verbose behavior) */
#define LOG_LEVEL_DEFAULT (LOG_LEVEL_INFO | LOG_LEVEL_WARN | LOG_LEVEL_ERROR)

/* Global logging mask — set via --logging flag, parsed from config, etc. */
extern int g_logging;

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
    char cluster_fs[256];
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
    char send_options[128];
    char recv_options[128];
    char push_zip_cmd[128];
    char pull_unzip_cmd[128];
    char push_buf_cmd[128];
    char pull_buf_cmd[128];
    char debug_inject_zfs_pipeline_cmd[128];
    char pipe_allow[2048];
    int  send_all_snap;
    int  resume;
    size_t chunk_size;
} zep_config_t;

static inline uint32_t zep_invert_ts(time_t t) {
    return (uint32_t)(ZEP_MAX_UINT32 - (uint64_t)t);
}

/* Parse comma-separated logging levels string into bitmask.
 * Accepted: DEBUG,INFO,WARN,ERROR,AUDIT (case-insensitive) */
int zep_log_parse_mask(const char *str);

/* Set logging mask from string, then load from config DB if available.
 * Returns 0 on success. */
int zep_log_init(const char *db_path);

/* Structured logging: level-based, only fires if level is in mask. */
void zep_air_log(int level, const char *fmt, ...);

/* Convenience macros — level defaults to INFO */
#define zep_log(fmt, ...) \
    zep_air_log(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)

#define zep_log_debug(fmt, ...) \
    do { if (g_logging & LOG_LEVEL_DEBUG) zep_air_log(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__); } while(0)

#define zep_log_warn(fmt, ...) \
    do { if (g_logging & LOG_LEVEL_WARN) zep_air_log(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__); } while(0)

#define zep_log_error(fmt, ...) \
    do { if (g_logging & LOG_LEVEL_ERROR) zep_air_log(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__); } while(0)

#define zep_log_audit(fmt, ...) \
    do { if (g_logging & LOG_LEVEL_AUDIT) zep_air_log(LOG_LEVEL_AUDIT, fmt, ##__VA_ARGS__); } while(0)

/* zep_log now outputs at INFO level (default mask includes INFO) */
/* If user sets --logging=NONE, even INFO won't fire since INFO is not in mask */

#endif

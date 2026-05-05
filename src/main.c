#include "common.h"
#include "db.h"
#include "zfs.h"
#include "pipeline.h"
#include "storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>

static char g_db_path[ZEP_MAX_PATH] = "zep-air.db";

static void usage(const char *prog) {
    fprintf(stderr,
        "Zeplicator Air v%s — air-gapped ZFS replication\n"
        "\n"
        "Usage: %s <command> [options]\n"
        "\n"
        "Commands:\n"
        "  push    Push a snapshot to the storage intermediary\n"
        "  pull    Pull snapshots from the storage intermediary\n"
        "  config  Manage configuration\n"
        "  status  Show replication status\n"
        "\n"
        "Push options:\n"
        "  --filesystem, -f FS    ZFS filesystem (required)\n"
        "  --label, -l LABEL      Snapshot label (required)\n"
        "  --db PATH              Database path (default: %s)\n"
        "\n"
        "Pull options:\n"
        "  --filesystem, -f FS    ZFS filesystem (required)\n"
        "  --donor, -d NODE       Donor node name\n"
        "  --db PATH              Database path (default: %s)\n"
        "\n"
        "Config options:\n"
        "  set KEY VALUE          Set a configuration value\n"
        "  get KEY                Get a configuration value\n"
        "  list                   List all configuration\n"
        "  --db PATH              Database path (default: %s)\n"
        "\n"
        "Common config keys:\n"
        "  storage_root     Path to storage directory or mount\n"
        "  server_url       URL of zep-air-serve (for remote)\n"
        "  node_name        Name of this node\n"
        "  cert_path        Path to TLS client certificate\n"
        "  key_path         Path to TLS client key\n"
        "  ca_path          Path to CA certificate\n"
        "  chunk_size       Max blob size in bytes (default: %d)\n",
        ZEP_VERSION, prog, g_db_path, g_db_path, g_db_path, ZEP_DEFAULT_CHUNK_SZ);
}

static int cmd_push(int argc, char *argv[]) {
    char filesystem[ZEP_MAX_SNAPSHOT_NAME] = {0};
    char label[64] = {0};

    static struct option opts[] = {
        {"filesystem", required_argument, 0, 'f'},
        {"label",      required_argument, 0, 'l'},
        {"db",         required_argument, 0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "f:l:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'f': snprintf(filesystem, sizeof(filesystem), "%s", optarg); break;
            case 'l': snprintf(label, sizeof(label), "%s", optarg); break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    if (!filesystem[0] || !label[0]) {
        fprintf(stderr, "error: --filesystem and --label are required\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    zep_config_t cfg;
    db_config_load(db, &cfg);

    err_t ret = pipeline_push(db, &cfg, filesystem, label);

    db_close(db);
    return ret == ZEP_ERR_OK ? 0 : 1;
}

static int cmd_pull(int argc, char *argv[]) {
    char filesystem[ZEP_MAX_SNAPSHOT_NAME] = {0};
    char donor[64] = {0};

    static struct option opts[] = {
        {"filesystem", required_argument, 0, 'f'},
        {"donor",      required_argument, 0, 'd'},
        {"db",         required_argument, 0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "f:d:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'f': snprintf(filesystem, sizeof(filesystem), "%s", optarg); break;
            case 'd': snprintf(donor, sizeof(donor), "%s", optarg); break;
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    if (!filesystem[0]) {
        fprintf(stderr, "error: --filesystem is required\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    zep_config_t cfg;
    db_config_load(db, &cfg);

    if (!donor[0] && cfg.node_name[0]) {
        snprintf(donor, sizeof(donor), "%s", cfg.node_name);
    }

    err_t ret = pipeline_pull(db, &cfg, filesystem, donor);

    db_close(db);
    return ret == ZEP_ERR_OK ? 0 : 1;
}

static int cmd_config(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: zep-air config <set|get|list> [args]\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    int rc = 0;
    const char *sub = argv[1];

    if (strcmp(sub, "set") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: zep-air config set KEY VALUE\n");
            rc = 1;
        } else {
            if (db_config_set(db, argv[2], argv[3]) != ZEP_ERR_OK) {
                fprintf(stderr, "Failed to set config\n");
                rc = 1;
            } else {
                printf("Set %s = %s\n", argv[2], argv[3]);
            }
        }
    } else if (strcmp(sub, "get") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: zep-air config get KEY\n");
            rc = 1;
        } else {
            char value[512] = {0};
            if (db_config_get(db, argv[2], value, sizeof(value)) != ZEP_ERR_OK) {
                printf("(not set)\n");
            } else {
                printf("%s\n", value);
            }
        }
    } else if (strcmp(sub, "list") == 0) {
        zep_config_t cfg;
        db_config_load(db, &cfg);
        printf("node_name    = %s\n", cfg.node_name[0] ? cfg.node_name : "(not set)");
        printf("storage_root = %s\n", cfg.storage_root[0] ? cfg.storage_root : "(not set)");
        printf("server_url   = %s\n", cfg.server_url[0] ? cfg.server_url : "(not set)");
        printf("cert_path    = %s\n", cfg.cert_path[0] ? cfg.cert_path : "(not set)");
        printf("key_path     = %s\n", cfg.key_path[0] ? cfg.key_path : "(not set)");
        printf("ca_path      = %s\n", cfg.ca_path[0] ? cfg.ca_path : "(not set)");
        printf("chunk_size   = %zu\n", cfg.chunk_size);
    } else if (strcmp(sub, "--help") == 0 || strcmp(sub, "-h") == 0) {
        printf("Usage: zep-air config <set|get|list> [args]\n");
    } else {
        fprintf(stderr, "Unknown config command: %s\n", sub);
        rc = 1;
    }

    db_close(db);
    return rc;
}

static int cmd_status(int argc, char *argv[]) {
    static struct option opts[] = {
        {"db",   required_argument, 0, 'D'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'D': snprintf(g_db_path, sizeof(g_db_path), "%s", optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    zep_config_t cfg;
    db_config_load(db, &cfg);

    printf("=== Zeplicator Air Status ===\n");
    printf("Node: %s\n\n", cfg.node_name[0] ? cfg.node_name : "(not configured)");

    printf("Pushed snapshots:\n");
    char **pushed = NULL;
    int pushed_cnt = 0;
    db_list_pushed(db, &pushed, &pushed_cnt);
    if (pushed_cnt == 0) {
        printf("  (none)\n");
    } else {
        for (int i = 0; i < pushed_cnt; i++) {
            printf("  %s\n", pushed[i]);
        }
    }

    printf("\nPulled snapshots:\n");
    char **pulled = NULL;
    int pulled_cnt = 0;
    db_list_pulled(db, &pulled, &pulled_cnt);
    if (pulled_cnt == 0) {
        printf("  (none)\n");
    } else {
        for (int i = 0; i < pulled_cnt; i++) {
            printf("  %s\n", pulled[i]);
        }
    }

    storage_free_list(pushed, pushed_cnt);
    storage_free_list(pulled, pulled_cnt);
    db_close(db);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *argv2[64];
    int argc2 = 0;

    for (int i = 0; i < argc && argc2 < 63; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            i++;
            snprintf(g_db_path, sizeof(g_db_path), "%s", argv[i]);
        } else {
            argv2[argc2++] = argv[i];
        }
    }
    argv2[argc2] = NULL;

    if (argc2 < 2) {
        usage(argv2[0]);
        return 1;
    }

    const char *cmd = argv2[1];

    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage(argv2[0]);
        return 0;
    }

    char **sub_argv = (char **)argv2 + 1;
    int sub_argc = argc2 - 1;

    if (strcmp(cmd, "push") == 0)   return cmd_push(sub_argc, sub_argv);
    if (strcmp(cmd, "pull") == 0)   return cmd_pull(sub_argc, sub_argv);
    if (strcmp(cmd, "config") == 0) return cmd_config(sub_argc, sub_argv);
    if (strcmp(cmd, "status") == 0) return cmd_status(sub_argc, sub_argv);

    fprintf(stderr, "Unknown command: %s\n", cmd);
    usage(argv2[0]);
    return 1;
}

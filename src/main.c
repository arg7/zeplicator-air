/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "common.h"
#include "db.h"
#include "zfs.h"
#include "pipeline.h"
#include "storage.h"
#include "http.h"
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

static char g_db_path[ZEP_MAX_PATH] = "zep-air.db";

static void usage(const char *prog) {
    fprintf(stderr,
        "Zeplicator Air v%s — air-gapped ZFS replication\n"
        "\n"
        "Usage: %s <command> [options]\n"
        "\n"
        "Commands:\n"
        "  snap    Create local snapshots (no push)\n"
        "  cron    Query server for due tasks, execute push/pull\n"
        "  rotate  Purge old snapshots beyond retention (safe, skips protected)\n"
        "  push    Push a snapshot to the storage intermediary\n"
        "  pull    Pull snapshots from the storage intermediary\n"
        "  config  Manage configuration\n"
        "  status  Show replication status\n"
        "\n"
        "Snap options:\n"
        "  --filesystem, -f FS    ZFS filesystem (optional, use mapping instead)\n"
        "  --label, -l LABEL      Snapshot label (required)\n"
        "  --db PATH              Database path (default: %s)\n"
        "  [FS1 FS2 ...]          Cluster filesystem names (uses mapping)\n"
        "\n"
        "Push options:\n"
        "  --filesystem, -f FS    ZFS filesystem (optional, use mapping instead)\n"
        "  --label, -l LABEL      Snapshot label (required)\n"
        "  --db PATH              Database path (default: %s)\n"
        "  [FS1 FS2 ...]          Cluster filesystem names (uses mapping)\n"
        "\n"
        "Pull options:\n"
        "  --filesystem, -f FS    ZFS filesystem (optional, use mapping instead)\n"
        "  --donor, -d NODE       Donor node name\n"
        "  --db PATH              Database path (default: %s)\n"
        "  [FS1 FS2 ...]          Cluster filesystem names (uses mapping)\n"
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
        "  key_password     Password for encrypted key\n"
        "  chunk_size       Max blob size in bytes (default: %d)\n",
        ZEP_VERSION, prog, g_db_path, g_db_path, g_db_path, g_db_path, ZEP_DEFAULT_CHUNK_SZ);
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

    if (!label[0]) {
        fprintf(stderr, "error: --label is required\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    zep_config_t cfg;
    db_config_load(db, &cfg);

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);

    int pushed = 0;

    if (filesystem[0]) {
        err_t ret = pipeline_push(&cfg, &http_cfg, filesystem, label);
        if (ret == ZEP_ERR_OK) pushed++;
    } else if (optind < argc) {
        for (int i = optind; i < argc; i++) {
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            if (pipeline_resolve_fs(argv[i], cfg.mapping,
                                    local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                err_t ret = pipeline_push(&cfg, &http_cfg, local_fs, label);
                if (ret == ZEP_ERR_OK) pushed++;
            } else {
                fprintf(stderr, "push: no mapping for '%s'\n", argv[i]);
            }
        }
    } else if (cfg.mapping[0]) {
        const char *p = cfg.mapping;
        while (*p) {
            const char *colon = strchr(p, ':');
            if (!colon) break;
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            err_t ret = pipeline_push(&cfg, &http_cfg, local_fs, label);
            if (ret == ZEP_ERR_OK) pushed++;
            const char *comma = strchr(colon, ',');
            p = comma ? comma + 1 : colon + strlen(colon);
        }
    } else {
        fprintf(stderr, "error: no filesystem specified (use -f, positional args, or configure mapping)\n");
        db_close(db);
        return 1;
    }

    db_close(db);
    return pushed > 0 ? 0 : 1;
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

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);

    zep_config_t cfg;
    db_config_load(db, &cfg);

    if (!donor[0] && cfg.node_name[0]) {
        snprintf(donor, sizeof(donor), "%s", cfg.node_name);
    }

    if (!filesystem[0] && optind >= argc && !cfg.mapping[0]) {
        fprintf(stderr, "error: no filesystem specified (use -f, positional args, or configure mapping)\n");
        db_close(db);
        return 1;
    }

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);

    int pulled = 0;

    if (filesystem[0]) {
        err_t ret = pipeline_pull(&cfg, &http_cfg, filesystem, donor);
        if (ret == ZEP_ERR_OK) pulled++;
    } else if (optind < argc) {
        for (int i = optind; i < argc; i++) {
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            if (pipeline_resolve_fs(argv[i], cfg.mapping,
                                    local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                err_t ret = pipeline_pull(&cfg, &http_cfg, local_fs, donor);
                if (ret == ZEP_ERR_OK) pulled++;
            } else {
                fprintf(stderr, "pull: no mapping for '%s'\n", argv[i]);
            }
        }
    } else if (cfg.mapping[0]) {
        const char *p = cfg.mapping;
        while (*p) {
            const char *colon = strchr(p, ':');
            if (!colon) break;
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            err_t ret = pipeline_pull(&cfg, &http_cfg, local_fs, donor);
            if (ret == ZEP_ERR_OK) pulled++;
            const char *comma = strchr(colon, ',');
            p = comma ? comma + 1 : colon + strlen(colon);
        }
    }

    db_close(db);
    return pulled > 0 ? 0 : 1;
}

static int cmd_snap(int argc, char *argv[]) {
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
    if (!label[0]) {
        fprintf(stderr, "error: --label is required\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (db_open(g_db_path, &db) != ZEP_ERR_OK) return 1;
    db_init_tables(db);
    zep_config_t cfg;
    db_config_load(db, &cfg);

    const char *cluster = cfg.cluster[0] ? cfg.cluster : "zep";
    int created = 0;

    if (filesystem[0]) {
        char snap_name[ZEP_MAX_SNAPSHOT_NAME];
        if (zfs_snapshot_create_cluster(filesystem, cluster, label,
                                         snap_name, sizeof(snap_name)) == ZEP_ERR_OK) {
            printf("Created: %s\n", snap_name);
            created++;
        }
    } else if (optind < argc) {
        for (int i = optind; i < argc; i++) {
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            if (pipeline_resolve_fs(argv[i], cfg.mapping,
                                    local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                char snap_name[ZEP_MAX_SNAPSHOT_NAME];
                if (zfs_snapshot_create_cluster(local_fs, cluster, label,
                                                 snap_name, sizeof(snap_name)) == ZEP_ERR_OK) {
                    printf("Created: %s\n", snap_name);
                    created++;
                }
            } else {
                fprintf(stderr, "snap: no mapping for '%s'\n", argv[i]);
            }
        }
    } else if (cfg.mapping[0]) {
        const char *p = cfg.mapping;
        while (*p) {
            const char *colon = strchr(p, ':');
            if (!colon) break;
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            char snap_name[ZEP_MAX_SNAPSHOT_NAME];
            if (zfs_snapshot_create_cluster(local_fs, cluster, label,
                                             snap_name, sizeof(snap_name)) == ZEP_ERR_OK) {
                printf("Created: %s\n", snap_name);
                created++;
            }
            const char *comma = strchr(colon, ',');
            p = comma ? comma + 1 : colon + strlen(colon);
        }
    } else {
        fprintf(stderr, "error: no filesystem specified\n");
        db_close(db);
        return 1;
    }

    db_close(db);
    return created > 0 ? 0 : 1;
}

static int cmd_rotate(int argc, char *argv[]) {
    char filesystem[ZEP_MAX_SNAPSHOT_NAME] = {0};

    static struct option opts[] = {
        {"filesystem", required_argument, 0, 'f'},
        {"db",         required_argument, 0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "f:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'f': snprintf(filesystem, sizeof(filesystem), "%s", optarg); break;
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

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);

    /* get protected guids from server */
    char *pjson = http_get_json(&http_cfg,
        cfg.cluster[0] ? "" : NULL);
    char *protected_url = NULL;
    if (cfg.cluster[0])
        asprintf(&protected_url, "/v1/cron/protected?%s", cfg.cluster);

    char **protected_guids = NULL;
    int pcount = 0;
    if (cfg.cluster[0]) {
        char *pj = http_get_json(&http_cfg, protected_url);
        free(protected_url);
        if (pj) {
            cJSON *pa = cJSON_Parse(pj);
            free(pj);
            if (pa && cJSON_IsArray(pa)) {
                pcount = cJSON_GetArraySize(pa);
                protected_guids = calloc((size_t)pcount, sizeof(char *));
                for (int i = 0; i < pcount; i++) {
                    cJSON *item = cJSON_GetArrayItem(pa, i);
                    if (item && cJSON_IsString(item))
                        protected_guids[i] = strdup(item->valuestring);
                }
                cJSON_Delete(pa);
            }
        }
    }
    (void)pjson;

    int purged = 0;
    const char *p = filesystem[0] ? filesystem :
                    (optind < argc ? argv[optind] : NULL);

    if (!p && cfg.mapping[0]) {
        const char *mp = cfg.mapping;
        while (*mp) {
            const char *colon = strchr(mp, ':');
            if (!colon) break;
            char local_fs[ZEP_MAX_SNAPSHOT_NAME];
            const char *start = colon + 1;
            const char *end = strchr(start, ',');
            if (!end) end = start + strlen(start);
            const char *paren = strchr(start, '(');
            size_t n = paren ? (size_t)(paren - start) : (size_t)(end - start);
            if (n >= sizeof(local_fs)) n = sizeof(local_fs) - 1;
            memcpy(local_fs, start, n);
            local_fs[n] = '\0';
            p = local_fs;
            break;
        }
    }

    if (!p) { fprintf(stderr, "rotate: no filesystem specified\n"); db_close(db); return 1; }

    /* list snapshots for the fs */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zfs list -Hp -t snapshot -o name -s creation '%s' 2>/dev/null", p);
    FILE *fp = popen(cmd, "r");
    if (!fp) { db_close(db); return 1; }

    char line[512];
    typedef struct { char *name; char label[64]; char guid[ZEP_MAX_GUID_LEN]; } snap_t;
    snap_t *snaps = NULL;
    int scount = 0, scap = 0;

    while (fgets(line, sizeof(line), fp)) {
        size_t sl = strlen(line);
        while (sl > 0 && (line[sl-1] == '\n' || line[sl-1] == '\r')) line[--sl] = '\0';
        if (!line[0]) continue;
        if (scount >= scap) {
            scap = scap ? scap * 2 : 64;
            snaps = realloc(snaps, (size_t)scap * sizeof(snap_t));
        }
        snaps[scount].name = strdup(line);
        /* extract label: after @<cluster>-<label>- */
        char *at = strchr(line, '@');
        if (at) {
            char *dash2 = strchr(at + 1, '-');
            if (dash2) dash2 = strchr(dash2 + 1, '-');
            if (dash2) {
                size_t llen = (size_t)(dash2 - (at + 1));
                if (llen >= sizeof(snaps[scount].label)) llen = sizeof(snaps[scount].label) - 1;
                memcpy(snaps[scount].label, at + 1, llen);
                snaps[scount].label[llen] = '\0';
            }
        }
        snprintf(cmd, sizeof(cmd), "zfs get -Hp -o value guid '%s' 2>/dev/null", line);
        FILE *gp = popen(cmd, "r");
        if (gp) {
            if (fgets(snaps[scount].guid, sizeof(snaps[scount].guid), gp)) {
                size_t gsl = strlen(snaps[scount].guid);
                while (gsl > 0 && (snaps[scount].guid[gsl-1] == '\n' ||
                       snaps[scount].guid[gsl-1] == '\r'))
                    snaps[scount].guid[--gsl] = '\0';
            }
            pclose(gp);
        }
        scount++;
    }
    pclose(fp);

    /* count per label, purge excess oldest first, skip protected */
    for (int i = 0; i < scount; i++) {
        if (!snaps[i].label[0]) continue;
        int count = 0;
        for (int j = 0; j < scount; j++)
            if (strcmp(snaps[j].label, snaps[i].label) == 0) count++;

        int retention = 60; /* default */
        /* could read from cluster config, use 60 for now */

        if (count > retention && snaps[i].guid[0]) {
            int protected = 0;
            for (int k = 0; k < pcount; k++)
                if (protected_guids[k] && strcmp(protected_guids[k], snaps[i].guid) == 0)
                    { protected = 1; break; }
            if (protected) continue;

            char dcmd[1024];
            snprintf(dcmd, sizeof(dcmd), "zfs destroy '%s' 2>&1", snaps[i].name);
            FILE *dp = popen(dcmd, "r");
            if (dp) {
                char ebuf[256] = {0};
                fread(ebuf, 1, sizeof(ebuf)-1, dp);
                int rc = pclose(dp);
                if (rc == 0) {
                    printf("purged: %s (label=%s, count=%d)\n", snaps[i].name, snaps[i].label, count);
                    purged++;
                }
            }
        }
    }

    for (int i = 0; i < scount; i++) free(snaps[i].name);
    free(snaps);
    for (int i = 0; i < pcount; i++) free(protected_guids[i]);
    free(protected_guids);
    db_close(db);
    printf("rotate: purged %d snapshots\n", purged);
    return 0;
}

static int cmd_cron(int argc, char *argv[]) {
    int daemon_mode = 0;
    int interval = 60;

    static struct option opts[] = {
        {"daemon",  no_argument,       0, 'd'},
        {"interval", required_argument, 0, 'i'},
        {"db",       required_argument, 0, 'D'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "di:D:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'd': daemon_mode = 1; break;
            case 'i': interval = atoi(optarg); if (interval < 10) interval = 10; break;
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

    http_config_t http_cfg;
    memset(&http_cfg, 0, sizeof(http_cfg));
    snprintf(http_cfg.server_url, sizeof(http_cfg.server_url), "%s", cfg.server_url);
    snprintf(http_cfg.cert_path, sizeof(http_cfg.cert_path), "%s", cfg.cert_path);
    snprintf(http_cfg.key_path, sizeof(http_cfg.key_path), "%s", cfg.key_path);
    snprintf(http_cfg.ca_path, sizeof(http_cfg.ca_path), "%s", cfg.ca_path);
    snprintf(http_cfg.key_password, sizeof(http_cfg.key_password), "%s", cfg.key_password);
    db_close(db);

    do {
        char *json = http_get_json(&http_cfg, "/v1/cron/sync");
        if (!json) {
            if (daemon_mode) { sleep((unsigned int)interval); continue; }
            return 1;
        }

        cJSON *tasks = cJSON_Parse(json);
        free(json);
        if (!tasks || !cJSON_IsArray(tasks)) {
            if (tasks) cJSON_Delete(tasks);
            if (daemon_mode) { sleep((unsigned int)interval); continue; }
            return 1;
        }

        int tasks_done = 0;

        cJSON *task;
        cJSON_ArrayForEach(task, tasks) {
            cJSON *action = cJSON_GetObjectItem(task, "action");
            cJSON *cfs = cJSON_GetObjectItem(task, "cluster_fs");
            cJSON *label = cJSON_GetObjectItem(task, "label");

            if (!action || !cJSON_IsString(action)) continue;

            if (strcmp(action->valuestring, "push") == 0 &&
                cfs && cJSON_IsString(cfs) &&
                label && cJSON_IsString(label)) {
                char local_fs[ZEP_MAX_SNAPSHOT_NAME];
                if (db_open(g_db_path, &db) == ZEP_ERR_OK) {
                    db_init_tables(db);
                    zep_config_t cfg2;
                    db_config_load(db, &cfg2);
                    if (pipeline_resolve_fs(cfs->valuestring, cfg2.mapping,
                                            local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                        pipeline_push(&cfg2, &http_cfg, local_fs, label->valuestring);
                        tasks_done++;
                    }
                    db_close(db);
                }
            } else if (strcmp(action->valuestring, "sync") == 0 &&
                       cfs && cJSON_IsString(cfs)) {
                cJSON *donor = cJSON_GetObjectItem(task, "donor");
                char local_fs[ZEP_MAX_SNAPSHOT_NAME];
                if (db_open(g_db_path, &db) == ZEP_ERR_OK) {
                    db_init_tables(db);
                    zep_config_t cfg2;
                    db_config_load(db, &cfg2);
                    if (pipeline_resolve_fs(cfs->valuestring, cfg2.mapping,
                                            local_fs, sizeof(local_fs)) == ZEP_ERR_OK) {
                        pipeline_pull(&cfg2, &http_cfg, local_fs,
                                      (donor && cJSON_IsString(donor)) ? donor->valuestring : "");
                        tasks_done++;

                        /* ack latest local guid */
                        char latest[ZEP_MAX_GUID_LEN] = {0};
                        zfs_get_latest_guid(local_fs, latest, sizeof(latest));
                        if (latest[0]) {
                            char body[128];
                            snprintf(body, sizeof(body), "{\"guid\":\"%s\"}", latest);
                            http_post_json(&http_cfg, "/v1/cron/ack", body);
                        }
                    }
                    db_close(db);
                }
            }
        }
        cJSON_Delete(tasks);

        if (daemon_mode) sleep((unsigned int)interval);
    } while (daemon_mode);

    return 0;
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
    db_close(db);

    printf("=== Zeplicator Air Status ===\n");
    printf("Node:       %s\n", cfg.node_name[0] ? cfg.node_name : "(not set)");
    printf("Cluster:    %s\n", cfg.cluster[0] ? cfg.cluster : "(not set)");
    printf("Server:     %s\n", cfg.server_url[0] ? cfg.server_url : "(not set)");
    printf("Cert:       %s\n", cfg.cert_path[0] ? cfg.cert_path : "(not set)");
    printf("Mapping:    %s\n", cfg.mapping[0] ? cfg.mapping : "(not set)");
    printf("Chunk size: %zu\n", cfg.chunk_size);
    printf("\nPush/pull history is tracked on the server — no local snapshot DB.\n");
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

    if (strcmp(cmd, "rotate") == 0) return cmd_rotate(sub_argc, sub_argv);
    if (strcmp(cmd, "snap") == 0)   return cmd_snap(sub_argc, sub_argv);
    if (strcmp(cmd, "cron") == 0)   return cmd_cron(sub_argc, sub_argv);
    if (strcmp(cmd, "push") == 0)   return cmd_push(sub_argc, sub_argv);
    if (strcmp(cmd, "pull") == 0)   return cmd_pull(sub_argc, sub_argv);
    if (strcmp(cmd, "config") == 0) return cmd_config(sub_argc, sub_argv);
    if (strcmp(cmd, "status") == 0) return cmd_status(sub_argc, sub_argv);

    fprintf(stderr, "Unknown command: %s\n", cmd);
    usage(argv2[0]);
    return 1;
}

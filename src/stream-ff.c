/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "audit.h"

static int name_cmp(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --in <dir> [--unzip_cmd <cmd>] [--skip N] [--cut N]\n"
        "\n"
        "  Streams numbered chunk files from <dir> to stdout, optionally\n"
        "  decompressing with --unzip_cmd, skipping first N bytes (--skip),\n"
        "  and/or limiting output to N bytes (--cut).\n"
        "\n"
        "  If --unzip_cmd is set (e.g. \"zstd -d\"), chunks are piped through\n"
        "  it before skip/cut. Otherwise chunks are read directly (fseek for\n"
        "  skip, at chunk file granularity).\n", prog);
}

int main(int argc, char *argv[]) {
    /* parse args first to get --in dir, then init audit log */
    const char *in_dir = NULL;
    const char *unzip_cmd = NULL;
    uint64_t skip = 0, cut = 0;
    int has_skip = 0, has_cut = 0;
    const char *audit_log_path = NULL;

    static struct option opts[] = {
        {"in",        required_argument, 0, 'i'},
        {"unzip_cmd", required_argument, 0, 'u'},
        {"skip",      required_argument, 0, 's'},
        {"cut",       required_argument, 0, 'c'},
        {"audit-log", required_argument, 0, 'a'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:u:s:c:a:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'i': in_dir = optarg; break;
            case 'u': unzip_cmd = optarg; break;
            case 's': skip = (uint64_t)strtoull(optarg, NULL, 10); has_skip = 1; break;
            case 'c': cut  = (uint64_t)strtoull(optarg, NULL, 10); has_cut  = 1; break;
            case 'a': audit_log_path = optarg; break;
            case 'h': usage(argv[0]); return 0;
            default:  return 1;
        }
    }

    audit_init(audit_log_path);

    if (!in_dir) {
        usage(argv[0]);
        return 1;
    }

    DIR *d = opendir(in_dir);
    if (!d) { perror(in_dir); return 1; }

    char *files[65536];
    int nfiles = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] >= '0' && ent->d_name[0] <= '9')
            files[nfiles++] = strdup(ent->d_name);
    }
    closedir(d);

    if (nfiles == 0) {
        fprintf(stderr, "zep-stream-ff: no chunk files in %s\n", in_dir);
        return 1;
    }

    qsort(files, (size_t)nfiles, sizeof(char *), name_cmp);

    if (unzip_cmd && unzip_cmd[0]) {
        int is_zstd = (strncmp(unzip_cmd, "zstd", 4) == 0 &&
                       (!unzip_cmd[4] || unzip_cmd[4] == ' '));
        uint64_t skipped = 0, written = 0;

        for (int i = 0; i < nfiles; i++) {
            char path[4096];
            snprintf(path, sizeof(path), "%s/%s", in_dir, files[i]);

            uint64_t unc_size = 0;
            if (is_zstd && has_skip && skipped < skip) {
                char lcmd[8192];
                snprintf(lcmd, sizeof(lcmd),
                         "zstd -l -v '%s' | grep 'Decompressed Size:'", path);
                FILE *lp = popen(lcmd, "r");
                if (lp) {
                    char line[256];
                    if (fgets(line, sizeof(line), lp)) {
                        char *lparen = strrchr(line, '(');
                        if (lparen) {
                            char *rparen = strchr(lparen, ')');
                            if (rparen) *rparen = '\0';
                            unc_size = (uint64_t)strtoull(lparen + 1, NULL, 10);
                        }
                    }
                    int rc = pclose(lp);
                    audit_log(AUDIT_EVT_EXEC, "stream-ff", lcmd, WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
                }
            }

            if (unc_size > 0 && has_skip && skipped + unc_size <= skip) {
                skipped += unc_size;
                continue;
            }

            char cmd[8192];
            snprintf(cmd, sizeof(cmd), "%s < '%s'",
                     unzip_cmd, path);
            FILE *fp = popen(cmd, "r");
            if (!fp) {
                audit_log(AUDIT_EVT_EXEC, "stream-ff", cmd, -127);
                continue;
            }

            if (unc_size > 0 && has_skip && skipped < skip) {
                uint64_t discard = skip - skipped;
                skipped = skip;
                unsigned char dbuf[65536];
                while (discard > 0) {
                    size_t nr = fread(dbuf, 1,
                        sizeof(dbuf) < discard ? sizeof(dbuf) : (size_t)discard, fp);
                    if (nr == 0) break;
                    discard -= (uint64_t)nr;
                }
            }

            {
                unsigned char buf[65536];
                size_t off = 0;
                int first = 1;
                while (1) {
                    size_t nr = fread(buf, 1, sizeof(buf), fp);
                    if (nr == 0) break;

                    if (first && has_skip && skipped < skip) {
                        uint64_t rem = skip - skipped;
                        if ((uint64_t)nr <= rem) {
                            skipped += nr;
                            continue;
                        }
                        off = (size_t)rem;
                        skipped += (uint64_t)off;
                        first = 0;
                    }

                    size_t tow = nr - off;
                    if (has_cut && written + (uint64_t)tow > cut)
                        tow = (size_t)(cut - written);
                    if (tow == 0) {
                        int rc = pclose(fp);
                        audit_log(AUDIT_EVT_EXEC, "stream-ff", cmd, WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
                        goto done;
                    }

                    if (fwrite(buf + off, 1, tow, stdout) != tow) {
                        int rc = pclose(fp);
                        audit_log(AUDIT_EVT_EXEC, "stream-ff", cmd, WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
                        goto done;
                    }
                    written += (uint64_t)tow;
                    off = 0;

                    if (has_cut && written >= cut) {
                        int rc = pclose(fp);
                        audit_log(AUDIT_EVT_EXEC, "stream-ff", cmd, WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
                        goto done;
                    }
                }
            }
            int rc = pclose(fp);
            audit_log(AUDIT_EVT_EXEC, "stream-ff", cmd, WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
        }
    } else {
        uint64_t skipped = 0, written = 0;
        for (int i = 0; i < nfiles; i++) {
            char path[4096];
            snprintf(path, sizeof(path), "%s/%s", in_dir, files[i]);

            struct stat st;
            if (stat(path, &st) != 0) continue;
            uint64_t fsz = (uint64_t)st.st_size;

            if (has_skip && skipped + fsz <= skip) {
                skipped += fsz;
                continue;
            }

            FILE *fp = fopen(path, "rb");
            if (!fp) continue;

            if (has_skip && skipped < skip) {
                uint64_t off = skip - skipped;
                skipped = skip;
                fseek(fp, (long)off, SEEK_SET);
            }

            unsigned char buf[65536];
            while (1) {
                size_t nr = fread(buf, 1, sizeof(buf), fp);
                if (nr == 0) break;

                if (has_cut && written + (uint64_t)nr > cut)
                    nr = (size_t)(cut - written);

                if (fwrite(buf, 1, nr, stdout) != nr) {
                    fclose(fp);
                    goto done;
                }
                written += (uint64_t)nr;

                if (has_cut && written >= cut) {
                    fclose(fp);
                    goto done;
                }
            }
            fclose(fp);
        }
    }

done:
    fflush(stdout);
    for (int i = 0; i < nfiles; i++) free(files[i]);
    audit_close();
    return 0;
}

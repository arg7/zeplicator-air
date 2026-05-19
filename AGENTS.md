# AGENTS.md — Zeplicator Air Development Guide

## Overview

Zeplicator Air is an air-gapped ZFS replication system in pure C (~4,600 LOC). No SSH between nodes — a central HTTPS server (`zep-air-serve`) is the sole communication channel. Nodes push ZFS snapshots to it and pull from it. Mutual TLS authenticates every connection.

```
master ──push──▶ [zep-air-serve] ◀──pull── client
```

## Build

```sh
# Dependencies (Debian)
sudo apt install gcc make libcurl4-openssl-dev libssl-dev libsqlite3-dev \
  libcjson-dev libmicrohttpd-dev libzstd-dev libgnutls28-dev zfsutils-linux

make            # three binaries: zep-air, zep-air-serve, zep-air-admin

After modifying sources, always do a clean stop → install → start cycle. Do not just restart individual daemons — the old binary remains running under the cron daemon wrapper. Ensure all binaries are fully stopped before install; otherwise the old binary stays locked.

```sh
sudo cluster/cluster-ctl.sh stop
sudo make install
sudo cluster/cluster-ctl.sh start
```

## Three Binaries

| Binary | Role | Source |
|--------|------|--------|
| `zep-air-serve` | HTTPS server (MHD/GnuTLS), REST API, SQLite, chain tracking | `src/serve.c` |
| `zep-air` | Node agent: push, pull, snap, rotate, cron daemon | `src/main.c` |
| `zep-air-admin` | Remote admin tool (libcurl): cluster, nodes, suspend, promote | `src/admin.c` |

## Key Source Files

| File | LOC | Purpose |
|------|-----|---------|
| `src/serve.c` | 1246 | MHD server, all REST handlers, admin API, cron sync, zstream verify |
| `src/main.c` | 754 | CLI dispatcher, push/pull/snap/cron/rotate commands |
| `src/admin.c` | 547 | libcurl client for remote admin — cluster, join, suspend, config |
| `src/db.c` | 449 | SQLite: config KV, auth (certs+roles), cluster_chain, push/pull tracking |
| `src/pipeline.c` | 383 | Push/pull orchestration, mapping resolver, SHA256, chunking |
| `src/http.c` | 314 | libcurl HTTP client with mTLS, PUT/GET blobs+meta |
| `src/zfs.c` | 209 | Shells out to `zfs`/`zstd` — snapshot, send, recv, guid queries |
| `src/auth.c` | 161 | OpenSSL: X.509 CN extraction, fingerprint, CA verification |
| `src/storage.c` | 245 | Filesystem blob store: meta.json, blob files, directory layout |
| `src/zstream.c` | 62 | Parses `zstream dump -v` output for toguid/fromguid |
| `test/cluster_smoke.sh` | 206 | 12-test suite with 3 isolated ZFS users over HTTPS |
| `pki/mk-ca.sh` | 118 | Creates CA, server cert, admin cert |
| `pki/mk-node.sh` | 97 | Creates per-node cert+key .pem bundle |

## Data Flow

### Push (zep-air → server)
```
zfs snapshot → zfs send → [buf_cmd |] [zip_cmd] → chunk → SHA256 → HTTPS PUT blob → PUT meta.json
```
Server verifies: reassembles blobs → `zstd -d` → `zstream dump -v` → extracts toguid/fromguid → stores in `cluster_chain`.

### Pull (server → zep-air)
```
GET snapshot list → GET meta.json → GET blobs → SHA256 verify → reassemble → [unzip_cmd |] [buf_cmd |] zfs recv
```

### Cron (zep-air daemon)
```
GET /v1/cron/sync → execute tasks → POST /v1/cron/ack → GET /v1/cron/protected → rotate
```
Server returns due labels for masters, filesystem list for clients. Nodes never query local ZFS for discovery — the server SQLite is the source of truth.

## Server State (SQLite)

The server DB (`zep-air.db`) is authoritative. Tables:

| Table | Purpose |
|-------|---------|
| `config` | Key-value store (cluster definitions, cron timestamps) |
| `auth` | Certificates, roles (`server|admin|master|client`), cluster membership, suspended flag, last ack |
| `cluster_chain` | Canonical GUID chain per cluster (`UNIQUE(cluster_key, toguid)`) |
| `pushed`/`pulled` | Legacy local tracking (deprecated — server is source of truth) |

### Key config keys (server-side)
| Key | Example |
|-----|---------|
| `cluster_<name>` | Cluster JSON definition |
| `cron_last_<cluster>_<fs>_<label>` | Last push timestamp |
| `send_options` / `recv_options` | Extra ZFS flags per node |
| `push_zip_cmd` / `pull_unzip_cmd` | Compression pipeline |
| `push_buf_cmd` / `pull_buf_cmd` | Buffer command (mbuffer) |

### Key config keys (node-side, local SQLite)
| Key | Example |
|-----|---------|
| `node_name` | Must match cert CN |
| `server_url` | `https://master.zep.lan:8443` |
| `cert_path` / `key_path` / `ca_path` | TLS credentials |
| `key_password` | For encrypted keys |
| `cluster` | Cluster name |
| `mapping` | `cluster_fs:local_fs(label:ret,...),...` |

## Client Cert Auth Flow

1. TLS handshake — server verifies client cert is signed by CA (`MHD_OPTION_HTTPS_MEM_TRUST`)
2. Server extracts cert from GnuTLS session via `gnutls_certificate_get_peers()`
3. Computes SHA256 fingerprint, looks up role in `auth` table
4. Admin routes (`/v1/admin/*`) require `role = admin`
5. New certs are auto-registered if not found

## REST API Quick Reference

```
GET  /health                          Always 200 (no auth)
# Data routes
PUT  /v1/nodes/<n>/snapshots/<p>/meta
PUT  /v1/nodes/<n>/snapshots/<p>/blobs/<N>
GET  /v1/nodes/<n>/snapshots
GET  /v1/nodes/<n>/snapshots/<p>/meta.json
GET  /v1/nodes/<n>/snapshots/<p>/blobs/<N>
# Admin routes (admin cert required)
POST /v1/admin/clusters
GET  /v1/admin/clusters[/<name>]
DELETE /v1/admin/clusters/<name>
POST /v1/admin/nodes
GET  /v1/admin/nodes
DELETE /v1/admin/nodes/<cn>
GET|POST|DELETE /v1/admin/config[/<key>]
POST /v1/admin/suspend[/master|clients|<cn>]
POST /v1/admin/resume[/master|clients|<cn>]
POST /v1/admin/promote/<cn>
POST /v1/admin/rollback/<snap>
POST /v1/admin/snap/<name>
POST /v1/admin/unsnap/<name>
# Cron
GET  /v1/cron/sync
POST /v1/cron/ack
GET  /v1/cron/protected?<cluster>
```

## Storage Layout

```
<storage_root>/<node>/<inverted_ts>-<guid>/
    meta.json       ← snapshot metadata (GUID, base_guid, label, blobs[])
    0000, 0001...   ← zstd-compressed chunks, SHA256-checksummed
```

Inverted timestamp (`MAX_UINT32 - unix_ts`) ensures reverse-chronological order on LIST.

## Error Handling Convention

Functions return `err_t` (typedef `int8_t`). Defined in `src/common.h`:
`ZEP_ERR_OK (0)`, `ZEP_ERR_SYS`, `ZEP_ERR_ZFS`, `ZEP_ERR_STORAGE`, `ZEP_ERR_DB`, `ZEP_ERR_NETWORK`, `ZEP_ERR_CERT`, `ZEP_ERR_JSON`, `ZEP_ERR_CHECKSUM`, `ZEP_ERR_NO_SNAPSHOTS`, `ZEP_ERR_NOT_FOUND`.

Positive values = errors. Check with `if (ret != ZEP_ERR_OK)`.

## Testing

```sh
sudo test/cluster_smoke.sh
```

Creates 3 isolated users (`za-master`, `za-client-1`, `za-client-2`), each with a loopback ZFS pool, PKI certs, starts a TLS server, runs 12 tests. All over HTTPS. Needs root (for ZFS pool creation). Destroys everything on cleanup.

The test is sensitive to other ZFS activity on the system (background `zpool destroy` can block operations).

## Common Gotchas

1. **DB ownership**: `zep-air-serve --setup` runs as root and creates the DB owned by root. The daemon must own the DB file to write. Solution: `chown` after setup, or run setup as the same user.

2. **Client certs not requested by MHD**: MHD 1.0.3 with `MHD_OPTION_HTTPS_MEM_TRUST` alone doesn't request client certs. The workaround uses `gnutls_certificate_get_peers()` on the GnuTLS session to extract the cert even if MHD doesn't expose it.

3. **`zfs allow` permissions**: The `receive` delegated permission requires both `mount` and `create`. Always grant: `clone,create,destroy,mount,promote,receive,rollback,send,snapshot`.

4. **Snapshot name collisions**: Snapshots use second-precision timestamps. Two rapid pushes within the same second will collide on name. The `snap` command uses cluster-aware naming: `<fs>@<cluster>-<label>-<timestamp>`.

5. **Incremental send detection**: Base GUID is obtained BEFORE creating the new snapshot. Getting it after would return the new snapshot's GUID. Don't do that.

6. **Pull ordering**: Snapshots are processed oldest-first (chronological). Full sends (base_guid empty) must be pulled before incrementals. The loop iterates from `prefix_count - 1` down to `0`.

7. **Getopt `+` prefix**: Using `+` in getopt option strings stops at the first non-option argument. Used in subcommands where the first arg is the subcommand name. For sub-subcommands (e.g., `cluster set`), DON'T use `+` because the sub-subcommand ("set") would stop parsing.

8. **Combined .pem files**: `--key` flag is optional — defaults to `--cert` path. The `.pem` file contains both cert and key. OpenSSL/curl handle this natively.

## Build Flags

- `-D_GNU_SOURCE` required for `asprintf`, `strptime`
- Server links `-lgnutls` (for `gnutls_certificate_get_peers`, `gnutls_x509_crt_*`)
- All binaries link `-lssl -lcrypto -lcurl -lsqlite3 -lcjson -lzstd -lm`
- MHD linked via pkg-config (GnuTLS backend on Debian)

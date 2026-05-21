# AGENTS.md — Zeplicator Air Development Guide

## Roles

| Role | Name | Responsibility |
|------|------|----------------|
| Architect | AR | Sets direction, defines success criteria, reviews decisions, approves changes |
| Agent | AXIS | Executes tasks, writes code, runs tests, surfaces conflicts and uncertainties |

AR is the sole decision-maker. AXIS executes — it does not second-guess requirements, merge conflicting patterns, or silently skip failures. AXIS asks clarifying questions when direction is unclear and surfaces uncertainty instead of guessing.

## Overview

Zeplicator Air is an air-gapped ZFS replication system in pure C (~7500 LOC). No SSH between nodes — a central HTTPS server (`zep-air-serve`) is the sole communication channel. Nodes push ZFS snapshots to it and pull from it. Mutual TLS authenticates every connection. Nodes maintain persistent WebSocket connections to the server for real-time task dispatch.

```
master ──push──▶ [zep-air-serve] ◀──pull── client
         ↕ WS (tasks, discovery, keepalive)
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

`START_CLIENTS=0` in `cluster/cluster.env` for master-only testing. `cluster-ctl.sh start` cleans `/tmp/zep-*.log` on each invocation.

## Three Binaries

| Binary | Role | Source |
|--------|------|--------|
| `zep-air-serve` | HTTPS server (MHD/GnuTLS), REST API, SQLite, chain tracking, WS node/pipe endpoints | `src/serve.c` |
| `zep-air` | Node agent: push, pull, snap, cron daemon (WS-based task dispatch) | `src/main.c` |
| `zep-air-admin` | Remote admin tool (libcurl): cluster, nodes, suspend, promote | `src/admin.c` |

## Key Source Files

| File | LOC | Purpose |
|------|-----|---------|
| `src/serve.c` | 3297 | MHD server, all REST handlers, admin API, cron sync, zstream verify, WS node/pipe endpoints |
| `src/main.c` | 1542 | CLI dispatcher, push/pull/snap/cron commands, WS node client with custom frame protocol |
| `src/admin.c` | 1155 | libcurl client for remote admin — cluster, join, suspend, config |
| `src/db.c` | 664 | SQLite: config KV, auth (certs+roles), cluster_chain, push/pull tracking |
| `src/stream-ff.c` | 242 | Stream forwarder for pipe/WS bridging |
| `src/audit.c` | 171 | Audit logging (stderr-based) |
| `src/http.c` | 166 | libcurl HTTP client with mTLS, PUT/GET blobs+meta |
| `src/zfs.c` | 115 | Shells out to `zfs`/`zstd` — snapshot, send, recv, guid queries |
| `src/zstream.c` | 110 | Parses `zstream dump -v` output for toguid/fromguid |
| `src/auth.c` | 74 | OpenSSL: X.509 CN extraction, fingerprint, CA verification |
| `src/pipeline.c` | 43 | Push/pull orchestration, mapping resolver, SHA256, chunking |
| `test/cluster_smoke.sh` | 203 | 12-test suite with 3 isolated ZFS users over HTTPS |
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
Server returns due labels for masters, filesystem list for clients. Discovery is node-initiated via WS TEXT message (`{"action":"discovery","snaps":[...]}`) after WS connect — avoids MHD 1.0.1 GnuTLS socketpair forwarding bug when server initiates. Nodes never query local ZFS for discovery — the server SQLite is the source of truth.

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
# WebSocket upgrade routes
GET  /v1/ws/node?cn=<name>           WebSocket upgrade (node agent connection)
GET  /v1/ws/pipe?cn=<name>           WebSocket upgrade (admin pipe bridge)
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
POST /v1/admin/pipe                  Start pipe (admin → node subprocess)
# Cron (HTTP-based, used by cron daemon)
GET  /v1/cron/sync                    Generate sync tasks based on label intervals
POST /v1/cron/ack                     Acknowledge task completion, update cron_last_*
GET  /v1/cron/protected?<cluster>     List protected GUIDs (prevent rollback deletion)
GET  /v1/cron/rotation?cluster=<c>    Get rotation candidates for a cluster
POST /v1/cron/rotate-ack              Report rotation results (deleted/remaining GUIDs)
POST /v1/cron/inventory               Register snapshot inventory from node
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

9. **MHD 1.0.1 GnuTLS socketpair bug**: Server cannot receive data through socketpair when initiating communication. Workaround: node-initiated discovery — node sends `{"action":"discovery","snaps":[...]}` as first WS TEXT message after connecting.

10. **`MHD_upgrade_action` SEGV**: Calling `MHD_upgrade_action(MHD_UPGRADE_ACTION_CLOSE)` from a worker thread crashes in MHD's internal code (corrupted state). Removed entirely; MHD handles cleanup on thread exit.

11. **`cJSON_Delete` on child arrays**: Deleting a parent object (e.g., `cJSON_Delete(discovery)`) frees child arrays (e.g., `snaps`). Calling `cJSON_GetArraySize(snaps)` after delete is use-after-free. Save `cJSON_GetArraySize()` before delete.

## Build Flags

- `-D_GNU_SOURCE` required for `asprintf`, `strptime`
- Server links `-lgnutls` (for `gnutls_certificate_get_peers`, `gnutls_x509_crt_*`)
- All binaries link `-lssl -lcrypto -lcurl -lsqlite3 -lcjson -lzstd -lm`
- MHD linked via pkg-config (GnuTLS backend on Debian)

## MISC

Be carefull to not dump binary data to TTY.

## RULES

1. think before coding: state assumptions, don't guess. AXIS can't read AR's mind, stop hoping it will

2. simplicity first: minimum code, no speculative abstractions. the moment AXIS adds "for future flexibility," it'll add 200 lines it'll delete next quarter

3. surgical changes: touch only what you must. don't let AXIS improve adjacent code, that's how PRs blow up

4. goal-driven execution: define success criteria upfront, loop until verified. without them AXIS either loops forever or stops too early

5. use AXIS only for judgment calls: classification, drafting, summarization, extraction. NOT routing, retries, status-code handling, deterministic transforms. if code can answer, code answers

6. token budgets are not advisory: per-task 4000, per-session 30000. by message 40 of a long debug, AXIS is re-suggesting fixes AR rejected at message 5

7. surface conflicts, don't average them: two patterns in the codebase? AR picks one. AXIS doesn't blend them — that's how errors get swallowed twice

8. read before you write: read exports, callers, shared utilities. AXIS will happily add a duplicate function next to an identical one it never read

9. tests verify intent, not just behavior: a test that can't fail when business logic changes is wrong. all 12 of the tests can pass while the function returns a constant

10. checkpoint every significant step: AXIS finished steps 5 and 6 on top of a broken state from step 4. nobody noticed for an hour

11. match the codebase conventions: class components? don't fork to hooks silently. testing patterns assumed componentDidMount, hooks broke them without surfacing

12. fail loud: "completed successfully" with 14% of records silently skipped is the worst class of bug. AXIS surfaces uncertainty, doesn't hide it

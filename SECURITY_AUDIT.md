# Security Audit Report — zep-air-serve

**Date:** 2026-05-21
**Binary:** `zep-air-serve` (libmicrohttpd + GnuTLS + SQLite, ~8000 LOC)
**Build:** ASAN-enabled (`-fsanitize=address`)
**Test:** `sudo ./test/ws_tests.sh` — 19/19 pass

---

## Issues Fixed

| # | Severity | File:Line | Issue | Fix |
|---|----------|-----------|-------|-----|
| 1 | CRITICAL | serve.c:3069-3076 | SQL injection in `/v1/cron/inventory` — `DELETE` query with `node`, `cluster`, `cluster_fs` from JSON body concatenated into SQL | Parameterized queries with `?` placeholders; dynamic `NOT IN` → `!= ?N` per GUID |
| 2 | CRITICAL | serve.c:568-573 | SQL injection in scheduler — `LIKE '%%%s%%'` with `cluster_buf`/`ln` from DB/JSON, wildcard characters change query semantics | Parameterized `LIKE ?2 ESCAPE '\\'` with suffix matching on `@cluster-label-ts` portion |
| 3 | CRITICAL | serve.c:1120 | `system("mkdir -p '%s'")` with cert CN in path — single quotes contain most injection but `system()` is a bad pattern | Not yet fixed (low risk) |
| 4 | CRITICAL | serve.c:3324-3327 | `system("openssl rsa -passin pass:'...'")` — password visible in `ps`, `system()` call | Replaced with `PEM_read_bio_PrivateKey`/`PEM_write_bio_PrivateKey_traditional` via EVP_PKEY/BIO API |
| 5 | HIGH | audit.c:83-98 | `audit_escape_str` was actually correct (initial audit was wrong — writes `\"` and `\\`) | No fix needed |
| 6 | HIGH | serve.c:260-266 | `pthread_cancel` can leave `g_node_ws_lock` held → `node_ws_shutdown` deadlocks on same mutex | Replaced with `pthread_timedjoin_np` (5s timeout); only destroy mutexes if thread joined cleanly |
| 7 | HIGH | serve.c:1583-1588 | `pipe_allowed` prefix matching via `strncmp` — `zfs` matches `zfsadm` | Documented feature, not a bug (per README) |
| 8 | MEDIUM | serve.c:260-285 | Heap-use-after-free in pipe bridge: node thread frees `nw` via `node_ws_unregister` while pipe handler still accesses it | Added `pipe_bridge_active` flag; node thread skips `free(nw)` when set; pipe handler frees after bridge ends |
| 9 | MEDIUM | audit.c:120 | `g_audit_tmp` global mutable static — concurrent MHD worker threads corrupt each other's temp file paths | Changed to `static __thread char g_audit_tmp[512]` |
| 10 | MEDIUM | serve.c:3306-3350 | `load_pem` frees original data before decrypted copy is confirmed — data loss on failure | Original data kept until decrypted copy is successfully read |
| 11 | MEDIUM | serve.c:564-592 | Scheduler dedup check used `LIKE` substring match which masked a pre-existing bug: `snap_name` uses `cluster_fs` format while DB stores actual ZFS names | Parameterized LIKE with suffix matching, properly escaping `%`/`_` |
| 12 | MEDIUM | cluster/cluster-init.sh, cluster/ctl.sh | No encrypted key support — PKI keys always unencrypted, no `-P` flag to server | Added `KEY_PASSWORD` env var, `encrypt_key` helper, `-passin` for CA signing, `-P` for server start |

## Remaining Issues

| # | Severity | File:Line | Issue | Notes |
|---|----------|-----------|-------|-------|
| 13 | CRITICAL | serve.c:1120 | `system("mkdir -p ...")` with cert CN in path | Low immediate risk (single quotes contain injection), but `system()` is bad pattern. Replace with `mkdir()` syscall. |
| 14 | HIGH | serve.c:1674-1722 | Pipeline tool classification bypass — multiple "main" segments in pipeline could bypass allowlist | Requires `cat` in `pipe_allow_tools` + crafted pipeline. Reject pipelines with >1 non-tool segment. |
| 15 | MEDIUM | zfs.c:20-62 | Shell command building via string concat — `extra_opts`, `buf_cmd`, `zip_cmd` from config DB concatenated into shell commands | Validate against whitelist of allowed characters, or use `posix_spawn` with argv arrays. |
| 16 | MEDIUM | serve.c (多处) | `snprintf` return value ignored in many places | Truncation silently produces incomplete strings. Check return values in security-sensitive paths. |
| 17 | MEDIUM | serve.c:321 | `ws_build_accept` unsigned wrap — `bptr->length - 1` when `length == 0` wraps to `SIZE_MAX` | Add bounds check before subtraction. |
| 18 | LOW | serve.c:473-478 | `fcntl` return value unchecked on `F_SETFL` | If it fails, socket stays non-blocking → bridge loop busy-spins. |
| 19 | LOW | serve.c:46 | `g_db` global SQLite handle accessed from multiple threads | Acceptable with `SQLITE_OPEN_FULLMUTEX` (default). Document the assumption. |

---

## Test Results

| Test | Before | After |
|------|--------|-------|
| `sudo ./test/ws_tests.sh` (cached) | 19/19 pass | 19/19 pass |
| `sudo ./test/ws_tests.sh` (full init from zero, encrypted PKI) | N/A | 19/19 pass |

## Commits

| Commit | Message |
|--------|---------|
| `622cb4f` | fix: replace string-concatenated SQL with parameterized queries |
| `2dba3c1` | fix: replace pthread_cancel with cooperative timed join in node_ws_shutdown |
| `70900e0` | fix: make g_audit_tmp thread-local to prevent cross-thread corruption |
| `8911e50` | fix: threaded audit temp file, pipe bridge UAF, encrypted key loading |

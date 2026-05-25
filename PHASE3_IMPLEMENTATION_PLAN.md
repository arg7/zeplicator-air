# Phase 3 Implementation Plan — Resume Push with Chunked Streaming

## Overview

Implement the complete resume push workflow: master node pushes ZFS snapshots via WebSocket, server receives chunked `.stream` files, validates each chunk with `zstream token`, retries on failure, and joins all chunks into `stream.zfs` on success. The server manages the retry loop; the node simply runs `zfs send` and streams data.

## 1. Schema Changes

### Drop `snapshot_upload` table

```sql
DROP TABLE IF EXISTS snapshot_upload;
```

### Create `fs` table

```sql
CREATE TABLE IF NOT EXISTS fs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster           TEXT NOT NULL,
    fs                TEXT NOT NULL,
    last_pushed_guid  TEXT NOT NULL DEFAULT '',
    last_pulled_guid  TEXT NOT NULL DEFAULT '',
    push_resume_token TEXT NOT NULL DEFAULT '',
    push_bytes_recv   BIGINT NOT NULL DEFAULT 0,
    push_status       TEXT NOT NULL DEFAULT 'pending',
    UNIQUE(cluster, fs)
);
```

**`push_status` values:** `pending` → `pushing` → `resuming` (on failure) → `pushed` (on success)

### Add `id` column to `snapshots` table

```sql
ALTER TABLE snapshots ADD COLUMN id INTEGER PRIMARY KEY AUTOINCREMENT;
```

Monotonic auto-increment for reliable snapshot ordering (lexicographic snapshot name comparison is unreliable due to interleaved labels).

### Migration

Not needed — clean slate.

## 2. New DB Functions (db.c / db.h)

### Remove

| Function | Replaced By |
|----------|-------------|
| `db_upload_get_offset(db, guid, buf, len)` | `db_fs_get_push_resume(db, cluster, fs, buf, len)` |
| `db_upload_save_token(db, guid, node, token, bytes)` | `db_fs_save_push_resume(db, cluster, fs, token, bytes)` |
| `db_upload_complete(db, guid)` | `db_fs_clear_push_resume(db, cluster, fs)` |
| `db_upload_has_incomplete(db, node)` | `db_fs_has_push_resume(db, cluster)` |

### Add

| Function | Purpose |
|----------|---------|
| `db_fs_get_push_resume(db, cluster, fs, token_buf, len)` | Returns `push_resume_token` for a cluster/fs pair. Returns `ZEP_ERR_OK` if set, `ZEP_ERR_NOT_FOUND` if empty. |
| `db_fs_save_push_resume(db, cluster, fs, token, bytes)` | Upserts `push_resume_token`, `push_bytes_recv` into `fs` table, sets `push_status='resuming'`. |
| `db_fs_clear_push_resume(db, cluster, fs)` | Clears `push_resume_token` and `push_bytes_recv`, sets `push_status='pending'`. |
| `db_fs_has_push_resume(db, cluster)` | Returns 1 if any fs in cluster has `push_status='resuming'`, 0 otherwise. |
| `db_fs_get_resume_entry(db, cluster, out_cluster, out_fs, out_token)` | Gets one `resuming` entry for cron retry: `SELECT cluster, fs, push_resume_token FROM fs WHERE push_status='resuming' AND push_resume_token != '' LIMIT 1`. Fills output buffers. Returns `ZEP_ERR_OK` if found. |

## 3. zstream Utilities (zstream.c / zstream.h)

### Add

| Function | Purpose |
|----------|---------|
| `zstream_join(dir_path, output_path)` | Runs `zstream join -i <dir>/*.stream > <output_path>`. Returns 0 on success, non-zero on failure. |
| `zstream_token_from_file(filepath, token_buf, len)` | Runs `zstream token -g -i <filepath>`, extracts token from stdout. Returns 0 on success, non-zero on failure. Token is null-terminated in `token_buf`. |
| `zstream_token_parse(buf, token_buf, len)` | Parses a token string and extracts the byte offset (for debugging/logging). |

## 4. Server Push Orchestration Loop (serve.c)

### Location

`node_ws_thread()` in `src/serve.c`, within the `push` action handler (currently around line 1160).

### Flow

```
Loop (per WS connection):

  1. Query fs WHERE push_status='resuming' AND push_resume_token != ''
     → If found: resume path (step 5)

  2. Query snapshots WHERE status='pending' AND direction='push' AND node=?
     → Group by cluster_fs, pick latest per fs (highest id)
     → If none found: print "push: phase 3 complete", break loop

  3. For each pending snapshot:
     a. Get cluster from auth table (cn → cluster)
     b. Get cluster_fs from snapshot name (before @)
     c. fs.push_status = 'pushing'

  4. Send push task via WS to node:
     {"action":"push","guid":"<guid>","snapshot":"<snap>","label":"<lbl>",
      "cluster_fs":"<cfs>","resume_token":""}

  5. (Resume path) If fs has push_resume_token:
     a. Send push task with resume_token:
        {"action":"push","guid":"<guid>","snapshot":"<snap>","label":"<lbl>",
         "cluster_fs":"<cfs>","resume_token":"<token>"}
     b. fs.push_status = 'pushing'

  6. Node streams data via WS BIN frames:
     a. Server writes each BIN frame to <NNNN>.stream file
     b. File naming: <storage_root>/<cn>/<inverted_ts>-<guid>/<NNNN>.stream
        (4-digit padded, 0000, 0001, ...)
     c. On resume: scan for existing .stream files, start numbering from last+1

  7. Node sends exit code (WS_OP_EXIT):
     a. If exit code != 0 → failure (truncated by head)
     b. If exit code == 0 → success (full stream received)

  8. On FAILURE:
     a. Run zstream token -g -i on last .stream chunk
     b. If token valid: save token to fs.push_resume_token, increment counter
     c. If token invalid: reuse previous token (don't increment)
     d. fs.push_status = 'resuming'
     e. UPDATE snapshots SET status='failed' WHERE node=? AND guid=? AND status='pushing'
     f. Loop back to step 1

  9. On SUCCESS:
     a. zstream join *.stream → stream.zfs
     b. If only one chunk (0000.stream): rename to stream.zfs
     c. rm *.stream (clean partials)
     d. UPDATE snapshots SET status='verified', push_status='pushed',
        blob_count=?, blob_size=? WHERE node=? AND guid=? AND status='pushing'
     e. CASCADE: UPDATE snapshots SET status='verified', push_status='pushed'
        WHERE node=? AND cluster_fs=? AND status='pending' AND id < <pushed_snap_id>
     f. fs.last_pushed_guid = pushed guid
     g. fs.push_status = 'pushed'
     h. db_fs_clear_push_resume() (clear token/bytes)
     i. Loop back to step 1

  10. When no more pending or resuming snapshots:
      print "push: phase 3 complete", break
```

### Key Implementation Details

- **Blob file naming:** `<NNNN>.stream` (not bare `0000` as currently)
- **Resume offset:** On resume, scan for existing `.stream` files, start numbering from last+1
- **Chunk validation:** After node finishes sending (WS_OP_EXIT received), server runs `zstream token -g -i` on the last `.stream` file:
  - Exit 0 → chunk is valid, save token, increment counter, retry
  - Exit non-zero → chunk is truncated, reuse previous token, retry
- **zstream join:** `zstream join -i <dir>/*.stream > <dir>/stream.zfs`
  - On success: rename/join complete, clean partials
  - On failure (exit 2 = no DRR_END): treat as success for split chunks (expected behavior)
- **Cascade update:** All earlier pending snapshots for the same `cluster_fs` are marked verified when the latest one succeeds (they're contained within it)

### Current Code Reference Points

- Push handler: `serve.c` lines ~1160-1467
- Cron retry pass: `serve.c` lines ~2601-2630
- Incomplete check: `serve.c` line ~2930

## 5. Cron Sync Updates (serve.c)

### Retry Pass (serve.c:2601-2630)

Replace:
```sql
SELECT su.guid, su.resume_token, s.cluster_fs, s.label
FROM snapshot_upload su JOIN snapshots s ON s.guid = su.guid
WHERE su.node = ? AND su.complete = 0
  AND s.status = 'failed' AND s.direction = 'push' LIMIT 1
```

With:
```sql
SELECT cluster, fs, push_resume_token FROM fs
WHERE push_status = 'resuming' AND push_resume_token != '' LIMIT 1
```

Send push task with `resume_token` from the result, along with `cluster_fs` and `label` (looked up from snapshots table using the `last_pushed_guid` or a separate query).

### Incomplete Check (serve.c:2930)

Replace:
```c
if (g_resume && db_upload_has_incomplete(g_db, ctx->node))
```

With:
```c
if (g_resume && db_fs_has_push_resume(g_db, cluster_param))
```

## 6. Test Updates (test/ws_tests.sh)

### Phase 3 Assertions (Step 8)

Current test already waits for `"push: phase 3 complete"`. Update to verify:

- **Chunked .stream files:** During interrupted pushes, `.stream` files exist in storage
- **Final stream.zfs:** Exists after successful join
- **No leftover partials:** `find <store>/za-master -name "*.stream" ! -name "stream.zfs"` returns 0
- **fs table state:** `push_status='pushed'`, `last_pushed_guid` is set
- **snapshots cascade:** All earlier pending snaps for same fs have `status='verified'` and `push_status='pushed'`
- **Resume token round-trip:** Token saved after failure, sent back on retry (check server log for "push: saved resume token")

### Test Flow

1. `ws_tests.sh` sets `resume=1` and `debug_inject_zfs_pipeline_cmd="head -c 200K"`
2. Phase 1 (discovery) + Phase 2 (create_snap) work as-is
3. Phase 3: Server loop pushes snapshots, each interrupted at 200KB
4. After ~5-6 retries per snapshot, full stream completes
5. Test verifies final state

## 7. Files to Modify

| File | Changes |
|------|---------|
| `src/db.c` | Drop `snapshot_upload`, create `fs` table, add `db_fs_*` functions, remove `db_upload_*` |
| `src/db.h` | Replace `db_upload_*` declarations with `db_fs_*` |
| `src/zstream.c` | Add `zstream_join()`, `zstream_token_from_file()`, replace `2>/dev/null` with `audit_popen()` |
| `src/zstream.h` | New function declarations |
| `src/serve.c` | Replace all `snapshot_upload`/`db_upload_*` refs, add push orchestration loop, `.stream` extension, `zstream join`, cascade update, `"push: phase 3 complete"`, replace `2>/dev/null` with `audit_popen()` |
| `src/main.c` | Replace `2>/dev/null` with `audit_popen()`, add stderr forwarding over WS |
| `src/zfs.c` | Replace `2>/dev/null` with `audit_popen()` |
| `src/stream-ff.c` | Replace `2>/dev/null` with `audit_popen()` |
| `test/ws_tests.sh` | Phase 3 assertions for `.stream` files, `fs` table, cascade update |

**No changes to `src/main.c` for resume_token logic** — node already handles `resume_token` in push requests. Only stderr capture changes are needed.

## 8. Execution Order

1. **`src/db.c` / `src/db.h`** — Schema change + new functions (foundation)
2. **`src/zstream.c` / `src/zstream.h`** — Utilities (used by server)
3. **`src/serve.c`** — Push orchestration loop (biggest change, depends on 1+2)
4. **`src/main.c` / `src/zfs.c` / `src/stream-ff.c`** — Replace all `2>/dev/null` with `audit_popen()` (independent, no dependencies)
5. **`test/ws_tests.sh`** — Update assertions (depends on 3+4)

The stderr capture changes (step 4) are independent of the push loop and can be done in parallel or after.

## 8.5. Stderr Capture Rule

**Never discard stderr on any external tool call.** All `popen` calls that currently use `2>/dev/null` must be replaced with `audit_popen()` / `audit_popen_result()` to capture stderr for debugging.

### Existing infrastructure

`audit_popen()` / `audit_popen_result()` in `src/audit.c` already handles this:
- Replaces `2>/dev/null` with `2>/tmpfile` automatically
- Captures stderr to a temp file
- `audit_popen_result()` reads stderr into a buffer after `pclose()`
- Temp file is cleaned up automatically

### Audit logging with stderr

`audit_log_write2()` / `audit_log_err()` macro accepts an `stderr_output` parameter:
```c
audit_log_err(AUDIT_EVT_EXEC, "serve", cmd, exit_code, stderr_buf);
```

### Places to fix

Every `popen()` call with `2>/dev/null` in the codebase needs to be updated:

| File | Line(s) | Command | Current | Fix |
|------|---------|---------|---------|-----|
| `serve.c` | 895 | `zstd -d` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `serve.c` | 1086 | `zfs send` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `serve.c` | 1102 | `zfs send -i` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `serve.c` | 1123 | `zfs send` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `serve.c` | 1341 | `zstream dump -v` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `serve.c` | 1344 | `zstream dump -v` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `serve.c` | 1435 | `zstream token -g -i` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `main.c` | 397 | `zfs list` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `main.c` | 538, 621 | `zfs recv` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `main.c` | 1570 | `zfs list` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `main.c` | 1627 | `zfs get` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `zfs.c` | 31, 42, 54 | `zfs send` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `zfs.c` | 98 | `zfs list \| tail` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `stream-ff.c` | 101 | `zstd -l -v` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `stream-ff.c` | 124 | user cmd | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `zstream.c` | 33 | `zstream dump -v` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |
| `zstream.c` | 85 | `zstream token` | `2>/dev/null` | `audit_popen()` + `audit_popen_result()` |

### Pattern for replacing popen calls

```c
// Before:
FILE *fp = popen("zfs send ... 2>/dev/null", "r");
// ... read stdout ...
int rc = pclose(fp);

// After:
char stderr_buf[2048];
FILE *fp = audit_popen("zfs send ... 2>/dev/null");
// ... read stdout ...
int rc = audit_popen_result(fp, stderr_buf, sizeof(stderr_buf));
if (rc != 0 && stderr_buf[0]) {
    zep_log("ERROR: cmd failed rc=%d stderr=%s\n", rc, stderr_buf);
}
audit_log_err(AUDIT_EVT_EXEC, "serve", "zfs send ...", rc, stderr_buf);
```

### WS stderr forwarding

For push/pull operations over WebSocket, stderr from `zfs send` should be forwarded to the client via WS TEXT frames. This is especially important when debugging interrupted transfers.

Pattern for stderr forwarding in `node_ws_thread`:
```c
// After receiving WS_OP_EXIT, check captured stderr
if (stderr_buf[0]) {
    char err_frame[2048];
    snprintf(err_frame, sizeof(err_frame),
            "{\"action\":\"stderr\",\"data\":\"%s\"}", stderr_buf);
    ws_send_frame_gtls(nw, WS_OP_TEXT,
                       (unsigned char *)err_frame, strlen(err_frame));
}
```

This enables the admin client or node agent to see what `zfs send` / `zfs recv` / `zstream` actually output.

## 9. Edge Cases

- **Single chunk completes:** If the remaining stream is < 200KB, only `0000.stream` exists → rename to `stream.zfs`
- **Invalid last chunk:** `zstream token -g -i` fails on truncated chunk → reuse previous token, don't increment counter
- **zstream join exit 2:** Split chunks don't carry DRR_END → treat as success (expected behavior per zstream demo)
- **Multiple filesystems:** Loop processes one snapshot at a time, ordered by `push_status='resuming'` first, then by `id` for pending
- **Node disconnects mid-push:** WS connection drops → thread exits, fs stays in `pushing` state → next cron cycle will retry as `resuming` (or handle as new error case)
- **Empty snapshot stream:** If zfs send produces no data → skip, mark as verified with blob_count=0

## 10. Expected Server Log Output

```
DEBUG: ws: node za-master registered sock=14
INFO: discovery: registered ... (Phase 1)
INFO: create_snap: phase 2 complete (Phase 2)
INFO: push: started processing pending snapshots
INFO: push: sending push task for guid=<xxx> snap=<snap>
INFO: push: received chunk 0000.stream, size=204800
INFO: push: chunk 0000.stream interrupted, generating resume token
INFO: push: saved resume token for guid=<xxx> size=204800
INFO: push: retrying push for guid=<xxx> with resume token
INFO: push: received chunk 0000.stream, size=204800
INFO: push: chunk 0000.stream interrupted, generating resume token
... (repeat ~5-6 times)
INFO: push: full stream received, joining chunks
INFO: push: joined 6 chunks → stream.zfs (size=1048576)
INFO: push: cascaded verified status to 2 earlier pending snapshots for fs=za-pool-1/za-data-1
INFO: push: phase 3 complete
```

## 11. Storage Layout

```
/var/lib/zep-air/store/za-master/<inverted_ts>-<guid>/
├── 0000.stream    ← 200KB (first push, interrupted)
├── 0001.stream    ← 200KB (retry 1, interrupted)
├── 0002.stream    ← 200KB (retry 2, interrupted)
├── 0003.stream    ← 200KB (retry 3, interrupted)
├── 0004.stream    ← 200KB (retry 4, interrupted)
├── 0005.stream    ← ~100KB (retry 5, complete)
└── stream.zfs     ← joined full stream (after success)
```

After `zstream join` and cleanup, only `stream.zfs` remains.

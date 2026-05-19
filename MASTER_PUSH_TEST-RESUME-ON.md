# Master Push Test — WebSocket Streaming (resume=on)

## 1. TEST SCOPE

This test validates the complete resume push workflow: master node initiates a push that gets **intentionally interrupted** by `debug_inject_zfs_pipeline_cmd` (`head -c 200K`), server detects failure, marks snapshot as `failed`, saves a resume token from the partial blob, then on the **next cron cycle** sends a retry push task with `resume_token`, node resends from the interruption point, and server appends to a new blob file (`0001`). After N retries the full stream completes and snapshot is marked `verified`.

### What we test
1. Server configured with `resume=1`
2. `debug_inject_zfs_pipeline_cmd` set to `head -c 200K` — truncates zfs send stream at 200KB
3. Push starts, 200KB of stream sent, then `head` exits → zfs send pipe breaks
4. Server detects incomplete stream (zstream dump fails on truncated blob), marks snapshot `failed`
5. Server generates resume token from partial blob (`0000`) → saves to `snapshot_upload`
6. Next cron cycle: server detects `failed` snapshot with `resume_token` in `snapshot_upload`
7. Server sends push task with `resume_token` field populated
8. Master receives task, uses `resume_token` → `zfs send -t <token>` (client-side resume logic unchanged)
9. Server receives retry, opens blob `0001` (append mode), sends `{"resume":true,"offset":<bytes>}` to node
10. After 5 retries the full stream completes → server marks `verified`
11. `zstream dump -v` on reassembled blobs succeeds, `cluster_chain` populated

### Test environment
- Cluster: `test`
- Master node: `za-master` (role=master)
- ZFS filesystem: `za-master-pool/master`
- Cluster filesystem mapping: `za-pool-1/za-data-1:za-master-pool/master`
- Labels: `min` (60s), `hour` (3600s), `day` (86400s)
- Storage root: `/var/lib/zep-air/store`
- Server DB: `/var/lib/zep-air/server.db`
- Cron interval: 2 seconds
- **Resume config: enabled** (`resume=1`)
- **Debug injection: `head -c 200K`** (immediately after zfs send, truncates stream)
- **Test snapshot: 1MB file** in ZFS filesystem (ensures stream > 200KB)

---

## 2. TEST PROCEDURE

### Step 1: Clean cluster reinit
```
sudo ./cluster-reinit.sh
```
Wipes all state: ZFS pools, PKI, server DB, node DBs, cluster config. Fresh empty filesystem.

### Step 2: Enable resume + configure debug injection + create test data
```sql
-- Server: enable resume mode
INSERT OR REPLACE INTO config (key, value) VALUES ('resume', '1');
```

```bash
# Master node: inject head -c 200K into zfs send pipeline
sudo -u za-master zep-air config set debug_inject_zfs_pipeline_cmd "head -c 200K"

# Master node: create 1MB file (ensures zfs send stream > 200KB)
sudo -u za-master bash -c 'dd if=/dev/urandom of=/mnt/za-master-pool/master/testfile bs=1M count=1 2>/dev/null'
```

### Step 3: Server starts, nodes connect via WebSocket
- Server starts on port 18443 (TLS)
- Master connects to `GET /v1/ws/node?cn=za-master`
- Server registers: `DEBUG: ws: node za-master registered sock=14`

### Step 4: Cron/sync — server sends push + inventory tasks (cycle 1)
**Server sends 4 tasks:** 3 push tasks (min, hour, day) + 1 inventory task.

All `cron_last_*` keys are empty → `create=true` for all labels. No resume tokens yet.

### Step 5: Master creates snapshots and begins push
```
zfs snapshot 'za-master-pool/master@test-min-<timestamp>'
```
`pipeline_push_ws()` opens `zfs send ... | ... | head -c 200K`.

### Step 6: Push interrupted — `head` exits after 200KB
- `head -c 200K` reads 200KB of compressed stream output, then exits
- This closes the write end of the pipe → `zfs send` receives SIGPIPE
- Server receives BIN frames until pipe exhaustion
- Server writes data to blob `0000` (~200KB compressed)
- Server runs `zstream dump -v` on `0000` → **FAILS** (truncated stream, no valid DRR_BEGIN records)
- Server marks snapshot: `UPDATE snapshots SET status='failed' ...`
- Server generates resume token: `zstream token -g -i <storage>/0000`
- Server saves to `snapshot_upload`:
  ```sql
  INSERT OR REPLACE INTO snapshot_upload
  (guid, node, bytes_received, resume_token, complete)
  VALUES ('<guid>','za-master',204800,'<token>',0)
  ```
- Server logs: `INFO: push: saved resume token for guid=XXX size=204800`

### Step 7: Verify failed state in DB
```sql
-- Snapshot is failed
SELECT guid, label, status, blob_size FROM snapshots
WHERE node='za-master' AND status='failed';
-- → guid=XXX, label=min, status=failed, blob_size=204800

-- Resume token saved
SELECT guid, bytes_received, resume_token, complete
FROM snapshot_upload WHERE node='za-master';
-- → guid=XXX, bytes_received=204800, resume_token=<non-empty>, complete=0
```

### Step 8: Next cron cycle — server detects failed snapshot, sends retry (cycle 2)
Server's cron/sync now includes a **retry pass** that checks `snapshot_upload` for incomplete resumable pushes:

```json
{
  "action": "push",
  "cluster_fs": "za-pool-1/za-data-1",
  "label": "min",
  "resume_token": "<zstream-token-from-snapshot_upload>"
}
```

Master receives task, `pipeline_push_ws()` uses `resume_token`:
- Opens `zfs send -t <token>` → resumes from interruption point
- `head -c 200K` kicks in again, truncates at 200KB of remaining stream

### Step 9: Server receives retry — writes to blob `0001`
- Server detects `resume_token` in push metadata → `is_resume = 1`
- Server scans existing blobs, finds `0000`, opens `0001` for writing
- Server sends `{"resume":true,"offset":0}` to node (offset=0 because new blob)
- Server receives BIN frames, writes to `0001` (~200KB)
- `zstream dump -v` on `0001` alone **fails** (still truncated)
- Server marks snapshot `status='failed'` again
- Server regenerates resume token from `0001`: `zstream token -g -i <storage>/0001`
- `snapshot_upload` updated with new token (INSERT OR REPLACE)

### Step 10: Repeat failure → retry cycle (cycles 3-5)
Each cycle follows the same pattern:
1. Server detects failure from truncated blob
2. Server generates new resume token from the latest blob
3. Next cron/sync sends push task with updated `resume_token`
4. Client retries with `zfs send -t <updated_token>`
5. Server writes to next blob (`0002`, `0003`, ...)

### Step 11: Final retry — stream completes
After ~5 retries (total stream ≈ 1MB / ~200KB per retry):
- Remaining stream data < 200KB
- `head -c 200K` passes through all remaining data without truncating
- Server receives complete stream in the last blob
- **Server reassembles all blobs** (`cat 0000 0001 0002 ... 0005`)
- `zstream dump -v` on reassembled stream **succeeds**
- Server marks snapshot: `UPDATE snapshots SET status='verified' ...`
- Server calls `db_upload_complete(g_db, guid)` → deletes from `snapshot_upload`
- Server logs: `INFO: push: completed resume for guid=XXXX`

---

## 3. INTERNAL STATE CHANGES

### Database: `snapshots` table lifecycle

| Cycle | guid | label | status | blob_size | blob_count |
|-------|------|-------|--------|-----------|------------|
| 1 (create) | XXX | min | pushing | 0 | 1 |
| 1 (interrupt) | XXX | min | **failed** | 204800 | 1 |
| 2 (retry) | XXX | min | pushing | 0 | 1 |
| 2 (interrupt) | XXX | min | **failed** | 204800 | 2 |
| 3 | XXX | min | **failed** | 204800 | 3 |
| 4 | XXX | min | **failed** | 204800 | 4 |
| 5 | XXX | min | **failed** | 204800 | 5 |
| 6 (final) | XXX | min | **verified** | 204800 | 6 |

### Database: `snapshot_upload` table

| guid | bytes_received | resume_token | complete |
|------|---------------|--------------|----------|
| XXX | 204800 | <token-1> | 0 | ← after cycle 1 failure
| XXX | 204800 | <token-2> | 0 | ← after cycle 2 failure
| XXX | 204800 | <token-3> | 0 | ← after cycle 3 failure
| XXX | 204800 | <token-4> | 0 | ← after cycle 4 failure
| XXX | 204800 | <token-5> | 0 | ← after cycle 5 failure
| (deleted) | | | | ← cycle 6 success

### Database: `cluster_chain` table
Only populated on **final success**:
| cluster_key | fromguid | toguid | pushed_by |
|-------------|----------|--------|-----------|
| test | 0 | <stream-toguid> | za-master |

### Storage filesystem
```
/var/lib/zep-air/store/za-master/<inverted_ts>-<guid>/
├── 0000    ← 200KB (first push, interrupted)
├── 0001    ← 200KB (retry 1, interrupted)
├── 0002    ← 200KB (retry 2, interrupted)
├── 0003    ← 200KB (retry 3, interrupted)
├── 0004    ← 200KB (retry 4, interrupted)
└── 0005    ← ~100KB (retry 5, complete — remaining stream < 200KB)
```

---

## 4. KEY DESIGN POINTS

### Why `head -c 200K` is injected immediately after `zfs send`
The `debug_inject_zfs_pipeline_cmd` config appends `| head -c 200K` after the zfs send pipeline:
```
zfs send <snapshot> | mbuffer | zstd | head -c 200K
```
`head` reads 200KB of the **compressed** stream then exits, closing the pipe. `zfs send` gets SIGPIPE (exit code 141).

### Blob reassembly for verification (critical change)
On resume pushes (blob_num > 0), the server must reassemble all blobs before running `zstream dump -v`:
```
cat <dir>/0000 <dir>/0001 ... <dir>/000N | zstream dump -v -
```
The current code only runs `zstream dump -v` on the single last blob, which fails on partial data. For resume, reassembly is required.

### Resume token from partial compressed blob
`zstream token -g -i <blob_path>` operates on the **compressed blob** directly. It extracts the resume position from the zstd-compressed stream header, so no decompression is needed.

### Resume token updates on each failure
Each failure uses `INSERT OR REPLACE` into `snapshot_upload`:
- `bytes_received` stays at last blob size
- `resume_token` gets updated to new token
- `complete` stays 0
- Next cron/sync picks up the **latest** token

### 5 retries expected
With ~1MB uncompressed stream and ~200KB compressed per retry:
- Retry 1: 200KB sent → remaining ~800KB
- Retry 2: 200KB sent → remaining ~600KB
- Retry 3: 200KB sent → remaining ~400KB
- Retry 4: 200KB sent → remaining ~200KB
- Retry 5: 200KB sent → remaining ~0 (stream complete)

### Client-side resume unchanged
The client continues to use its existing local DB logic for resume. The server sends `resume_token` in the cron/sync push task JSON, and `pipeline_push_ws()` uses the external token if provided via a new parameter. The existing local DB lookup is preserved for future use.

---

## 5. TEST VERDICT

Expected outcome:

| Step | Status | Details |
|------|--------|---------|
| Resume enabled (`resume=1`) | ✅ | config key set |
| Debug injection configured | ✅ | `head -c 200K` appended to pipeline |
| 1MB test file created | ✅ | stream > 200KB |
| First push interrupted by head | ✅ | blob 0000 = 200KB, zstream dump fails |
| Snapshot marked `failed` | ✅ | status='failed' in snapshots table |
| Resume token saved to snapshot_upload | ✅ | complete=0, token non-empty |
| Cron/sync detects failed + token | ✅ | retry push task sent |
| Client retries with `zfs send -t` | ✅ | resume from interruption point |
| Server writes to new blob (0001+) | ✅ | append mode |
| Repeat failure → retry (cycles 2-5) | ✅ | token updated each time |
| Final stream completes (cycle 6) | ✅ | head doesn't truncate |
| Blob reassembly succeeds | ✅ | cat 0000..000N verified |
| Snapshot marked `verified` | ✅ | blob_count=6 |
| cluster_chain populated | ✅ | toguid/fromguid recorded |
| snapshot_upload cleaned up | ✅ | record deleted |

---

## 6. CONFIGURATION NOTES

### Resume config: **ENABLED**

```sql
INSERT OR REPLACE INTO config (key, value) VALUES ('resume', '1');
```

**When `resume == 1`:**
- Server generates resume tokens on push failure: `zstream token -g -i <blob_path>`
- Tokens saved to `snapshot_upload` with `complete=0`
- Next cron/sync includes `resume_token` in push task
- Server writes retry data to new blob (`0001`, `0002`, ...) in append mode
- On success, `snapshot_upload` record is deleted
- Server reassembles all blobs for verification on resume pushes

**Blob numbering for resume:**
- First push: `0000`
- First resume: `0001`
- Nth resume: `000N`

### Debug injection config: `head -c 200K`

```bash
sudo -u za-master zep-air config set debug_inject_zfs_pipeline_cmd "head -c 200K"
```

This appends `| head -c 200K` to the zfs send pipeline, truncating the compressed stream at 200KB. Used for testing resume interruption.

---

## 7. FAILURE MODES TO WATCH FOR

| Failure | Cause | Mitigation |
|---------|-------|------------|
| zstream dump succeeds on truncated blob | `zstream` tolerates partial streams | Use larger file or smaller head limit |
| Resume token generation fails | `zstream token` can't parse compressed blob | Decompress first: `zstd -d <blob> -c \| zstream token` |
| Blob reassembly fails | Missing blob files on disk | Ensure blobs persist across retries |
| Client never retries | `resume_token` not parsed from task JSON | Verify `cmd_cron()` parses `resume_token` field |
| Server sends same task repeatedly | `snapshot_upload.complete` not set on success | Verify `db_upload_complete()` called on verified path |
| `head` exits 0 but zfs send doesn't fail | Pipe buffering hides SIGPIPE | Check `zstream dump` result, not just pipe exit code |

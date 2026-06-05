# Phase 4 Plan — Client Discovery

## Goal
When a client node connects via WS and sends discovery (its local snapshots), the server registers them in the `snapshots` table with `direction='pull'` and `pull_status='discovered'`, then promotes the latest per `cluster_fs` to `pending`.

## DB Changes

### New Column: `pull_status` on `snapshots` table

Add migration in `db_init_tables()` (after line 141 in `db.c`):
```c
    /* One-shot migration: add pull_status for client discovery */
    {
        char *merr = NULL;
        sqlite3_exec(db,
                     "ALTER TABLE snapshots ADD COLUMN pull_status TEXT NOT NULL DEFAULT 'discovered'",
                     NULL, NULL, &merr);
        if (merr) sqlite3_free(merr);
    }
```

### Update `db_snapshot_insert()` signature

In `db.c:310-339`, add `pull_status` as 14th parameter:
```c
err_t db_snapshot_insert(sqlite3 *db, const char *cluster, const char *node,
                         const char *guid, const char *base_guid,
                         const char *snapshot, const char *label,
                         const char *cluster_fs, int blob_count,
                         size_t blob_size, const char *direction,
                         const char *storage_base, const char *status,
                         const char *pull_status) {
    const char *sql =
        "INSERT OR IGNORE INTO snapshots "
        "(cluster, node, guid, base_guid, snapshot, label, cluster_fs, "
        " status, blob_count, blob_size, direction, storage_base, pull_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    // ... bind 13 params (pull_status at position 13)
}
```

Update `db.h:31-36` to match the new signature.

### Update all callers (5 in serve.c)

All existing callers pass 13 args. Add `'discovered'` as 14th arg:

| Location | Current args | New 14th arg |
|----------|-------------|--------------|
| `serve.c:1036` (master discovery) | `"push", "", "pending"` | `"discovered"` |
| `serve.c:1894` (create_snap ack) | `"push", "", "pending"` | `"discovered"` |
| `serve.c:3303` (cron ack pull) | `"pull", "", "pending"` | `"discovered"` |
| `serve.c:3635` (inventory) | `"push"/"pull", "", "pending"` | `"discovered"` |
| `serve.c:3707` (inventory full sync) | `"pull", "", "pending"` | `"discovered"` |

## Code Changes

### `src/serve.c` — Discovery Handler

In `node_ws_thread()` discovery handler (around line 970), replace the `else { skip }` branch:

```c
if (strcmp(role_buf, "master") == 0 && cluster_buf[0]) {
    // === EXISTING MASTER DISCOVERY (unchanged) ===
    // Lines 971-1094: register with direction='push', push_status='archived'/'pending'
    // Promote latest per cluster_fs
    // Log: "discovery: %s total=%d new=%d existing=%d latest_fs=%d\n"
} else if (strcmp(role_buf, "client") == 0 && cluster_buf[0]) {
    // === CLIENT DISCOVERY (NEW) ===
    // Same structure as master discovery but:
    //   - direction='pull'
    //   - pull_status='discovered' (new column)
    //   - push_status='archived' (same lifecycle as master)
    //   - status='pending'
    // Same cluster_fs resolution from auth.mapping
    // Same latest-per-fs promotion logic
    // Log: "discovery: phase 4 completed\n"
} else {
    zep_log("discovery: node=%s role=%s — skipping\n",
        nw->cn, role_buf[0] ? role_buf : "(none)");
}
```

The client discovery loop is nearly identical to master discovery. Differences:
- `db_snapshot_insert()` call uses `"pull"` for direction, `"discovered"` for pull_status
- The `latest_fs` tracking and promotion logic is the same
- Log message differs: `"discovery: phase 4 completed"` instead of `"discovery: %s total=%d..."`

### `test/ws_tests.sh` — Add Phase 4 Section

After the existing master discovery/push tests (after line 546), add:

1. **Start client nodes** — set START_CLIENTS=1 or start manually:
   ```bash
   nohup sudo -u za-client-1 sh -c "\"$ZEP\" --logging DEBUG,INFO,WARN,ERROR,AUDIT --db \"$CLIENT1_DB\" cron --daemon --interval 5 2> /tmp/zep-za-client-1.log" </dev/null >/dev/null 2>&1 &
   ```

2. **Create snapshots on client node**:
   ```bash
   $SUDO zfs snapshot za-client-1-pool/slave@test-hour-${NOW}
   $SUDO zfs snapshot za-client-1-pool/slave@test-min-${NOW}
   ```

3. **Wait for client discovery** (15s timeout):
   ```bash
   while [[ $elapsed -lt 15 ]]; do
       if grep -q "discovery: phase 4 completed" /tmp/zep-server.log 2>/dev/null; then
           echo "  Phase 4 complete after ${elapsed}s"
           break
       fi
       sleep 1; elapsed=$((elapsed + 1))
   done
   ```

4. **Assert phase 4 log**:
   ```bash
   if grep -q "discovery: phase 4 completed" /tmp/zep-server.log; then
       ok "discovery: phase 4 completed logged"
   else
       bad "discovery: phase 4 NOT logged"
   fi
   ```

5. **Assert client snapshots in DB**:
   ```bash
   client_snap_count=$($SUDO sqlite3 "$SERVER_DB" \
       "SELECT COUNT(*) FROM snapshots WHERE node='za-client-1' AND direction='pull';")
   if [[ "$client_snap_count" -ge 2 ]]; then
       ok "DB: $client_snap_count client snapshots registered with direction='pull'"
   else
       bad "DB: expected >= 2 client snaps, got $client_snap_count"
   fi
   ```

6. **Assert pull_status='discovered'**:
   ```bash
   discovered_count=$($SUDO sqlite3 "$SERVER_DB" \
       "SELECT COUNT(*) FROM snapshots WHERE node='za-client-1' AND pull_status='discovered';")
   if [[ "$discovered_count" -ge 2 ]]; then
       ok "DB: $discovered_count client snaps have pull_status='discovered'"
   else
       bad "DB: expected >= 2 with pull_status='discovered', got $discovered_count"
   fi
   ```

7. **Assert latest promoted to pending**:
   ```bash
   pending_client=$($SUDO sqlite3 "$SERVER_DB" \
       "SELECT COUNT(*) FROM snapshots WHERE node='za-client-1' AND push_status='pending';")
   if [[ "$pending_client" -eq 1 ]]; then
       ok "DB: 1 client snapshot promoted to pending (latest per fs)"
   else
       bad "DB: expected 1 pending client snap, got $pending_client"
   fi
   ```

## Files to Edit

| File | Changes |
|------|---------|
| `src/db.c` | Add `pull_status` column migration in `db_init_tables()` |
| `src/db.c` | Add `pull_status` param to `db_snapshot_insert()` function |
| `src/db.h` | Update `db_snapshot_insert()` signature |
| `src/serve.c` | Client discovery branch in discovery handler (~line 1095) |
| `src/serve.c` | Update 5 callers of `db_snapshot_insert()` with new param |
| `test/ws_tests.sh` | Add Phase 4 section: start clients, create snaps, verify |

## Implementation Order

1. `db.c` — add column migration
2. `db.c` + `db.h` — update `db_snapshot_insert()` signature
3. `serve.c` — update 5 callers
4. `serve.c` — add client discovery branch
5. `ws_tests.sh` — add Phase 4 assertions
6. Build, install, test

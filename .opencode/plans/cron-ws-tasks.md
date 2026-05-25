# Plan: Server-Initiated Cron Tasks via WebSocket

## Goal
Move cron sync logic from the old REST endpoints into the `node_ws_thread` so the server pushes tasks to nodes over the existing WebSocket connection.

## Current State
- ✅ Cron REST endpoints removed from `serve.c`
- ✅ HTTP cron loop removed from `cmd_cron()` in `main.c`
- ✅ Reconnect loop bug fixed (`break` → `continue` in pipe handlers)
- ✅ Discovery runs on every WS connect (Phase 1 in `node_ws_thread`)
- ❌ No cron scheduler in `node_ws_thread`
- ❌ No WS action handlers for `sync`/`push`/`pull`/`rotation` on the client
- ❌ `cmd_rotate()` already deleted (needs local-only replacement)

## Architecture

### Server Side: Cron Scheduler in `node_ws_thread`

The `node_ws_thread` already has:
1. **Phase 1**: Discovery on connect (lines 507-741)
2. **Main event loop** (lines 744+): handles WS frames, PING/PONG, TEXT actions

We add a **Phase 2: Cron Scheduler** that runs between discovery and the main event loop.

```
node_ws_thread():
  Phase 1: Discovery (every connect)
  Phase 2: Cron Scheduler (runs once after discovery, sets up interval loop)
  Phase 3: Main event loop (handles WS frames + periodic task dispatch)
```

### Client Side: WS Action Handlers

The `ws_node_pipe_thread` in `main.c` currently handles:
- `pipe` action (server-initiated command execution)
- `pull_ws`, `push_ws`, `resume` (via pipe from main thread)

We add handlers for:
- `sync` action (server sends task list)
- `push` action (execute push task)
- `pull` action (execute pull task)
- `ack` action (send ack back to server)
- `rotation` action (execute rotation)

## Implementation Steps

### Step 1: Server — Add role/cluster tracking to `struct node_ws`

Add fields to track node role/cluster (already queried in discovery, but needed for scheduler):

```c
struct node_ws {
    // ... existing fields ...
    char role[16];           // "master" or "client"
    char cluster[64];        // cluster name
    char mapping[2048];      // node mapping
    int is_master;           // 1 if master
    time_t last_cron_check;  // last cron sync check time
};
```

Populate these in the discovery phase (Phase 1) — they're already being set there.

### Step 2: Server — Add `server_send_tasks()` function

Create a function that:
1. Checks `now - nw->last_cron_check >= interval`
2. Looks up node role/cluster from `nw->role`/`nw->cluster`
3. Builds task array based on role:
   - **Master**: For each cluster_fs + label, check `cron_last_*` config key. If due, add `push` task.
   - **Client**: Find master donor, check `snapshots` table for pending pulls, add `pull` task.
   - **Suspended**: Send empty task list.
4. Sends tasks as a single TEXT frame: `{"action":"sync","tasks":[...]}`
5. Updates `nw->last_cron_check`

### Step 3: Server — Integrate scheduler into main event loop

In the main event loop (line 744+), after the PING check:
```c
time_t now = time(NULL);
if (now - nw->last_cron_check >= default_interval) {
    server_send_tasks(nw);
    nw->last_cron_check = now;
}
```

Default interval: 60 seconds (configurable via `cluster` JSON `sync_interval` field).

### Step 4: Client — Add WS action handlers for `sync`/`push`/`pull`/`rotation`

In `ws_node_pipe_thread` (main.c), add handlers in the TEXT dispatch block (after line 733):

```c
if (strcmp(action->valuestring, "sync") == 0) {
    // Server sends task list
    cJSON *tasks = cJSON_GetObjectItem(task, "tasks");
    if (tasks && cJSON_IsArray(tasks)) {
        cJSON *t;
        cJSON_ArrayForEach(t, tasks) {
            cJSON *act = cJSON_GetObjectItem(t, "action");
            cJSON *cfs = cJSON_GetObjectItem(t, "cluster_fs");
            cJSON *lbl = cJSON_GetObjectItem(t, "label");
            
            if (strcmp(act->valuestring, "push") == 0) {
                // Execute push via pipeline_push_ws()
                // Send ack back: {"action":"ack","label":"...","cluster_fs":"..."}
            } else if (strcmp(act->valuestring, "pull") == 0) {
                // Execute pull via pipeline_pull_ws()
                // Send ack back: {"action":"ack","guid":"..."}
            }
        }
        // Send tasks_done: {"action":"tasks_done"}
    }
}
```

### Step 5: Client — Replace `cmd_rotate()` with local-only rotation

The old `cmd_rotate()` used HTTP REST. Create a new local-only version:
1. Read config from local SQLite
2. For each mapped filesystem, list local snapshots
3. Determine which snapshots exceed retention count
4. Destroy oldest snapshots exceeding retention
5. No server coordination needed

### Step 6: Client — Update `usage()` and command dispatch

Update `usage()` to document the new `rotate` command as local-only.
Update `main()` dispatch to call the new local `cmd_rotate()`.

## File Changes

| File | Changes |
|------|---------|
| `src/serve.c` | Add role/cluster fields to `struct node_ws`, add `server_send_tasks()`, integrate into main loop |
| `src/main.c` | Add `sync`/`push`/`pull`/`rotation` handlers in `ws_node_pipe_thread`, add local `cmd_rotate()` |
| `src/common.h` | Add new WS_OP definitions if needed |

## Risks & Mitigations

1. **Race condition**: Server sends tasks while node is mid-pull/push.
   → Node only accepts `sync` actions when idle (not in push/pull/resume handler). The pipe handler already has a `continue` after each task, so we can check `g_push_ws_req.ready == 0 && g_pull_ws_req.ready == 0` before processing sync.

2. **Connection loss**: If WS drops mid-cron cycle, node reconnects and server needs to re-send tasks.
   → Server's `last_cron_check` is per-connection. On reconnect, discovery runs again, then scheduler checks intervals. Tasks will be re-sent if still due.

3. **Pong timeout**: If cron interval is 60s and node doesn't send PONGs.
   → Node sends PONG on every PING. Server timeout is 180s.

4. **Multiple masters in same cluster**: Client needs to know which master to pull from.
   → Server queries `auth` table for master donor. This is already in the old cron sync logic.

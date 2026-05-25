# Plan: Remove Cron REST Endpoints, Server-Initiated Tasks via WebSocket

## Goal
Completely remove all cron REST endpoints from the server. Move task discovery and coordination to the existing persistent WebSocket connection.

## Architecture Decision: Server-Initiated Tasks via WS

The server pushes task list to the node over the existing WebSocket connection. The node's `ws_node_pipe_thread` receives tasks and executes them. No more HTTP polling for cron.

### Current Flow (HTTP-based)
```
Node ──GET /v1/cron/sync──▶ Server ──JSON tasks──▶ Node
Node ──executes tasks──▶ Node
Node ──POST /v1/cron/ack──▶ Server
Node ──GET /v1/cron/rotation──▶ Server ──JSON──▶ Node
Node ──POST /v1/cron/rotate-ack──▶ Server
```

### New Flow (WS-based)
```
Server ──TEXT{"action":"sync"}──▶ Node ──executes tasks──▶ Node
Node ──TEXT{"action":"ack",...}──▶ Server
Server ──TEXT{"action":"rotation"}──▶ Node ──rotates──▶ Node
Node ──TEXT{"action":"rotate-ack",...}──▶ Server
```

## Changes Required

### 1. Server Side (`src/serve.c`)

#### A. Add task queue to `struct node_ws` (line 49)
Add fields to `struct node_ws`:
```c
void *task_queue;          // linked list of task JSON strings
size_t task_queue_len;     // total bytes in queue
int has_tasks;             // flag for condvar signaling
```

#### B. Add `server_send_tasks(struct node_ws *nw)` function
After the main event loop's `select()` (line 772), check `has_tasks`. If set, send queued tasks as TEXT frames, then clear the queue.

#### C. Periodic task dispatch from `node_ws_thread` (main thread check)
The main loop (line 744) already has a `select()` with 50ms timeout. Every N seconds (e.g., 60s, matching the cron interval), the thread checks if there are new tasks to send.

How to trigger task generation:
- Add a `pthread_cond_t` to `struct node_ws`
- The `node_ws_thread` itself is the scheduler — on each loop iteration, it checks `if (now - last_check >= interval)` and generates tasks
- Tasks are queued and sent directly from the thread

#### D. Remove cron REST handlers
Delete these line ranges from `serve.c`:
- `GET /v1/cron/sync`: lines 2270–2529
- `POST /v1/cron/ack`: lines 2531–2583
- `GET /v1/cron/protected`: lines 2585–2611
- `GET /v1/cron/rotation`: lines 2613–2741
- `POST /v1/cron/rotate-ack`: lines 2743–2807
- `POST /v1/cron/inventory`: lines 2809–2996

That's ~1,530 lines of server-side cron code to remove.

#### E. Server-side cron logic moves to `node_ws_thread`
The cron sync logic (currently in the REST handler) moves into the `node_ws_thread`'s main loop. Every cron interval:
1. Look up node role/cluster from auth table
2. Check label intervals against `cron_last_*` config keys
3. Build task array (push/sync/inventory)
4. Send as TEXT frames to the node

### 2. Client Side (`src/main.c`)

#### A. Modify `ws_node_pipe_thread` to handle new WS action types
Add handlers in the server-initiated TEXT dispatch path (lines 723–1068):

| New Action | Handler Location | Purpose |
|---|---|---|
| `"sync"` | After line 741 | Receive task list, execute push/sync/inventory |
| `"rotation"` | After line 1062 | Receive rotation candidates, destroy snapshots |

#### B. New `ws_handle_sync()` handler
When the node receives `{"action":"sync"}` from the server:
1. Parse the task array
2. Execute push tasks (same as current Phase B/C in `cmd_cron`)
3. Execute sync tasks (same as current Phase D for "sync" action)
4. Execute inventory tasks (same as current Phase D for "inventory" action)
5. After all tasks done, send `{"action":"tasks_done"}` to server
6. Then wait for `{"action":"rotation"}` from server

#### C. Remove standalone `cmd_rotate()`
The `zep-air rotate` command is removed entirely. Rotation is only done via the cron daemon's WS-based rotation flow.

#### D. Remove HTTP-based cron loop
The `do { ... } while()` loop in `cmd_cron()` (lines 1332–1745) is replaced by the WS-based task handlers. The cron daemon still runs in daemon mode, but instead of HTTP polling, it:
1. Connects WebSocket (unchanged)
2. Waits for server-initiated `{"action":"sync"}` messages
3. Executes tasks
4. Sends acks back over WS
5. Waits for next `{"action":"sync"}`

#### E. Remove `http_get_json` and `http_post_json` calls for cron
Remove these calls from `cmd_cron()`:
- Line 1333: `http_get_json(&http_cfg, "/v1/cron/sync")`
- Line 1482: `http_post_json(&http_cfg, "/v1/cron/ack", body)` (push ack)
- Line 1544: `http_post_json(&http_cfg, "/v1/cron/ack", body)` (sync ack)
- Line 1614: `http_post_json(&http_cfg, "/v1/cron/inventory", body)`
- Line 1626: `http_get_json(&http_cfg, rot_url)` (rotation)
- Line 1728: `http_post_json(&http_cfg, "/v1/cron/rotate-ack", body)`

#### F. Remove `http_persistent_start` call
Line 1330: `http_persistent_start(&http_cfg)` — no longer needed since all communication is via WS.

### 3. Standalone `cmd_rotate()` (`src/main.c` lines 1113–1262)

This standalone rotate command also uses HTTP REST endpoints. Options:
- **A)** Convert it to use WS (connect WS, send `{"action":"rotate"}`, receive response, execute)
- **B)** Make it fully local (node decides rotation without server input) — simpler but loses coordination
- **C)** Keep it as a no-op with a deprecation warning

Recommendation: **Option B** — local rotation. The node already has the cluster config and can compute rotation candidates from its local ZFS snapshots + retention counts.

### 4. DB Functions (`src/db.c`)

The cron REST endpoints use these DB functions:
- `db_config_get()` / `db_config_set()` — for `cron_last_*` keys
- `db_snapshot_insert()` — for ack/inventory
- `db_snapshot_latest_guid()` — for client sync
- `db_snapshot_chain_json()` — for client sync snapshot list
- `db_common_ancestor()` — for rotation protection
- `db_snapshot_delete_node_guid()` — for rotate-ack
- `db_rotation_candidates()` — for rotation

**Keep all of these** — they're still needed. The cron logic moves from REST handlers to the WS thread, but the DB operations remain the same.

### 5. `pipeline.c`

No changes needed. `pipeline_resolve_fs()` is a pure mapping function, independent of transport.

### 6. `src/admin.c`

No changes needed. Admin doesn't use cron endpoints.

## File Change Summary

| File | Lines Added | Lines Removed | Net Change |
|------|------------|---------------|------------|
| `src/serve.c` | ~100 (task queue + scheduler) | ~1,530 (cron REST handlers) | **-1,430** |
| `src/main.c` | ~300 (WS task handlers) | ~400 (HTTP cron loop) | **-100** |
| `src/db.c` | 0 | 0 | 0 |
| `src/admin.c` | 0 | 0 | 0 |
| `test/cluster_smoke.sh` | ~20 | ~20 | 0 |
| `test/pull_resume_smoke.sh` | ~10 | ~10 | 0 |
| **Total** | **~430** | **~1,960** | **-1,530** |

## Implementation Order

1. **Server: add task queue to `struct node_ws`** and the `has_tasks` flag
2. **Server: move cron sync logic into `node_ws_thread`** — the thread itself generates tasks and sends them
3. **Server: remove cron REST handlers** (6 endpoints, ~1,530 lines)
4. **Client: add WS action handlers** for `sync` and `rotation` in `ws_node_pipe_thread`
5. **Client: remove HTTP cron loop** from `cmd_cron()`
6. **Client: convert `cmd_rotate()` to local-only**
7. **Test suite: update** to use WS-based cron (test creates snapshots, waits for sync)
8. **Build + test**

## Risks

1. **Race condition**: Server sends tasks while node is mid-pull/push. Mitigation: node only accepts `sync`/`rotation` actions when idle (not in the middle of a push/pull/pipe handler).
2. **Backward compatibility**: Nodes running old binary won't understand new WS actions. Mitigation: server sends a `protocol_version` field; nodes with older versions disconnect gracefully.
3. **Pong timeout**: If cron interval is 60s and node doesn't send PONGs, server might disconnect. Mitigation: node sends PONG on every action received.
4. **Connection loss**: If WS drops mid-cron cycle, node reconnects and server needs to re-send tasks. Mitigation: server remembers which tasks were sent per cycle.

# Fix: Create All Snapshots, Push Only Last (Latest)

## Problem
On first cron cycle, server sends `create=true` for all 3 labels (min, hour, day). Currently:
- Node only creates 1 snapshot (due to `!snapshot_created` guard)
- Node pushes that 1 snapshot under each label's task
- Result: only `min` snapshot exists, only pushed once

## Solution
Restructure `cmd_cron` (src/main.c) push task handling in 3 passes:

### Pass 1: Collect push tasks
- Build `push_task_list` array from tasks
- Track total push_count

### Pass 2: Create snapshots
- For each push task in list: if `create=true`, create a ZFS snapshot
- All 3 snapshots created: `@cluster-min-TIMESTAMP`, `@cluster-hour-TIMESTAMP`, `@cluster-day-TIMESTAMP`

### Pass 3: Push only last, ack all
- `pipeline_push_ws()` called only for the last push task (day = longest interval = latest snapshot)
- `pipeline_push_ws` finds the newest snapshot on disk (already does via `zfs list -S creation`)
- `/v1/cron/ack` posted for ALL labels (min, hour, day) — updates `cron_last_*` timestamps
- Server records all 3 labels with the same GUID

### Expected Result
- 3 ZFS snapshots created per first cycle
- 1 push (the latest/day snapshot)
- 3 acks recorded (min, hour, day all have same GUID)
- Server DB: one `snapshots` entry (INSERT OR REPLACE overwrites)
- Subsequent cycles: no creates (all `cron_last_*` set), only inventory

## Files Changed
- `src/main.c` — `cmd_cron` function (lines ~1347-1412)

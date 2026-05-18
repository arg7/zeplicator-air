# Snapshot Creation on First Push

## Goal
Server tells node to create a cluster-named snapshot on first push per label.

## Current Flow
1. Server checks `cron_last_<cluster>_<fs>_<label>` — if first time (last==0), emits "push" task
2. Node calls `pipeline_push_ws` which finds no snapshot and fails with "no snapshot guid found"
3. No snapshot is ever created

## New Flow
1. Server emits `"push"` task with `"create": true` flag (only when `last == 0`)
2. Node creates snapshot: `fs@<cluster>-<label>-<YYYYMMDDHHmmSS>`
3. Node pushes the newly created snapshot
4. Server updates `cron_last_` on ack

## Changes

### serve.c (line ~1991)
Add `"create": true` to push tasks when last==0:
```c
if (last == 0 || (now - last) >= interval_sec) {
    cJSON *t = cJSON_CreateObject();
    cJSON_AddStringToObject(t, "action", "push");
    cJSON_AddStringToObject(t, "cluster_fs", cluster_fs);
    cJSON_AddStringToObject(t, "label", lbl->string);
    if (last == 0)
        cJSON_AddTrueToObject(t, "create");
    cJSON_AddItemToArray(tasks, t);
}
```

### main.c:cmd_cron (push handler ~line 1343)
Check for `"create"` flag, create snapshot before push:
```c
if (strcmp(action->valuestring, "push") == 0 && ...) {
    cJSON *create = cJSON_GetObjectItem(task, "create");
    // if create is true, create snapshot first
    char snap_name[ZEP_MAX_SNAPSHOT_NAME] = {0};
    if (create && cJSON_IsTrue(create) && cfg2.cluster[0]) {
        char ts_buf[32];
        time_t now = time(NULL);
        struct tm tm = {0};
        gmtime_r(&now, &tm);
        strftime(ts_buf, sizeof(ts_buf), "%Y%m%d%H%M%S", &tm);
        char snap_label[128];
        snprintf(snap_label, sizeof(snap_label), "%s-%s-%s",
                 cfg2.cluster, label->valuestring, ts_buf);
        char snap_cmd[2048];
        snprintf(snap_cmd, sizeof(snap_cmd),
                 "zfs snapshot '%s@%s'", local_fs, snap_label);
        zep_log("cron: creating snapshot '%s'\n", snap_label);
        FILE *sp = popen(snap_cmd, "r");
        if (sp) { while(fgets(sline,sizeof(sline),sp)); pclose(sp); }
    }
    pipeline_push_ws(&cfg2, local_fs, label->valuestring, ...);
}
```

### main.c:push handler ack
When creating snapshot, also include snapshot name in ack body so server knows which label to track:

### main.c:pipeline_push_ws cleanup
Remove the broken snapshot creation code that was added previously (lines ~1822-1914). Restore to clean state: just find existing snapshot and push it.

## Testing
1. After reinit, first cron cycle should create snapshot
2. Snapshot name: `za-master-pool/master@test-min-YYYYMMDDHHmmSS`
3. Subsequent cycles should use existing snapshot (no new snap, just push)
4. Each label (min, hour, day) gets its own snapshot per interval

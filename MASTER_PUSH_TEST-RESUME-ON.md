# Master Push Test — WebSocket Streaming (resume=on)

## 1. TEST SCOPE

This test validates the complete resume push workflow: master node initiates a push that gets **intentionally interrupted** by `debug_inject_zfs_pipeline_cmd` (`head -c 200K`), server detects failure, marks snapshot as `failed`, saves a resume token from the partial blob, then on the **next cron cycle** sends a retry push task with `resume_token`, node resends from the interruption point, and server appends to a new blob file (`0001`). After N retries the full stream completes and snapshot is marked `verified`.

### What we test

** PHASE 1 **
1.1. Server configured with `resume=1`
1.2. `debug_inject_zfs_pipeline_cmd` set to `head -c 200K` — truncates zfs send stream at 200KB
1.3. Master establish  WS connection, 
1.4. Master sends its inventory of snapshots, filtered for cluster config
1.5. Server register snaps in db

** PHASE 2 **
2.1. Server check which labels are due, and sends snap tasks for due labels (they all due first time) via WS
2.2. Master creates snaps and return their GUIDs
2.3. Server registers created snaps in db
2.4. Server repeats phase 2 each 10 seconds

** PHASE 3 **
3.1 Server check if we have any fs with push_resume status, if yes, see 3.9.1

3.2. Server check if latest snaphot was downloaded to Storage yet. Exit if all done
3.3. Server send push task to Master via WS, update fs record with status "pushing"
3.4. Master starts zfs send (with snap name or resume_token if present) with bufferring and compression options, after 200KB of stream sent, `head` exits → zfs send pipe breaks, Master sends exit code with EOF
3.5. Server receives WS BIN frames with data, saves them in Storage with name <inverted epoch>-<snap guid>/<progressive number with padding '0' up to 4 chars>.stream. each zfs send must produce unique stream file
3.6. Server sees error exit code, generates resume token from partial stream,  saves it in fs table with status "push_resume" and exit
3.7. Server sees success exit code, it should join partial streams in one stream.zfs file. in case we have only one 0000.stream, we just rename it to stream.zfs and update fs table with status "pushed" and last_snap_guid = pushed guid
3.8. Server prints "phase 3 complete" and exit

3.9 Server send push task to Master with resume_token and continue to 3.4

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

### Step 1.1: Clean test start
```
sudo ./test/ws_tests.sh
```
Wipes all state: ZFS pools, PKI, server DB, node DBs, cluster config.
Creates some snapshots to test inventory code.
Creates 1M test file, to test zfs send with resume feature.

### Step 1.2: Config
Sets resume=1
Sets debug_inject_zfs_pipeline_cmd="head -c 200K" # Master node: inject head -c 200K into zfs send pipeline

### Step 1.3: Server starts, Master connect via WebSocket
- Server starts on port 18443 (TLS)
- Master connects to `GET /v1/ws/node?cn=za-master`
- Server registers: `DEBUG: ws: node za-master registered sock=14`

### Step 1.4: Master sends inventory 
Master: 
	INFO: ws-node: sending discovery 2 snaps

### Step 1.5: Master sends inventory
Server:
	INFO: discovery: registered za-master-pool/master@test-hour-20250101-000000 guid=16063417931126828694 lbl=hour
	INFO: discovery: registered za-master-pool/master@test-min-20250101-000000 guid=2193979308683888433 lbl=min
	INFO: discovery: test total=2 new=2 existing=0
	INFO: discovery: phase 1 complete
with status: "pending"

** THIS COMPLETES PHASE 1 **

### Step 2.1: Server check which labels are due
**Server sends 3 snap tasks:** one for (min, hour, day), since they all due (snaps in inventory are from year ago).
INFO: scheduler: create_snap za-pool-1/za-data-1@test-min-20260525-170257 (label=min, interval=60s)
INFO: scheduler: create_snap za-pool-1/za-data-1@test-hour-20260525-170257 (label=hour, interval=3600s)
INFO: scheduler: create_snap za-pool-1/za-data-1@test-day-20260525-170257 (label=day, interval=86400s)

### Step 2.2: Master creates snapshots and returns their GUIDs

INFO: ws-node: RX create_snap from server
INFO: create_snap: zfs snapshot -g 'guid' 'za-master-pool/master@test-min-20260525-170257' 2>&1
INFO: create_snap: rc=0 guid=13686818674863960790
INFO: ws-node: RX create_snap from server
INFO: create_snap: zfs snapshot -g 'guid' 'za-master-pool/master@test-hour-20260525-170257' 2>&1
INFO: create_snap: rc=0 guid=11309819494776308093
INFO: ws-node: RX create_snap from server
INFO: create_snap: zfs snapshot -g 'guid' 'za-master-pool/master@test-day-20260525-170257' 2>&1
INFO: create_snap: rc=0 guid=2437934325884200519

### Step 2.3: Server register created snaps with GUIDs

INFO: create_snap: RX response from za-master
INFO: scheduler: registered snap za-master-pool/master@test-min-20260525-170257 guid=13686818674863960790 label=min
INFO: create_snap: RX response from za-master
INFO: scheduler: registered snap za-master-pool/master@test-hour-20260525-170257 guid=11309819494776308093 label=hour
INFO: create_snap: RX response from za-master
INFO: scheduler: registered snap za-master-pool/master@test-day-20260525-170257 guid=2437934325884200519 label=day
INFO: create_snap: phase 2 complete
with status: "pending"

### Step 2.4: snap task repeats after 10 seconds 

** THIS COMPLETES PHASE 2 **

3.1 Server check if we have any fs with push_resume status, if yes, see 3.9.1
select first snap with status "push_resume", if exists go 3.9.1.

3.2. Server check if selected snaphot was downloaded to Storage yet. Exit if all done
select last snap with "pending" status. If none exists, exit.

3.3. Server send push task to Master via WS with snap name or resume token, update fs record with status "pushing".

3.4. Master starts zfs send (with snap name or resume_token if present) with bufferring and compression options, after 200KB of stream sent, `head` exits → zfs send pipe breaks, Master sends exit code with EOF

3.5. Server receives WS BIN frames with data, saves them in Storage with name <inverted epoch>-<snap guid>/<progressive number with padding '0' up to 4 chars>.stream. each zfs send must produce unique stream file

3.6. Server sees error exit code, generates resume token from partial stream,  saves it in fs table with status "push_resume" and exit

3.7. Server sees success exit code, it should join partial streams in one stream.zfs file. in case we have only one 0000.stream, we just rename it to stream.zfs and update fs table with status "pushed" and last_snap_guid = pushed guid

3.8. Server prints "phase 3 complete" and exit

3.9 Server send push task to Master with resume_token from fs and continue to 3.4

bash code to accomplish this phase 3:

	# On Server

        cnt=0
        send_opt=${snap_pending}
	folder="${storage_root}/${epoch}-${guid}"
        # For test we insert head -c 200K after zfs send to simulate interrupted transfer.
        while true
        do
                chunk="${folder}/$(printf '%04d' $cnt).stream"
                ssh master-host zfs send ${send_opt} | head -c 200K > ${chunk}
                if [ $? -ne 0 ]; then
                        break
                fi
                token=$(zstream token -g -i ${chunk})
                # check if last chunk is valid, if not reuse previous token
                [ $? -eq 0 ] && send_opt="-t ${token}" && cnt=$((cnt+1))
        done

        # zfs recv signaled success, last chunk was received
        zstream join -i ${folder}/*.stream > ${folder}/stream.zfs
        [ $? -eq 0 ] && rm ${folder}/*.stream



### Storage filesystem on Server
```
/var/lib/zep-air/store/za-master/<inverted_ts>-<guid>/
├── 0000.stream    ← 200KB (first push, interrupted)
├── 0001.stream    ← 200KB (retry 1, interrupted)
├── 0002.stream    ← 200KB (retry 2, interrupted)
├── 0003.stream    ← 200KB (retry 3, interrupted)
├── 0004.stream    ← 200KB (retry 4, interrupted)
└── 0005.stream    ← ~100KB (retry 5, complete — remaining stream < 200KB)
```

---


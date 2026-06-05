#!/bin/bash
# test/ws_discovery_test.sh — Verify WS discovery only registers properly-named snapshots
#
# Steps:
#   1. sudo cluster/cluster-destroy.sh --force
#   2. sudo cluster/cluster-init.sh --zfs --resume-test
#   3. Create properly-named and improperly-named snapshots on za-master-pool/master
#   4. Start server + master cron daemon
#   5. Wait for discovery to complete
#   6. Check serve log for proper messaging
#   7. Query DB: properly-named snaps registered, improperly-named snaps NOT registered

set -euo pipefail

source "$(dirname "$0")/lib.sh"

###############################################################################
# Config
###############################################################################
CLUSTER_NAME="test"
ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/cluster/cluster.env"
SUDO="sudo"
SERVER_PORT=18443

CACHE_ARCHIVE="/tmp/ws_tests.tar.xz"
ZEP_BASE="/var/lib/zep-air"
ZFS_POOLS="za-master-pool za-client-1-pool za-client-2-pool"

SERV_LOG="/tmp/zep-server-discovery.log"
NODE_CNF_DIR="/tmp/zep-discovery-cnf"

MASTER_DB="/var/lib/zep-air/home/za-master/za-master.db"
CLIENT1_DB="/var/lib/zep-air/home/za-client-1/za-client-1.db"
CLIENT2_DB="/var/lib/zep-air/home/za-client-2/za-client-2.db"
SERVER_DB="/var/lib/zep-air/server.db"
PKI="/var/lib/zep-air/pki"

CLUSTER="test"
MAPPING="za-pool-1/za-data-1:za-master-pool/master"

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ZEP="zep-air"
SERV="zep-air-serve"
ADMIN="zep-air-admin"

pass=0; fail=0
ok()  { echo -e "  ${GREEN}OK${NC}  $1"; pass=$((pass+1)); }
bad() { echo -e "  ${RED}FAIL${NC} $1"; fail=$((fail+1)); }

cleanup() {
    # Stop server and cron
    $SUDO cluster/cluster-ctl.sh --env "$ENV_FILE" stop 2>/dev/null || true
    # Kill client-2 cron
    kill $CLIENT2_PID 2>/dev/null || true
    pkill -f "za-client-2.*cron" 2>/dev/null || true
    # Kill anything lingering
    pkill -9 zep-air-serve || true
    pkill -9 zep-air || true
}

# ── cache helpers ──
cache_exists() { [[ -f "$CACHE_ARCHIVE" ]]; }

warm_cache() {
    echo -e "${CYAN}=== Warming cache ===${NC}"
    # Kill lingering zep processes
    $SUDO cluster/cluster-ctl.sh --env "$ENV_FILE" stop 2>/dev/null || true
    pkill -9 zep-air-serve 2>/dev/null || true
    pkill -9 zep-air 2>/dev/null || true
    sleep 1
    # Export pools so loopback img files are not in use
    for p in $ZFS_POOLS; do
        zpool export "$p" 2>/dev/null || true
    done
    sleep 1
    # Remove old archive, create fresh tar.xz
    $SUDO rm -f "$CACHE_ARCHIVE"
    $SUDO sh -c "cd / && tar -cJf $CACHE_ARCHIVE var/lib/zep-air/" 2>&1
    echo "  Cache written: $CACHE_ARCHIVE ($(du -h "$CACHE_ARCHIVE" | cut -f1))"
    # Re-import pools so the test can run against them
    for p in $ZFS_POOLS; do
        zpool import -d "$ZEP_BASE" "$p" 2>/dev/null || true
    done
    sleep 1
}

restore_cache() {
    echo -e "${CYAN}=== Restoring from cache ===${NC}"
    # Kill lingering zep processes
    $SUDO cluster/cluster-ctl.sh --env "$ENV_FILE" stop 2>/dev/null || true
    pkill -9 zep-air-serve 2>/dev/null || true
    pkill -9 zep-air 2>/dev/null || true
    sleep 1
    # Destroy any leftover pools from a crashed previous run
    for p in $ZFS_POOLS; do
        zpool list -H -o name "$p" 2>/dev/null && zpool destroy -f "$p" 2>/dev/null || true
    done
    sleep 1
    # Clean slate
    $SUDO rm -rf "$ZEP_BASE"
    $SUDO mkdir -p "$ZEP_BASE"
    # Extract archive (tar --same-owner preserves ownership)
    $SUDO tar -xJf "$CACHE_ARCHIVE" -C / 2>&1
    echo "  Cache restored: $ZEP_BASE ($(du -sh "$ZEP_BASE" | cut -f1))"
    # Re-import pools from restored loopback img files
    for p in $ZFS_POOLS; do
        zpool import -d "$ZEP_BASE" "$p" 2>/dev/null || true
    done
    sleep 1
    echo "  Ready for tests"
}

###############################################################################
# 1. Setup: cache restore or full init
###############################################################################
echo -e "${CYAN}=== Step 1: Setup environment ===${NC}"
if cache_exists; then
    restore_cache
else
    echo -e "${CYAN}No cache — full init${NC}"
    $SUDO cluster/cluster-destroy.sh --env "$ENV_FILE" --force
    $SUDO zpool destroy za-master-pool 2>/dev/null || true
    $SUDO zpool destroy za-client-1-pool 2>/dev/null || true
    $SUDO zpool destroy za-client-2-pool 2>/dev/null || true

    echo -e "${CYAN}=== Step 2: Build and install ===${NC}"
    $SUDO make install 2>&1

    echo -e "${CYAN}=== Step 3: Init cluster ===${NC}"
    $SUDO cluster/cluster-init.sh --env "$ENV_FILE" --zfs --resume-test

    warm_cache
fi

###############################################################################
# 3.5 Set compression/buffering config (before daemons start)
###############################################################################
echo -e "${CYAN}=== Step 3.5: Compression + buffering config ===${NC}"
$SUDO $ZEP --db "$MASTER_DB" config set push_zip_cmd "zstd -c -1" || true
$SUDO $ZEP --db "$MASTER_DB" config set push_buf_cmd "cat" || true
# Clear stale debug inject pipeline cmd from cache
$SUDO sqlite3 "$MASTER_DB" "DELETE FROM config WHERE key='debug_inject_zfs_pipeline_cmd';" 2>/dev/null || true
$SUDO sqlite3 "$SERVER_DB" \
    "INSERT OR REPLACE INTO config VALUES ('push_unzip_cmd', 'zstd -d')" 2>/dev/null || true
$SUDO sqlite3 "$SERVER_DB" \
    "INSERT OR REPLACE INTO config VALUES ('pull_zip_cmd', 'zstd -c -1')" 2>/dev/null || true
$SUDO $ZEP --db "$CLIENT1_DB" config set pull_unzip_cmd "zstd -d" || true
$SUDO $ZEP --db "$CLIENT1_DB" config set pull_buf_cmd "cat" || true
$SUDO $ZEP --db "$CLIENT1_DB" config set recv_options "-o canmount=off" || true
echo "  Compression/buffering config set for master, server, client"

###############################################################################
# 4. Create snapshots with proper and improper names
###############################################################################
echo -e "${CYAN}=== Step 4: Create snapshots ===${NC}"

# Properly-named snapshots: <fs>@<cluster>-<label>-<timestamp>
# Format: za-master-pool/master@test-hour-<YYYYMMDD-hhmmss>

NOW="20250101-000000"

# Proper snapshot 1 (hour label)
$SUDO zfs snapshot za-master-pool/master@test-hour-${NOW}
echo "Created: za-master-pool/master@test-hour-${NOW}"

$SUDO zfs snapshot za-master-pool/master@test-min-${NOW}
echo "Created: za-master-pool/master@test-min-${NOW}"

# Improper snapshots — these should be FILTERED OUT by the node agent
# 1. Wrong cluster prefix
$SUDO zfs snapshot za-master-pool/master@wrongcluster-hour-${NOW}
echo "Created: za-master-pool/master@wrongcluster-hour-${NOW} (improper: wrong cluster)"

# 2. No cluster prefix at all (just label)
$SUDO zfs snapshot za-master-pool/master@hour-${NOW}
echo "Created: za-master-pool/master@hour-${NOW} (improper: no cluster prefix)"

# 3. Cluster prefix without dash separator
$SUDO zfs snapshot za-master-pool/master@test_hour_${NOW}
echo "Created: za-master-pool/master@test_hour_${NOW} (improper: underscore instead of dash)"

# 4. Cluster prefix with no label (just cluster-timestamp)
$SUDO zfs snapshot za-master-pool/master@test-${NOW}
echo "Created: za-master-pool/master@test-${NOW} (improper: no label between cluster and timestamp)"

# 5. Snapshot on a different filesystem not in mapping
$SUDO zfs snapshot za-master-pool/slave@test-hour-${NOW} 2>/dev/null || true
echo "Created: za-master-pool/slave@test-hour-${NOW} (improper: not in mapping)"

echo ""
echo "Snapshot inventory:"
$SUDO zfs list -t snap -o name za-master-pool/master 2>/dev/null || true
echo ""

###############################################################################
# 4. Start server + master cron daemon
###############################################################################
echo -e "${CYAN}=== Step 5: Start server + cron daemon ===${NC}"

# Clear old logs (some may be root-owned from previous runs)
$SUDO rm -f "$SERV_LOG" /tmp/zep-server.log /tmp/zep-za-master.log 2>/dev/null || true

# Start server with verbose logging — stderr goes to log, stdout stays clean
$SERV --logging DEBUG,INFO,WARN,ERROR,AUDIT --port "$SERVER_PORT" \
    --cert "$PKI/server.crt" --key "$PKI/server.key" \
    --ca "$PKI/ca.crt" --db "$SERVER_DB" \
    --storage "/var/lib/zep-air/store" \
    2>/tmp/zep-server.log &
SERV_PID=$!

if ! kill -0 "$SERV_PID" 2>/dev/null; then
    echo "Server failed to start!"
    tail -20 /tmp/zep-server.log
    exit 1
fi
echo "  Server started (PID $SERV_PID)"

# Start master cron daemon (this triggers WS connect + discovery)
# Use same pattern as cluster-ctl.sh: root runs sudo -u <cn> sh -c "..."
nohup sudo -u za-master sh -c "\"$ZEP\" --logging DEBUG,INFO,WARN,ERROR,AUDIT --db \"$MASTER_DB\" cron --daemon --interval 5 2> /tmp/zep-za-master.log" </dev/null >/dev/null 2>&1 &
CRON_PID=$!
disown $CRON_PID 2>/dev/null || true
echo "  Cron daemon started (PID $CRON_PID)"

# Wait for discovery and scheduler to complete (phase 1 + phase 2)
echo "  Waiting for discovery and scheduler to complete..."
DISCOVERY_TIMEOUT=15
elapsed=0
while [[ $elapsed -lt $DISCOVERY_TIMEOUT ]]; do
    if grep -q "create_snap: phase 2 complete\|discovery: phase 1 complete" /tmp/zep-server.log 2>/dev/null; then
        echo "  Discovery + scheduler complete after ${elapsed}s"
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

if [[ $elapsed -ge $DISCOVERY_TIMEOUT ]]; then
    echo "  WARNING: Discovery + scheduler did not complete within ${DISCOVERY_TIMEOUT}s"
fi


###############################################################################
# 5. Check serve log
###############################################################################
echo -e "${CYAN}=== Step 6: Check serve log ===${NC}"

if [[ ! -f /tmp/zep-server.log ]]; then
    bad "server log not found at /tmp/zep-server.log"
else
    ok "server log exists"

    # Check for discovery summary line
    if grep -q "discovery: test total=" /tmp/zep-server.log; then
        discovery_line=$(grep "discovery: test total=" /tmp/zep-server.log | tail -1)
        echo "  Discovery summary: $discovery_line"
        ok "discovery summary found"

        # Parse counts
        total=$(echo "$discovery_line" | grep -oP 'total=\K\d+')
        new=$(echo "$discovery_line" | grep -oP 'new=\K\d+')
        existing=$(echo "$discovery_line" | grep -oP 'existing=\K\d+')
        echo "  total=$total new=$new existing=$existing"

        # We created 2 proper snapshots on za-master-pool/master
        # The node agent filters to only cluster-prefixed ones on mapped filesystems
        # So total should be 2 (proper snaps only)
        if [[ "$total" -eq 2 ]]; then
            ok "discovery processed exactly 2 snapshots (proper names only)"
        else
            bad "expected total=2, got total=$total (improper names leaked through?)"
        fi

        if [[ "$new" -eq 2 ]]; then
            ok "all 2 snapshots were newly registered"
        else
            bad "expected new=2, got new=$new"
        fi
    else
        bad "no discovery summary line found in server log"
    fi

    # Check that improperly-named snapshots were NOT registered (no "registered" log for them)
    improper_names=(
        "wrongcluster-hour"
        "@hour-"
        "test_hour"
        "test-${NOW}"
    )
    for iname in "${improper_names[@]}"; do
        if grep -q "registered.*$iname" /tmp/zep-server.log 2>/dev/null; then
            bad "improperly-named snapshot registered: $iname"
        else
            ok "improperly-named snapshot NOT registered: $iname"
        fi
    done

    # Check for "skipped (no mapping)" for the slave filesystem snapshot
    if grep -q "skipped.*slave.*no mapping" /tmp/zep-server.log 2>/dev/null; then
        ok "slave filesystem snapshot correctly skipped (no mapping)"
    else
        # This might not appear if the node only scans mapped filesystems
        echo "  (slave snapshot skip may not appear — node only scans mapped FS)"
    fi

    # Check phase 1 complete
    if grep -q "discovery: phase 1 complete" /tmp/zep-server.log; then
        ok "discovery phase 1 complete logged"
    else
        bad "discovery phase 1 complete NOT logged"
    fi
fi

###############################################################################
# 6. Query DB directly
###############################################################################
echo -e "${CYAN}=== Step 7: Query snapshots table ===${NC}"

# Query all registered snapshots for the master node
echo "  Registered snapshots:"
$SUDO sqlite3 "$SERVER_DB" "SELECT snapshot, label, guid, cluster_fs, status FROM snapshots WHERE node='za-master' ORDER BY recorded_at;" 2>/dev/null || true

# Count registered proper snapshots
proper_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-master' AND snapshot LIKE 'za-master-pool/master@test-%';" 2>/dev/null || echo 0)

if [[ "$proper_count" -ge 2 ]]; then
    ok "DB: >= 2 properly-named snapshots registered (got $proper_count)"
else
    bad "DB: expected >= 2 properly-named snapshots, got $proper_count"
fi

# Count registered improper snapshots (should be 0)
improper_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-master' AND (snapshot LIKE '%wrongcluster%' OR snapshot LIKE '%@hour-%' OR snapshot LIKE '%test[%]hour%');" 2>/dev/null || echo 0)

if [[ "$improper_count" -eq 0 ]]; then
    ok "DB: 0 improperly-named snapshots registered"
else
    bad "DB: $improper_count improperly-named snapshots registered (LEAK!)"
fi

# Check that the slave filesystem snapshot is not in the DB
slave_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-master' AND snapshot LIKE '%slave%';" 2>/dev/null || echo 0)

if [[ "$slave_count" -eq 0 ]]; then
    ok "DB: slave filesystem snapshot not registered (not in mapping)"
else
    bad "DB: slave filesystem snapshot registered (should be filtered by mapping)"
fi

# Verify labels are correct
hour_label=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT label FROM snapshots WHERE node='za-master' AND snapshot LIKE '%test-hour-%' LIMIT 1;" 2>/dev/null || echo "")

if [[ "$hour_label" == "hour" ]]; then
    ok "label 'hour' correctly extracted from snapshot name"
else
    bad "expected label='hour', got label='$hour_label'"
fi

min_label=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT label FROM snapshots WHERE node='za-master' AND snapshot LIKE '%test-min-%' LIMIT 1;" 2>/dev/null || echo "")

if [[ "$min_label" == "min" ]]; then
    ok "label 'min' correctly extracted from snapshot name"
else
    bad "expected label='min', got label='$min_label'"
fi

# Verify cluster_fs is correct
cfs=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT cluster_fs FROM snapshots WHERE node='za-master' LIMIT 1;" 2>/dev/null || echo "")

if [[ "$cfs" == "za-pool-1/za-data-1" ]]; then
    ok "cluster_fs correctly resolved to 'za-pool-1/za-data-1'"
else
    bad "expected cluster_fs='za-pool-1/za-data-1', got cluster_fs='$cfs'"
fi

# Verify direction is 'push'
dir=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT direction FROM snapshots WHERE node='za-master' LIMIT 1;" 2>/dev/null || echo "")

if [[ "$dir" == "push" ]]; then
    ok "direction correctly set to 'push'"
else
    bad "expected direction='push', got direction='$dir'"
fi

###############################################################################
# 7. Test server-driven create_snap (phase 2)
###############################################################################
echo -e "${CYAN}=== Step 7: Test create_snap (server-driven) ===${NC}"

if grep -q "create_snap: phase 2 complete" /tmp/zep-server.log 2>/dev/null; then
    ok "create_snap: phase 2 complete (server-driven snapshot creation)"
else
    bad "create_snap: phase 2 complete NOT found in server log"
fi

# Server scheduler sends create_snap tasks for labels with unset cron_last_*
# The 'min' label has a 60s interval, cron_last_* is unset on fresh cache → fires
# Check that a server-generated snapshot was registered
server_snap_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-master' AND snapshot LIKE '%test-min-%' AND snapshot NOT LIKE '%test-hour-%';" 2>/dev/null || echo 0)

# We have at least 2 snapshots with 'min' in the name:
# 1. Locally created: za-master-pool/master@test-min-<YYYYMMDD-hhmmss> (from discovery)
# 2. Server-generated: za-master-pool/master@test-min-<YYYYMMDD-hhmmss> (from scheduler)
if [[ "$server_snap_count" -ge 2 ]]; then
    ok "DB: $server_snap_count min snapshots registered (discovery + server-driven)"
else
    bad "DB: expected >= 2 min snapshots, got $server_snap_count"
fi

# Verify server-generated snapshot has a non-empty GUID (from scheduler)
server_guid=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT guid FROM snapshots WHERE node='za-master' AND snapshot LIKE '%test-min-%' AND guid != '' ORDER BY recorded_at DESC LIMIT 1;" 2>/dev/null || echo "")

if [[ -n "$server_guid" && "$server_guid" != "" ]]; then
    ok "server-generated snapshot has GUID: ${server_guid:0:16}..."
else
    bad "server-generated snapshot missing GUID"
fi

###############################################################################
# 8. Test push pull (phase 3) — master push to serve storage
###############################################################################
echo -e "${CYAN}=== Step 8: Test push pull (phase 3) ===${NC}"

# Wait for pull to complete
PULL_TIMEOUT=120
elapsed=0
while [[ $elapsed -lt $PULL_TIMEOUT ]]; do
    if grep -q "push: db state: 0 push pending" /tmp/zep-server.log 2>/dev/null; then
        echo "  Phase 3 complete after ${elapsed}s"
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

if [[ $elapsed -ge $PULL_TIMEOUT ]]; then
    bad "push: phase 3 complete NOT found within ${PULL_TIMEOUT}s"
else
    ok "push: phase 3 complete detected"
fi

# Count total master snapshots (should be 3: hour + min + server-generated)
total_master=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-master';" 2>/dev/null || echo 0)

if [[ "$total_master" -ge 3 ]]; then
    ok "DB: $total_master master snapshots in DB (>= 3 expected)"
else
    bad "DB: expected >= 3 master snapshots, got $total_master"
fi

# The last (most recent) snapshot was the one actually pulled
last_snap=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT snapshot FROM snapshots WHERE node='za-master' ORDER BY snapshot DESC LIMIT 1;" 2>/dev/null || echo "")

if [[ -n "$last_snap" ]]; then
    ok "Last pulled snapshot: $last_snap"
else
    bad "Could not determine last snapshot"
fi

# Check DB: ALL 3 master snapshots should have push_status='verified'
verified_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-master' AND push_status='verified';" 2>/dev/null || echo 0)

if [[ "$verified_count" -ge 3 ]]; then
    ok "DB: $verified_count master snapshots have push_status='verified' (all 3 updated)"
else
    bad "DB: expected >= 3 verified snapshots, got $verified_count"
fi

# Check DB: no pending or failed push_status
pending_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-master' AND push_status='pending';" 2>/dev/null || echo 0)

if [[ "$pending_count" -eq 0 ]]; then
    ok "DB: 0 master snapshots still in pending state"
else
    bad "DB: $pending_count master snapshots still pending (pull may have failed)"
fi

failed_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-master' AND push_status='failed';" 2>/dev/null || echo 0)

if [[ "$failed_count" -eq 0 ]]; then
    ok "DB: 0 master snapshots in failed state"
else
    bad "DB: $failed_count master snapshots in failed state"
fi

# Check storage: assembled.zfs should exist in store/za-master/
store_dir="/var/lib/zep-air/store/za-master"
assembled_files=$($SUDO find "$store_dir" -name "assembled.zfs" 2>/dev/null | wc -l)

if [[ "$assembled_files" -ge 1 ]]; then
    assembled_path=$($SUDO find "$store_dir" -name "assembled.zfs" 2>/dev/null | head -1)
    assembled_size=$($SUDO stat -c%s "$assembled_path" 2>/dev/null || echo 0)
    ok "storage: assembled.zfs found at $assembled_path (size=$assembled_size)"
else
    bad "storage: no assembled.zfs found in $store_dir"
fi

# Check: no leftover .zfs chunk files
zfs_chunks=$($SUDO find "$store_dir" -name "*.zfs" ! -name "assembled.zfs" 2>/dev/null | wc -l)
if [[ "$zfs_chunks" -eq 0 ]]; then
    ok "storage: no leftover .zfs chunk files"
else
    bad "storage: $zfs_chunks leftover .zfs chunk files found"
fi

# Check fs table: should have entries for the cluster/fs
fs_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM fs;" 2>/dev/null || echo 0)

if [[ "$fs_count" -ge 1 ]]; then
    ok "fs table has $fs_count entries"
else
    bad "fs table is empty (expected >= 1)"
fi

# Check fs table: last_pushed_guid should be non-empty for test cluster
pushed_guid=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT last_pushed_guid FROM fs WHERE cluster='test' AND push_status='pushed' LIMIT 1;" 2>/dev/null || echo "")

if [[ -n "$pushed_guid" && "$pushed_guid" != "" ]]; then
    ok "fs table: pushed_guid set for test cluster ($pushed_guid)"
else
    bad "fs table: no pushed_guid for test cluster"
fi

# Check fs table: push_status should be 'pushed' (not 'pending' or 'resuming')
pushed_status=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM fs WHERE cluster='test' AND push_status='pushed';" 2>/dev/null || echo 0)

if [[ "$pushed_status" -ge 1 ]]; then
    ok "fs table: push_status='pushed' for test cluster"
else
    bad "fs table: push_status is not 'pushed' for test cluster"
fi

# Check fs table: push_bytes_recv should be 0 after completion
bytes_recv=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT push_bytes_recv FROM fs WHERE cluster='test' AND push_status='pushed' LIMIT 1;" 2>/dev/null || echo "N/A")

if [[ "$bytes_recv" == "0" ]]; then
    ok "fs table: push_bytes_recv=0 after push completion"
else
    bad "fs table: push_bytes_recv=$bytes_recv (expected 0 after completion)"
fi

# Check fs table: push_resume_token should be empty after completion
resume_token=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT push_resume_token FROM fs WHERE cluster='test' AND push_status='pushed' LIMIT 1;" 2>/dev/null || echo "N/A")

if [[ -z "$resume_token" ]]; then
    ok "fs table: push_resume_token cleared after push completion"
else
    bad "fs table: push_resume_token not cleared (got: $resume_token)"
fi

###############################################################################
# 8b. Phase 4: Client node discovery (register as direction='pull')
###############################################################################
echo -e "${CYAN}=== Step 8b: Phase 4 — Client discovery ===${NC}"

# Create snapshots on client node (za-client-1)
$SUDO zfs snapshot za-client-1-pool/slave@test-hour-${NOW}
echo "Created: za-client-1-pool/slave@test-hour-${NOW}"
$SUDO zfs snapshot za-client-1-pool/slave@test-min-${NOW}
echo "Created: za-client-1-pool/slave@test-min-${NOW}"

# Start client cron daemon (triggers WS connect + discovery)
nohup sudo -u za-client-1 sh -c "\"$ZEP\" --logging DEBUG,INFO,WARN,ERROR,AUDIT --db \"$CLIENT1_DB\" cron --daemon --interval 5 2> /tmp/zep-za-client-1.log" </dev/null >/dev/null 2>&1 &
CLIENT_PID=$!
disown $CLIENT_PID 2>/dev/null || true
echo "  Client cron daemon started (PID $CLIENT_PID)"

# Wait for phase 4 discovery
PHASE4_TIMEOUT=20
elapsed=0
while [[ $elapsed -lt $PHASE4_TIMEOUT ]]; do
    if grep -q "discovery: phase 4 completed" /tmp/zep-server.log 2>/dev/null; then
        echo "  Phase 4 complete after ${elapsed}s"
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

if [[ $elapsed -ge $PHASE4_TIMEOUT ]]; then
    bad "phase 4 NOT completed within ${PHASE4_TIMEOUT}s"
else
    ok "phase 4 completed detected"
fi

# Assert: phase 4 log message
if grep -q "discovery: phase 4 completed" /tmp/zep-server.log; then
    ok "discovery: phase 4 completed logged"
else
    bad "discovery: phase 4 completed NOT logged"
fi

# Assert: client snapshots registered with direction='pull'
client_snap_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-client-1' AND direction='pull';" 2>/dev/null || echo 0)

if [[ "$client_snap_count" -ge 2 ]]; then
    ok "DB: $client_snap_count client snapshots registered with direction='pull'"
else
    bad "DB: expected >= 2 client snaps, got $client_snap_count"
fi

# Assert: pull_status='discovered'
discovered_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-client-1' AND pull_status='discovered';" 2>/dev/null || echo 0)

if [[ "$discovered_count" -ge 2 ]]; then
    ok "DB: $discovered_count client snaps have pull_status='discovered'"
else
    bad "DB: expected >= 2 with pull_status='discovered', got $discovered_count"
fi

# Assert: at least 1 client snapshot promoted to pending (latest per fs)
pending_client=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-client-1' AND push_status='pending';" 2>/dev/null || echo 0)

if [[ "$pending_client" -ge 1 ]]; then
    ok "DB: $pending_client client snapshot(s) promoted to pending (latest per fs)"
else
    bad "DB: expected >= 1 pending client snap, got $pending_client"
fi

# Dump client snapshots for debugging
echo "  Client snapshots in DB:"
$SUDO sqlite3 "$SERVER_DB" "SELECT snapshot, label, guid, cluster_fs, direction, pull_status, push_status FROM snapshots WHERE node='za-client-1' ORDER BY recorded_at;" 2>/dev/null || true

###############################################################################
# 8c. Phase 5: Client pull from server (pull assembled.zfs via WS)
###############################################################################
echo -e "${CYAN}=== Step 8c: Phase 5 — Client pull ===${NC}"

# Destroy client dataset so pull recv can create it from scratch as za-client-1
echo "  Destroying client dataset for clean pull target..."
$SUDO zfs unmount za-client-1-pool/slave 2>/dev/null || true
$SUDO zfs destroy -r za-client-1-pool/slave 2>/dev/null || true

# Restart client cron daemon (Phase 4 killed it)
nohup sudo -u za-client-1 sh -c "\"$ZEP\" --logging DEBUG,INFO,WARN,ERROR,AUDIT --db \"$CLIENT1_DB\" cron --daemon --interval 5 2> /tmp/zep-za-client-1.log" </dev/null >/dev/null 2>&1 &
CLIENT_PID=$!
disown $CLIENT_PID 2>/dev/null || true
echo "  Client cron daemon started for pull (PID $CLIENT_PID)"

# Wait for pull ACK with success (exit_code=0)
PHASE5_TIMEOUT=60
elapsed=0
while [[ $elapsed -lt $PHASE5_TIMEOUT ]]; do
    if grep -q "pull_ack: guid=.*success" /tmp/zep-server.log 2>/dev/null; then
        echo "  Pull success after ${elapsed}s"
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

if [[ $elapsed -ge $PHASE5_TIMEOUT ]]; then
    bad "phase 5 pull success NOT received within ${PHASE5_TIMEOUT}s"
else
    ok "phase 5 pull ACK received with success"
fi

# Assert: pull_status='pulled' in DB
pulled_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-client-1' AND direction='pull' AND pull_status='pulled';" 2>/dev/null || echo 0)

if [[ "$pulled_count" -ge 1 ]]; then
    ok "DB: $pulled_count client snap(s) pull_status='pulled'"
else
    bad "DB: expected >= 1 pulled, got $pulled_count"
fi

# Assert: client has the pulled snapshot locally
client_snaps=$($SUDO zfs list -t snapshot -H -o name za-client-1-pool/slave 2>/dev/null)
if [[ -n "$client_snaps" ]]; then
    ok "client has pulled snapshot(s): $(echo "$client_snaps" | head -1)"
else
    bad "client does NOT have pulled snapshot"
fi

# Clean up client crond
kill $CLIENT_PID 2>/dev/null || true
pkill -f "za-client-1.*cron" 2>/dev/null || true

###############################################################################
# 8d. Start client-2 cron daemon (3 active WS connections)
###############################################################################
echo -e "${CYAN}=== Step 8d: Client-2 cron daemon ===${NC}"

nohup sudo -u za-client-2 sh -c "\"$ZEP\" --db \"$CLIENT2_DB\" cron --daemon --interval 5 2> /tmp/zep-za-client-2.log" </dev/null >/dev/null 2>&1 &
CLIENT2_PID=$!
disown $CLIENT2_PID 2>/dev/null || true
echo "  Client-2 cron daemon started (PID $CLIENT2_PID)"
sleep 2

###############################################################################
# 9. Dump full server log for debugging
###############################################################################
echo -e "${CYAN}=== Step 9: Discovery+scheduler+pull log entries ===${NC}"
grep -iE "discovery|create_snap|scheduler|pull|push:" /tmp/zep-server.log 2>/dev/null | while IFS= read -r line; do
    echo "  $line"
done

###############################################################################
# 10. Phase 6 — Snapshot rotation via WebSocket
###############################################################################
echo -e "${CYAN}=== Step 10: Phase 6 — Snapshot rotation ===${NC}"

# Lower min retention to 1 to trigger rotation during test
$SUDO sqlite3 "$SERVER_DB" \
    "SELECT value FROM config WHERE key = 'cluster_test';" 2>/dev/null > /tmp/cfg_tmp.json
python3 -c "
import json
with open('/tmp/cfg_tmp.json') as f:
    d = json.load(f)
for pool in d['pools'].values():
    for fs in pool.values():
        if 'labels' in fs and 'min' in fs['labels']:
            fs['labels']['min'] = 1
with open('/tmp/cfg_new.json', 'w') as f:
    json.dump(d, f, separators=(',', ':'))
"
$SUDO sqlite3 "$SERVER_DB" "UPDATE config SET value = readfile('/tmp/cfg_new.json') WHERE key = 'cluster_test';"
rm -f /tmp/cfg_tmp.json /tmp/cfg_new.json
echo "  Retention lowered: min → 1"

# Wait for rotation dispatch + rotate-ack
PHASE6_TIMEOUT=90
while (( PHASE6_TIMEOUT > 0 )); do
    if grep -q "phase 6 complete" /tmp/zep-server.log 2>/dev/null; then
        break
    fi
    sleep 2
    PHASE6_TIMEOUT=$((PHASE6_TIMEOUT - 2))
done
if grep -q "phase 6 complete" /tmp/zep-server.log 2>/dev/null; then
    ok "phase 6 rotation complete (rotate-ack processed)"
else
    bad "phase 6 NOT completed: no 'phase 6 complete' in log within 90s"
fi

# Assert: rotate-ack processed at least once
ack_count=$(grep -c "rotate-ack: processed from" /tmp/zep-server.log 2>/dev/null || echo 0)
if [[ "$ack_count" -ge 1 ]]; then
    ok "rotate-ack processed $ack_count time(s)"
else
    bad "rotate-ack NEVER processed (rotation did not fire)"
fi

###############################################################################
# 11. Verify compression and buffering options
###############################################################################
echo -e "${CYAN}=== Step 11: Compression + buffering verification ===${NC}"

# Verify push compression was used on master
push_count=$(grep -c "push_send.*zstd -c -1" /tmp/zep-za-master.log 2>/dev/null)
push_count=${push_count:-0}
if [[ "$push_count" -ge 1 ]]; then
    ok "push_zip_cmd (zstd -c -1) used: $push_count push_send events"
else
    bad "push_zip_cmd never used in push_send events"
fi

# Verify pull compression was used on client
recv_count=$(grep -c "pull recv_cmd=zstd -d" /tmp/zep-za-client-1.log 2>/dev/null)
recv_count=${recv_count:-0}
if [[ "$recv_count" -ge 1 ]]; then
    ok "pull_unzip_cmd (zstd -d) used: $recv_count pull(s)"
else
    bad "pull_unzip_cmd never used in pull recv"
fi

# Verify recv_options present in pull command
recv_opt=$(grep "pull recv_cmd.*canmount=off" /tmp/zep-za-client-1.log 2>/dev/null || true)
if [[ -n "$recv_opt" ]]; then
    ok "recv_options (-o canmount=off) present in pull recv_cmd"
else
    bad "recv_options missing from pull recv_cmd"
fi

###############################################################################
# 12. Pipe tests — admin→server→node subprocess bridge
###############################################################################
echo -e "${CYAN}=== Step 12: Pipe tests ===${NC}"

# Wait for all background tasks to settle (rotation triggers new pushes)
echo "  Waiting for background tasks to settle..."
SETTLE_TIMEOUT=60
elapsed=0
while [[ $elapsed -lt $SETTLE_TIMEOUT ]]; do
    pending=$($SUDO sqlite3 "$SERVER_DB" \
        "SELECT COUNT(*) FROM snapshots WHERE (push_status='pending' OR push_status='resuming') AND direction='push';" 2>/dev/null || echo 0)
    if [[ "$pending" -eq 0 ]]; then
        echo "  All tasks settled after ${elapsed}s ($pending pending)"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done
if [[ "$pending" -ne 0 ]]; then
    echo "  WARNING: $pending tasks still pending after ${SETTLE_TIMEOUT}s"
fi

PIPE_ADM="--server https://master.zep.lan:$SERVER_PORT --cert $PKI/admin.crt --key $PKI/admin.key --ca $PKI/ca.crt"

# Ensure pipe_allow is clean
$ADMIN $PIPE_ADM config set pipe_allow '*' >/dev/null 2>&1
sleep 1

# Test 12a: Basic single-command pipe — zfs list -t snap
echo -e "${CYAN}=== Step 12a: Pipe zfs list -t snap ===${NC}"
out=$(timeout 12s "$ADMIN" $PIPE_ADM pipe --node za-master zfs list -t snap 2>/dev/null)
if echo "$out" | grep -q '@'; then
    ok "pipe zfs list returned snapshots"
else
    bad "pipe zfs list failed (empty or no @)"
fi

# Test 12b: Pipe zfs send stream → zstream dump -v
echo -e "${CYAN}=== Step 12b: Pipe zfs send valid stream ===${NC}"
last_snap=$($SUDO zfs list -t snap -o name -s creation za-master-pool/master 2>/dev/null | tail -1 | tr -d '[:space:]')
if [ -n "$last_snap" ]; then
    tmp=$(mktemp)
    timeout 30s "$ADMIN" $PIPE_ADM pipe --node za-master "zfs send $last_snap" 2>/dev/null > "$tmp" || true
    $SUDO zstream dump -v < "$tmp" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        ok "pipe zfs send valid stream ($last_snap)"
    else
        bad "pipe zfs send stream invalid"
    fi
    rm -f "$tmp"
else
    bad "no snapshot found for pipe zfs send"
fi

# Test 12c: Pipe pipeline — zfs list | zstd -c → zstd -d
echo -e "${CYAN}=== Step 12c: Pipe send pipeline (zfs list | zstd -c) ===${NC}"
out=$(timeout 12s "$ADMIN" $PIPE_ADM pipe --node za-master \
    "bash -c 'zfs list -H -o name -t snap za-master-pool/master | zstd -c'" 2>/dev/null | zstd -d 2>/dev/null)
if echo "$out" | grep -q '@'; then
    ok "pipe send pipeline returned snapshots"
else
    bad "pipe send pipeline failed"
fi

# Test 12d: Pipe recv pipeline — echo | zstd -c → zstd -d | head -c 5
# Temporarily extend pipe_allow to include head
echo -e "${CYAN}=== Step 12d: Pipe recv pipeline (zstd -d | head -c 5) ===${NC}"
$ADMIN $PIPE_ADM config set pipe_allow "zfs,head" >/dev/null 2>&1
sleep 1
out=$(echo "hello world!" | zstd -c | timeout 12s "$ADMIN" $PIPE_ADM pipe --node za-master \
    "zstd -d | head -c 5" 2>/dev/null)
# Restore pipe_allow to zfs only
$ADMIN $PIPE_ADM config set pipe_allow zfs >/dev/null 2>&1
if echo "$out" | grep -q "hello"; then
    ok "pipe recv pipeline returned 'hello'"
else
    bad "pipe recv pipeline failed: got '$out'"
fi

###############################################################################
# Cleanup
###############################################################################
echo -e "${CYAN}=== Cleanup ===${NC}"
cleanup
echo ""
print_results
exit $fail

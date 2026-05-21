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

SERV_LOG="/tmp/zep-server-discovery.log"
NODE_CNF_DIR="/tmp/zep-discovery-cnf"

MASTER_DB="/var/lib/zep-air/home/za-master/za-master.db"
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
    sleep 2
    # Kill anything lingering
    pkill -f "zep-air-serve.*$SERVER_PORT" 2>/dev/null || true
    pkill -f "zep-air.*cron.*za-master" 2>/dev/null || true
    sleep 1
    pkill -9 -f "zep-air-serve.*$SERVER_PORT" 2>/dev/null || true
    pkill -9 -f "zep-air.*cron.*za-master" 2>/dev/null || true
}

###############################################################################
# 0. Build binaries
###############################################################################
echo -e "${CYAN}=== Building binaries ===${NC}"
make -s 2>&1 || true
cp "$PROJ_DIR/zep-air" "$PROJ_DIR/zep-air-serve" "$PROJ_DIR/zep-air-admin" /usr/local/bin/ 2>/dev/null || true

###############################################################################
# 1. Destroy
###############################################################################
echo -e "${CYAN}=== Step 1: Destroy cluster ===${NC}"
$SUDO cluster/cluster-destroy.sh --env "$ENV_FILE" --force

# Extra cleanup: ensure no stale processes or ZFS state
sleep 2
$SUDO zpool destroy za-master-pool 2>/dev/null || true
$SUDO zpool destroy za-client-1-pool 2>/dev/null || true
$SUDO zpool destroy za-client-2-pool 2>/dev/null || true
pkill -f "zep-air-serve" 2>/dev/null || true
sleep 2

###############################################################################
# 2. Build and install
###############################################################################
echo -e "${CYAN}=== Step 2: Build and install ===${NC}"
make -s 2>&1
$SUDO make install 2>&1

###############################################################################
# 3. Init
###############################################################################
echo -e "${CYAN}=== Step 3: Init cluster ===${NC}"
$SUDO cluster/cluster-init.sh --env "$ENV_FILE" --zfs --resume-test

###############################################################################
# 4. Create snapshots with proper and improper names
###############################################################################
echo -e "${CYAN}=== Step 4: Create snapshots ===${NC}"

# Properly-named snapshots: <fs>@<cluster>-<label>-<timestamp>
# Format: za-master-pool/master@test-hourly-<epoch>

NOW=$(date +%s)

# Proper snapshot 1 (hourly label)
$SUDO zfs snapshot za-master-pool/master@test-hourly-${NOW}
echo "Created: za-master-pool/master@test-hourly-${NOW}"

# Proper snapshot 2 (min label)
sleep 1
NOW2=$(date +%s)
$SUDO zfs snapshot za-master-pool/master@test-min-${NOW2}
echo "Created: za-master-pool/master@test-min-${NOW2}"

# Improper snapshots — these should be FILTERED OUT by the node agent
# 1. Wrong cluster prefix
$SUDO zfs snapshot za-master-pool/master@wrongcluster-hourly-${NOW}
echo "Created: za-master-pool/master@wrongcluster-hourly-${NOW} (improper: wrong cluster)"

# 2. No cluster prefix at all (just label)
$SUDO zfs snapshot za-master-pool/master@hourly-${NOW}
echo "Created: za-master-pool/master@hourly-${NOW} (improper: no cluster prefix)"

# 3. Cluster prefix without dash separator
$SUDO zfs snapshot za-master-pool/master@test_hourly_${NOW}
echo "Created: za-master-pool/master@test_hourly_${NOW} (improper: underscore instead of dash)"

# 4. Cluster prefix with no label (just cluster-timestamp)
$SUDO zfs snapshot za-master-pool/master@test-${NOW}
echo "Created: za-master-pool/master@test-${NOW} (improper: no label between cluster and timestamp)"

# 5. Snapshot on a different filesystem not in mapping
$SUDO zfs snapshot za-master-pool/slave@test-hourly-${NOW} 2>/dev/null || true
echo "Created: za-master-pool/slave@test-hourly-${NOW} (improper: not in mapping)"

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

# Start server with verbose logging, redirect to known log file
$SERV --logging DEBUG,INFO,WARN,ERROR,AUDIT --port "$SERVER_PORT" \
    --cert "$PKI/server.crt" --key "$PKI/server.key" \
    --ca "$PKI/ca.crt" --db "$SERVER_DB" \
    --storage "/var/lib/zep-air/store" \
    >/tmp/zep-server.log 2>&1 &
SERV_PID=$!
sleep 3

if ! kill -0 "$SERV_PID" 2>/dev/null; then
    echo "Server failed to start!"
    tail -20 /tmp/zep-server.log
    exit 1
fi
echo "  Server started (PID $SERV_PID)"

# Start master cron daemon (this triggers WS connect + discovery)
# Use same pattern as cluster-ctl.sh: root runs sudo -u <cn> sh -c "..."
nohup sudo -u za-master sh -c "\"$ZEP\" --logging DEBUG,INFO,WARN,ERROR,AUDIT --db \"$MASTER_DB\" cron --daemon --interval 5 > /tmp/zep-za-master.log 2>&1" </dev/null >/dev/null 2>&1 &
CRON_PID=$!
disown $CRON_PID 2>/dev/null || true
echo "  Cron daemon started (PID $CRON_PID)"

# Wait for discovery to happen (WS connect + discovery sent + processed)
echo "  Waiting for discovery to complete..."
DISCOVERY_TIMEOUT=30
elapsed=0
while [[ $elapsed -lt $DISCOVERY_TIMEOUT ]]; do
    if grep -q "discovery: phase 1 complete" /tmp/zep-server.log 2>/dev/null; then
        echo "  Discovery complete after ${elapsed}s"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

if [[ $elapsed -ge $DISCOVERY_TIMEOUT ]]; then
    echo "  WARNING: Discovery did not complete within ${DISCOVERY_TIMEOUT}s"
fi

sleep 2

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
        "wrongcluster-hourly"
        "@hourly-"
        "test_hourly"
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

if [[ "$proper_count" -eq 2 ]]; then
    ok "DB: exactly 2 properly-named snapshots registered (got $proper_count)"
else
    bad "DB: expected 2 properly-named snapshots, got $proper_count"
fi

# Count registered improper snapshots (should be 0)
improper_count=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT COUNT(*) FROM snapshots WHERE node='za-master' AND (snapshot LIKE '%wrongcluster%' OR snapshot LIKE '%@hourly-%' OR snapshot LIKE '%test[%]hourly%');" 2>/dev/null || echo 0)

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
hourly_label=$($SUDO sqlite3 "$SERVER_DB" \
    "SELECT label FROM snapshots WHERE node='za-master' AND snapshot LIKE '%test-hourly-%' LIMIT 1;" 2>/dev/null || echo "")

if [[ "$hourly_label" == "hourly" ]]; then
    ok "label 'hourly' correctly extracted from snapshot name"
else
    bad "expected label='hourly', got label='$hourly_label'"
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
# 7. Dump full server log for debugging
###############################################################################
echo -e "${CYAN}=== Step 8: Discovery-related log entries ===${NC}"
grep -i "discovery" /tmp/zep-server.log 2>/dev/null | while IFS= read -r line; do
    echo "  $line"
done

###############################################################################
# Cleanup
###############################################################################
echo -e "${CYAN}=== Cleanup ===${NC}"
cleanup
echo ""
print_results
exit $fail

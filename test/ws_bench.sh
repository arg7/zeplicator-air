#!/bin/bash
# test/ws_bench.sh — WS pipe throughput benchmark
#
# Measures WebSocket pipe bridge throughput by streaming
# dd if=/dev/urandom bs=1M count=<COUNT> through the WS channel.

set -euo pipefail

source "$(dirname "$0")/lib.sh"

###############################################################################
# Config
###############################################################################
ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/cluster/cluster.env"
SUDO="sudo"
SERVER_PORT=18443

CACHE_ARCHIVE="/tmp/ws_tests.tar.xz"
ZEP_BASE="/var/lib/zep-air"
ZFS_POOLS="za-master-pool za-client-1-pool za-client-2-pool"

MASTER_DB="/var/lib/zep-air/home/za-master/za-master.db"
SERVER_DB="/var/lib/zep-air/server.db"
PKI="/var/lib/zep-air/pki"

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ZEP="zep-air"
SERV="zep-air-serve"
ADMIN="zep-air-admin"

# Bench parameters
DATA_COUNT="${DATA_COUNT:-1024}"   # bs=1M blocks (1024 = 1GB)
BENCH_TIMEOUT="${BENCH_TIMEOUT:-300}"

pass=0; fail=0
ok()  { echo -e "  ${GREEN}OK${NC}  $1"; pass=$((pass+1)); }
bad() { echo -e "  ${RED}FAIL${NC} $1"; fail=$((fail+1)); }

# ── cache helpers ──
cache_exists() { [[ -f "$CACHE_ARCHIVE" ]]; }

warm_cache() {
    echo -e "${CYAN}=== Warming cache ===${NC}"
    $SUDO cluster/cluster-ctl.sh --env "$ENV_FILE" stop 2>/dev/null || true
    pkill -9 zep-air-serve 2>/dev/null || true
    pkill -9 zep-air 2>/dev/null || true
    sleep 1
    for p in $ZFS_POOLS; do
        zpool export "$p" 2>/dev/null || true
    done
    sleep 1
    $SUDO rm -f "$CACHE_ARCHIVE"
    $SUDO sh -c "cd / && tar -cJf $CACHE_ARCHIVE var/lib/zep-air/" 2>&1
    echo "  Cache written: $CACHE_ARCHIVE ($(du -h "$CACHE_ARCHIVE" | cut -f1))"
    for p in $ZFS_POOLS; do
        zpool import -d "$ZEP_BASE" "$p" 2>/dev/null || true
    done
    sleep 1
}

restore_cache() {
    echo -e "${CYAN}=== Restoring from cache ===${NC}"
    $SUDO cluster/cluster-ctl.sh --env "$ENV_FILE" stop 2>/dev/null || true
    pkill -9 zep-air-serve 2>/dev/null || true
    pkill -9 zep-air 2>/dev/null || true
    sleep 1
    for p in $ZFS_POOLS; do
        zpool list -H -o name "$p" 2>/dev/null && zpool destroy -f "$p" 2>/dev/null || true
    done
    sleep 1
    $SUDO rm -rf "$ZEP_BASE"
    $SUDO mkdir -p "$ZEP_BASE"
    $SUDO tar -xJf "$CACHE_ARCHIVE" -C / 2>&1
    echo "  Cache restored: $ZEP_BASE ($(du -sh "$ZEP_BASE" | cut -f1))"
    for p in $ZFS_POOLS; do
        zpool import -d "$ZEP_BASE" "$p" 2>/dev/null || true
    done
    sleep 1
    echo "  Ready"
}

cleanup() {
    $SUDO cluster/cluster-ctl.sh --env "$ENV_FILE" stop 2>/dev/null || true
    pkill -9 zep-air-serve 2>/dev/null || true
    pkill -9 zep-air 2>/dev/null || true
}

###############################################################################
# 1. Setup
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

    echo -e "${CYAN}=== Build and install ===${NC}"
    $SUDO make install 2>&1

    echo -e "${CYAN}=== Init cluster ===${NC}"
    $SUDO cluster/cluster-init.sh --env "$ENV_FILE" --zfs --resume-test

    warm_cache
fi

###############################################################################
# 2. Start daemons
###############################################################################
echo -e "${CYAN}=== Step 2: Start server + cron daemon ===${NC}"

$SUDO rm -f /tmp/zep-server.log /tmp/zep-za-master.log 2>/dev/null || true

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

nohup sudo -u za-master sh -c "\"$ZEP\" --logging DEBUG,INFO,WARN,ERROR,AUDIT --db \"$MASTER_DB\" cron --daemon --interval 5 2> /tmp/zep-za-master.log" </dev/null >/dev/null 2>&1 &
CRON_PID=$!
disown $CRON_PID 2>/dev/null || true
echo "  Cron daemon started (PID $CRON_PID)"

###############################################################################
# 3. Wait for settle
###############################################################################
echo -e "${CYAN}=== Step 3: Wait for background tasks to settle ===${NC}"
SETTLE_TIMEOUT=60
elapsed=0
while [[ $elapsed -lt $SETTLE_TIMEOUT ]]; do
    pending=$($SUDO sqlite3 "$SERVER_DB" \
        "SELECT COUNT(*) FROM snapshots WHERE (push_status='pending' OR push_status='resuming') AND direction='push';" 2>/dev/null || echo 0)
    if [[ "$pending" -eq 0 ]]; then
        echo "  Settled after ${elapsed}s"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done
if [[ "$pending" -ne 0 ]]; then
    echo "  WARNING: $pending tasks still pending after ${SETTLE_TIMEOUT}s"
fi

###############################################################################
# 4. Benchmark — WS pipe throughput
###############################################################################
echo -e "${CYAN}=== Step 4: WS pipe throughput benchmark ===${NC}"

PIPE_ADM="--server https://master.zep.lan:$SERVER_PORT --cert $PKI/admin.crt --key $PKI/admin.key --ca $PKI/ca.crt"

$ADMIN $PIPE_ADM config set pipe_allow '*' >/dev/null 2>&1
sleep 1

DATA_SIZE_MB=$DATA_COUNT
echo "  Streaming ${DATA_SIZE_MB} MB through WS pipe bridge..."
echo "  Command: dd if=/dev/urandom bs=1M count=${DATA_COUNT} >/dev/null"

START_TS=$(date +%s%N)

timeout "${BENCH_TIMEOUT}s" "$ADMIN" $PIPE_ADM pipe --node za-master \
    "dd if=/dev/urandom bs=1M count=${DATA_COUNT}" 2>/dev/null >/dev/null
EXIT_CODE=$?

END_TS=$(date +%s%N)
ELAPSED_NS=$((END_TS - START_TS))
ELAPSED_S=$(awk "BEGIN { printf \"%.3f\", $ELAPSED_NS / 1000000000 }")

if [[ $EXIT_CODE -eq 0 ]]; then
    THROUGHPUT=$(awk "BEGIN { printf \"%.2f\", ${DATA_SIZE_MB} / $ELAPSED_S }")
    echo ""
    echo -e "  ${GREEN}Throughput: ${THROUGHPUT} MB/s${NC}"
    echo "  Data: ${DATA_SIZE_MB} MB in ${ELAPSED_S}s"
    ok "pipe benchmark completed"
elif [[ $EXIT_CODE -eq 124 ]]; then
    bad "pipe benchmark timed out after ${BENCH_TIMEOUT}s"
else
    bad "pipe benchmark failed (exit code $EXIT_CODE)"
fi

###############################################################################
# Cleanup
###############################################################################
echo -e "${CYAN}=== Cleanup ===${NC}"
cleanup
echo ""
print_results
exit $fail

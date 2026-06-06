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

# strace profiling (set PROFILE=1 to enable)
PROFILE="${PROFILE:-0}"
if [[ "$PROFILE" -eq 1 ]]; then
    DATA_COUNT="${DATA_COUNT:-50}"      # 50MB for profiling
    BENCH_TIMEOUT="${BENCH_TIMEOUT:-120}"
fi
STRACE_DIR="/tmp/strace-prof"

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

# ── strace profiling ──
if [[ "$PROFILE" -eq 1 ]]; then
    NODE_PID=""
    for i in $(seq 1 15); do
        NODE_PID=$(ps -u za-master -o pid,comm 2>/dev/null | awk '$2=="zep-air" {print $1; exit}')
        [[ -n "$NODE_PID" ]] && break
        sleep 1
    done
    if [[ -z "$NODE_PID" ]]; then
        echo "  ERROR: cannot find za-master zep-air PID"
        cleanup; exit 1
    fi
    echo "  Profiling: node PID=$NODE_PID"
    rm -rf "$STRACE_DIR"; mkdir -p "$STRACE_DIR"

    $SUDO strace -c -T -o "$STRACE_DIR/node.out" -p "$NODE_PID" &
    SN_PID=$!
    sleep 1  # let strace attach settle

    START_TS=$(date +%s%N)
    timeout "${BENCH_TIMEOUT}s" strace -c -T -o "$STRACE_DIR/admin.out" \
        "$ADMIN" $PIPE_ADM pipe --node za-master \
        "dd if=/dev/urandom bs=1M count=${DATA_COUNT}" 2>/dev/null >/dev/null
    EXIT_CODE=$?
    END_TS=$(date +%s%N)

    $SUDO kill $SN_PID 2>/dev/null
    wait $SN_PID 2>/dev/null
    sleep 1
else
    START_TS=$(date +%s%N)
    timeout "${BENCH_TIMEOUT}s" "$ADMIN" $PIPE_ADM pipe --node za-master \
        "dd if=/dev/urandom bs=1M count=${DATA_COUNT}" 2>/dev/null >/dev/null
    EXIT_CODE=$?
    END_TS=$(date +%s%N)
fi

ELAPSED_NS=$((END_TS - START_TS))
ELAPSED_S=$(awk "BEGIN { printf \"%.3f\", $ELAPSED_NS / 1000000000 }")

if [[ $EXIT_CODE -eq 0 ]]; then
    THROUGHPUT=$(awk "BEGIN { printf \"%.2f\", ${DATA_SIZE_MB} / $ELAPSED_S }")
    echo ""
    if [[ "$PROFILE" -eq 1 ]]; then
        echo -e "  ${YELLOW}Profile throughput: ${THROUGHPUT} MB/s${NC} (strace overhead skews timing)"
    else
        echo -e "  ${GREEN}Throughput: ${THROUGHPUT} MB/s${NC}"
    fi
    echo "  Data: ${DATA_SIZE_MB} MB in ${ELAPSED_S}s"
    ok "pipe benchmark completed"
elif [[ $EXIT_CODE -eq 124 ]]; then
    bad "pipe benchmark timed out after ${BENCH_TIMEOUT}s"
else
    bad "pipe benchmark failed (exit code $EXIT_CODE)"
fi

###############################################################################
# 5. strace analysis (profile mode only)
###############################################################################
if [[ "$PROFILE" -eq 1 ]]; then
    echo -e "${CYAN}=== Step 5: strace syscall analysis ===${NC}"

    for which in node admin; do
        f="$STRACE_DIR/$which.out"
        [[ -f "$f" ]] || continue
        echo ""
        echo -e "  ${YELLOW}─── $which ───${NC}"
        awk '
        BEGIN { in_pct = 0 }
        /^---/ || /^% time/ { in_pct = 1; next }
        in_pct == 0 { next }
        /^-----/ { in_pct = 0; if (NR>1) exit; next }
        {
            time_pct = $1
            seconds = $2
            calls = $4
            syscall = $6
            if (syscall == "total" && time_pct == "100.00" && calls == "") next
            printf "    %-5s %6s  %10s  %-15s\n", time_pct"%", calls, seconds, syscall
        }' "$f"
    done

    echo ""
    echo "  strace files: $STRACE_DIR/{node,admin}.out"
    echo ""
    echo -e "${YELLOW}=== Key metrics ===${NC}"
    for which in node admin; do
        f="$STRACE_DIR/$which.out"
        [[ -f "$f" ]] || continue
        total_calls=$(awk '/^100.00/ {print $5}' "$f")
        reads=$(awk '$6=="read" {print $4; exit}' "$f")
        writes=$(awk '$6=="write" {print $4; exit}' "$f")
        sends=$(awk '$6=="sendto" {print $4; exit}' "$f")
        recvs=$(awk '$6=="recvfrom" {print $4; exit}' "$f")
        selects=$(awk '$6=="select" {print $4; exit}' "$f")
        echo -e "  ${YELLOW}$which${NC}: total=${total_calls} calls  read=${reads:-0} write=${writes:-0} sendto=${sends:-0} recvfrom=${recvs:-0} select=${selects:-0}"
    done
fi

###############################################################################
# Cleanup
###############################################################################
echo -e "${CYAN}=== Cleanup ===${NC}"
cleanup
echo ""
print_results
exit $fail

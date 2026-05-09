#!/bin/bash
# Pipe benchmark — measure throughput at various chunk sizes
# ./test/pipe_bench.sh [duration_sec] [chunk_size] [--skip-setup]
#   duration_sec  stream for at least this many seconds (default: 10)
#   chunk_size    WS payload in bytes, 0=default(16380) (default: 0)
set -euo pipefail
source "$(dirname "$0")/lib.sh"

DURATION=${1:-10}
CHUNK=${2:-0}
SERVER_PORT=18444
SKIP_SETUP=0
[[ "${3:-}" == "--skip-setup" ]] && SKIP_SETUP=1

# Estimate count needed for the duration (assume 60 MB/s)
EST_RATE=60
COUNT_MB=$((DURATION * EST_RATE))
[ "$COUNT_MB" -lt 10 ] && COUNT_MB=10
# Cap at 512 MB to avoid excessive memory/disk
[ "$COUNT_MB" -gt 512 ] && COUNT_MB=512

CHUNK_ARG=""
[ "$CHUNK" -gt 0 ] && CHUNK_ARG="--chunk $CHUNK"

bm_send() {
    local label="$1"; shift
    >&2 printf "  %-12s " "$label"
    local t0; t0=$(date +%s%N)
    local bytes; bytes=$("$@" 2>/dev/null | wc -c)
    local t1; t1=$(date +%s%N)
    local ns=$((t1 - t0))
    local sec=$(awk "BEGIN {printf \"%.2f\", $ns/1000000000}")
    local mb=$(awk "BEGIN {printf \"%.1f\", $bytes/1048576}")
    local rate=$(awk "BEGIN {printf \"%.1f\", $mb/${sec}}")
    printf "%6.1f MB/s  (%ss, %.1f MB)\n" "$rate" "$sec" "$mb"
}

bm_recv() {
    local label="$1"; shift
    >&2 printf "  %-12s " "$label"
    local t0; t0=$(date +%s%N)
    dd if=/dev/zero bs=1M count="$COUNT_MB" 2>/dev/null | "$@" >/dev/null
    local t1; t1=$(date +%s%N)
    local ns=$((t1 - t0))
    local sec=$(awk "BEGIN {printf \"%.2f\", $ns/1000000000}")
    local rate=$(awk "BEGIN {printf \"%.1f\", ${COUNT_MB}/${sec}}")
    printf "%6.1f MB/s  (%ss)\n" "$rate" "$sec"
}

echo "=== pipe benchmark — ${COUNT_MB} MB, target ~${DURATION}s ==="
[ "$CHUNK" -gt 0 ] && echo "    chunk = ${CHUNK} bytes" || echo "    chunk = default (16380)"

echo -e "\n${CYAN}Local baseline (no TLS, no relay)${NC}"
bm_send "dd" dd if=/dev/zero bs=1M count="$COUNT_MB" of=/dev/null

if [ "$SKIP_SETUP" -eq 1 ]; then
    echo -e "\n${CYAN}Skipping server/node setup${NC}"
    exit 0
fi

echo -e "\n${CYAN}Setting up server + node...${NC}"

for p in 18444 18445 18446; do sudo fuser -k $p/tcp 2>/dev/null || true; done
sleep 1

init_bins
init_tmp zep-bench

FQDN=bench.zep.lan
pki_ca
pki_server "$FQDN"
pki_nodes admin bench-node
hosts_add "$FQDN"

server_setup
server_start "$SERVER_PORT" "--verbose" >/dev/null 2>&1
echo "  Server PID=$SERV_PID"

admin_base "https://$FQDN:$SERVER_PORT"
node_join client bench-node
pipe_allow "zfs,dd,tee"

NDB="$TMP/node/zep-air.db"
mkdir -p "$TMP/node"
node_config "$NDB" bench-node "https://$FQDN:$SERVER_PORT" "$PKI/bench-node.crt" "$PKI/bench-node.key"

cron_spawn "$NDB" 2
echo "  Node cron PID=${CRON_PIDS[0]}"

# ── send benchmark (node → admin) ──
echo -e "\n${CYAN}Send benchmark (node→admin, node generates /dev/urandom)${NC}"
STM_CMD="$ADMIN $ADMIN_BASE pipe --node bench-node $CHUNK_ARG dd if=/dev/zero bs=1M count=$COUNT_MB"
bm_send "send" $STM_CMD

# ── recv benchmark (admin → node) ──
echo -e "\n${CYAN}Recv benchmark (admin→node, admin streams /dev/zero)${NC}"
rm -f "$TMP/recv-test"
RCV_CMD="$ADMIN $ADMIN_BASE pipe --node bench-node $CHUNK_ARG dd of=$TMP/recv-test bs=1M"
bm_recv "recv" $RCV_CMD

# Verify recv
EXPECTED=$((COUNT_MB * 1024 * 1024))
sz=$(stat -c%s "$TMP/recv-test" 2>/dev/null || echo 0)
if [ "$sz" -eq "$EXPECTED" ]; then
    echo -e "  ${GREEN}OK${NC}   recv: ${COUNT_MB} MB transferred, data verified"
else
    echo -e "  ${RED}FAIL${NC} recv: expected $EXPECTED bytes, got $sz"
fi

# ── stderr test ──
echo -e "\n${CYAN}Stderr propagation test${NC}"
STDERR_OUT=$("$ADMIN" $ADMIN_BASE pipe --node bench-node dd if=/dev/zero bs=1M count=1 of=/dev/null 2>&1 >/dev/null || true)
echo "$STDERR_OUT" | grep -q "bytes.*copied\|records" && \
    echo -e "  ${GREEN}OK${NC}   stderr from remote dd visible" || \
    echo -e "  ${RED}FAIL${NC} stderr from remote dd missing"

# ── tiny recv smoke test ──
echo -e "\n${CYAN}Tiny recv smoke test${NC}"
rm -f "$TMP/recv-tiny.txt"
echo -n "hello world" | \
    "$ADMIN" $ADMIN_BASE pipe --node bench-node tee "$TMP/recv-tiny.txt" 2>/dev/null
if [ -f "$TMP/recv-tiny.txt" ] && [ "$(cat "$TMP/recv-tiny.txt" 2>/dev/null)" = "hello world" ]; then
    echo -e "  ${GREEN}OK${NC}   tiny recv: 'hello world'"
else
    c=$(cat "$TMP/recv-tiny.txt" 2>/dev/null || echo "<missing>")
    echo -e "  ${RED}FAIL${NC} tiny recv got: '$c'"
fi

echo -e "\n${CYAN}Cleaning up...${NC}"
cleanup

echo -e "\n${GREEN}Benchmark complete.${NC}"
echo "Sent/received ${COUNT_MB} MB over HTTPS WebSocket pipe."
echo "Chunk: ${CHUNK:-default} bytes. Target: ~${DURATION}s. Cap: 512 MB."

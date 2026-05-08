#!/bin/bash
# Pipe benchmark — compare zep-air-admin pipe vs local baseline
# ./test/pipe_bench.sh [count_mb] [--skip-setup]
set -euo pipefail
source "$(dirname "$0")/lib.sh"

COUNT_MB=${1:-256}
SERVER_PORT=18444
SKIP_SETUP=0
[[ "${2:-}" == "--skip-setup" ]] && SKIP_SETUP=1

bm_quiet() {
    local label="$1"; shift
    >&2 printf "  %-10s " "$label"
    local t0; t0=$(date +%s%N)
    "$@" >/dev/null 2>/dev/null
    local t1; t1=$(date +%s%N)
    local ns=$((t1 - t0))
    local sec=$(awk "BEGIN {printf \"%.3f\", $ns/1000000000}")
    local rate=$(awk "BEGIN {printf \"%.1f\", ${COUNT_MB}/${sec}}")
    printf "%6.1f MB/s  (%.2fs, %d MB)\n" "$rate" "$sec" "$COUNT_MB"
}

echo "=== pipe benchmark — ${COUNT_MB} MB ==="

echo -e "\n${CYAN}Local baseline (no TLS, no relay)${NC}"
bm_quiet "dd" dd if=/dev/urandom bs=1M "count=$COUNT_MB" of=/dev/null

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
pipe_allow "zfs,dd"

NDB="$TMP/node/zep-air.db"
mkdir -p "$TMP/node"
node_config "$NDB" bench-node "https://$FQDN:$SERVER_PORT" "$PKI/bench-node.crt" "$PKI/bench-node.key"

cron_spawn "$NDB" 2
echo "  Node cron PID=${CRON_PIDS[0]}"

# ── benchmarks ──
echo -e "\n${CYAN}Pipe benchmarks (admin → server → node → server → admin)${NC}"

ADM_CMD="$ADMIN $ADMIN_BASE pipe dd if=/dev/urandom bs=1M count=$COUNT_MB"
bm_quiet "pipe"      $ADM_CMD
bm_quiet "pipe+zstd"  $ADMIN $ADMIN_BASE pipe --compress dd if=/dev/urandom bs=1M "count=$COUNT_MB"
bm_quiet "pipe+zbuf"  $ADMIN $ADMIN_BASE pipe --compress --buffer dd if=/dev/urandom bs=1M "count=$COUNT_MB"

# ── stderr test ──
echo -e "\n${CYAN}Stderr propagation test${NC}"
STDERR_OUT=$("$ADMIN" $ADMIN_BASE pipe dd if=/dev/urandom bs=1M count=4 2>&1 >/dev/null || true)
echo "$STDERR_OUT" | grep -q "bytes.*copied\|records" && \
    echo -e "  ${GREEN}OK${NC}   stderr from remote dd visible" || \
    echo -e "  ${RED}FAIL${NC} stderr from remote dd missing"

# ── recv test ──
echo -e "\n${CYAN}Recv direction test${NC}"
rm -f "$TMP/recv-test"
dd if=/dev/zero bs=1M count=4 2>/dev/null | \
    "$ADMIN" $ADMIN_BASE pipe --recv dd of="$TMP/recv-test" bs=1M 2>/dev/null
for i in 1 2 3 4 5; do
    sz=$(stat -c%s "$TMP/recv-test" 2>/dev/null || echo 0)
    [ "$sz" -eq 4194304 ] && break
    sleep 1
done
if [ -f "$TMP/recv-test" ] && [ "$(stat -c%s "$TMP/recv-test" 2>/dev/null || echo 0)" -eq 4194304 ]; then
    echo -e "  ${GREEN}OK${NC}   recv direction: 4 MB transferred"
else
    sz=$(stat -c%s "$TMP/recv-test" 2>/dev/null || echo 0)
    echo -e "  ${RED}FAIL${NC} recv direction data mismatch (got $sz bytes)"
fi

echo -e "\n${CYAN}Cleaning up...${NC}"
cleanup
echo -e "\n${GREEN}Benchmark complete.${NC}"
echo "Count = ${COUNT_MB} MB. Divide by 4 hops for per-hop overhead estimate."
#!/bin/bash
# Pipe benchmark — compare zep-air-admin pipe vs nc vs local baseline
# ./test/pipe_bench.sh [count_mb] [--skip-setup]
#    0 = local-only; 10/100/1024 = pipe+nc benchmarks
set -euo pipefail

COUNT_MB=${1:-256}
SERVER_PORT=18444
RED='\033[31m'; GREEN='\033[32m'; CYAN='\033[36m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ_DIR="$(dirname "$SCRIPT_DIR")"
BIN="$PROJ_DIR"
ZEP="$BIN/zep-air"
SERV="$BIN/zep-air-serve"
ADMIN="$BIN/zep-air-admin"

SKIP_SETUP=0
[[ "${2:-}" == "--skip-setup" ]] && SKIP_SETUP=1

bm()   { local label="$1"; shift
         >&2 printf "  %-10s " "$label"
         local t0; t0=$(date +%s%N)
         "$@"
         local t1; t1=$(date +%s%N)
         local ns=$((t1 - t0))
         local sec=$(awk "BEGIN {printf \"%.3f\", $ns/1000000000}")
         local rate=$(awk "BEGIN {printf \"%.1f\", ${COUNT_MB}/${sec}}")
         printf "%6.1f MB/s  (%.2fs, %d MB)\n" "$rate" "$sec" "$COUNT_MB"
       }

bm_quiet() { local label="$1"; shift
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

# ── local baseline ──
echo -e "\n${CYAN}Local baseline (no TLS, no relay)${NC}"
bm_quiet "dd" dd if=/dev/urandom bs=1M "count=$COUNT_MB" of=/dev/null

if [ "$SKIP_SETUP" -eq 1 ]; then
    echo -e "\n${CYAN}Skipping server/node setup${NC}"
    exit 0
fi

echo -e "\n${CYAN}Setting up server + node...${NC}"

# cleanup — avoid pkill -f which hangs on some systems
for port in 18444 18445 18446; do sudo fuser -k $port/tcp 2>/dev/null || true; done
sleep 1
rm -rf /tmp/zep-bench
mkdir -p /tmp/zep-bench/{pki,storage,node}
chmod 777 /tmp/zep-bench /tmp/zep-bench/storage /tmp/zep-bench/node

# host entry
grep -q "bench.zep.lan" /etc/hosts || echo "127.0.1.1 bench.zep.lan" | sudo tee -a /etc/hosts >/dev/null

PKI=/tmp/zep-bench/pki
# CA
openssl genrsa -out "$PKI/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes -key "$PKI/ca.key" -sha256 -days 365 \
  -out "$PKI/ca.crt" -subj "/C=XX/O=Bench/CN=Zep-Bench-CA" 2>/dev/null

# server
openssl genrsa -out "$PKI/server.key" 2048 2>/dev/null
openssl req -new -key "$PKI/server.key" -out "$PKI/server.csr" \
  -subj "/C=XX/O=Bench/CN=bench.zep.lan" 2>/dev/null
cat > "$PKI/server.ext" << 'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$PKI/server.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
  -CAcreateserial -out "$PKI/server.crt" -days 365 -sha256 \
  -extfile "$PKI/server.ext" 2>/dev/null
chmod 644 "$PKI/server.key"

# admin + node certs
for cn in admin bench-node; do
    openssl genrsa -out "$PKI/${cn}.key" 2048 2>/dev/null
    openssl req -new -key "$PKI/${cn}.key" -out "$PKI/${cn}.csr" \
        -subj "/C=XX/O=Bench/CN=${cn}" 2>/dev/null
    openssl x509 -req -in "$PKI/${cn}.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
        -CAcreateserial -out "$PKI/${cn}.crt" -days 365 -sha256 2>/dev/null
    chmod 644 "$PKI/${cn}.key"
done

# server DB + start
SDB=/tmp/zep-bench/zep-air.db
"$SERV" --setup --cert "$PKI/server.crt" --key "$PKI/server.key" \
    --ca "$PKI/ca.crt" --admin-cert "$PKI/admin.crt" --db "$SDB" 2>/dev/null

"$SERV" --verbose --port "$SERVER_PORT" --cert "$PKI/server.crt" --key "$PKI/server.key" \
    --ca "$PKI/ca.crt" --db "$SDB" --storage /tmp/zep-bench/storage &>/tmp/zep-bench/srv.log &
SERV_PID=$!
sleep 2

if ! kill -0 $SERV_PID 2>/dev/null; then
    echo "Server failed to start"; exit 1
fi

# register node
BASE="--server https://bench.zep.lan:$SERVER_PORT --cert $PKI/admin.crt --key $PKI/admin.key --ca $PKI/ca.crt"
"$ADMIN" $BASE join --role client --node bench-node --cert "$PKI/bench-node.crt" >/dev/null

# node config
NDB=/tmp/zep-bench/node/zep-air.db
rm -f "$NDB"
"$ZEP" --db "$NDB" config set node_name bench-node
"$ZEP" --db "$NDB" config set server_url "https://bench.zep.lan:$SERVER_PORT"
"$ZEP" --db "$NDB" config set cert_path "$PKI/bench-node.crt"
"$ZEP" --db "$NDB" config set key_path "$PKI/bench-node.key"
"$ZEP" --db "$NDB" config set ca_path "$PKI/ca.crt"

# set pipe_restrict for dd
"$ADMIN" $BASE config set pipe_restrict "zfs,dd" >/dev/null

# start node cron (background)
"$ZEP" --db "$NDB" cron --daemon --interval 2 &
CRON_PID=$!
sleep 2

if ! kill -0 $CRON_PID 2>/dev/null; then
    echo "Node cron failed to start"; exit 1
fi

echo "  Server PID=$SERV_PID  Node cron PID=$CRON_PID"

# ── benchmarks ──
echo -e "\n${CYAN}Pipe benchmarks (admin → server → node → server → admin)${NC}"

ADMIN_BASE="--server https://bench.zep.lan:$SERVER_PORT --cert $PKI/admin.crt --key $PKI/admin.key --ca $PKI/ca.crt"

bm_quiet "pipe"     "$ADMIN" $ADMIN_BASE pipe dd if=/dev/urandom bs=1M "count=$COUNT_MB"
bm_quiet "pipe+zstd" "$ADMIN" $ADMIN_BASE pipe --compress dd if=/dev/urandom bs=1M "count=$COUNT_MB"
bm_quiet "pipe+zbuf" "$ADMIN" $ADMIN_BASE pipe --compress --buffer dd if=/dev/urandom bs=1M "count=$COUNT_MB"

# ── stderr test ──
echo -e "\n${CYAN}Stderr propagation test${NC}"
STDERR_OUT=$("$ADMIN" $ADMIN_BASE pipe dd if=/dev/urandom bs=1M count=4 2>&1 >/dev/null || true)
echo "$STDERR_OUT" | grep -q "bytes.*copied\|records" && \
    echo -e "  ${GREEN}OK${NC}   stderr from remote dd visible" || \
    echo -e "  ${RED}FAIL${NC} stderr from remote dd missing"

# ── recv direction test ──
echo -e "\n${CYAN}Recv direction test${NC}"
dd if=/dev/zero bs=1M count=4 2>/dev/null | "$ADMIN" $ADMIN_BASE pipe --recv dd of=/tmp/zep-bench/recv-test bs=1M 2>/dev/null
if [ -f /tmp/zep-bench/recv-test ] && [ "$(stat -c%s /tmp/zep-bench/recv-test 2>/dev/null || echo 0)" -eq 4194304 ]; then
    echo -e "  ${GREEN}OK${NC}   recv direction: 4 MB transferred"
else
    echo -e "  ${RED}FAIL${NC} recv direction data mismatch"
fi
rm -f /tmp/zep-bench/recv-test

# ── cleanup ──
echo -e "\n${CYAN}Cleaning up...${NC}"
kill $CRON_PID 2>/dev/null || true
kill $SERV_PID 2>/dev/null || true
sleep 1
rm -rf /tmp/zep-bench

echo -e "\n${GREEN}Benchmark complete.${NC}"
echo "Count = ${COUNT_MB} MB. Divide by 4 hops for per-hop overhead estimate."

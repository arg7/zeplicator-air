#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

PORT=18449
TMP=/tmp/zep-pipe-test
rm -rf $TMP
mkdir -p $TMP/{pki,storage,node}
PKI=$TMP/pki
DB=$TMP/srv.db
NDB=$TMP/node/z.db

# PKI
openssl genrsa -out $PKI/ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key $PKI/ca.key -sha256 -days 365 -out $PKI/ca.crt -subj "/CN=CA" 2>/dev/null
for cn in bench.zep.lan admin benchie; do
    openssl genrsa -out $PKI/$cn.key 2048 2>/dev/null
    openssl req -new -key $PKI/$cn.key -out $PKI/$cn.csr -subj "/CN=$cn" 2>/dev/null
    openssl x509 -req -in $PKI/$cn.csr -CA $PKI/ca.crt -CAkey $PKI/ca.key -CAcreateserial -out $PKI/$cn.crt -days 365 -sha256 2>/dev/null
done
cp $PKI/bench.zep.lan.crt $PKI/server.crt
cp $PKI/bench.zep.lan.key $PKI/server.key
grep -q bench.zep.lan /etc/hosts || echo "127.0.1.1 bench.zep.lan" | sudo tee -a /etc/hosts >/dev/null

# Server
./zep-air-serve --setup --cert $PKI/server.crt --key $PKI/server.key --ca $PKI/ca.crt --admin-cert $PKI/admin.crt --db $DB 2>/dev/null
./zep-air-serve --port $PORT --cert $PKI/server.crt --key $PKI/server.key --ca $PKI/ca.crt --db $DB --storage $TMP/storage &>/dev/null &
SERV=$!
echo "server=$SERV"

# Node setup
BASE="--server https://bench.zep.lan:$PORT --cert $PKI/admin.crt --key $PKI/admin.key --ca $PKI/ca.crt"
sleep 1
timeout 3s ./zep-air-admin $BASE join --role client --node benchie --cert $PKI/benchie.crt 2>/dev/null || true
timeout 3s ./zep-air-admin $BASE config set pipe_restrict "zfs,dd" 2>/dev/null || true

./zep-air --db $NDB config set node_name benchie 2>/dev/null || true
./zep-air --db $NDB config set server_url "https://bench.zep.lan:$PORT" 2>/dev/null || true
./zep-air --db $NDB config set cert_path $PKI/benchie.crt 2>/dev/null || true
./zep-air --db $NDB config set key_path $PKI/benchie.key 2>/dev/null || true
./zep-air --db $NDB config set ca_path $PKI/ca.crt 2>/dev/null || true

# Cron
./zep-air --db $NDB cron --daemon --interval 1 &>/dev/null &
CRON=$!
echo "cron=$CRON"

# Test
echo "=== PIPE 4KB ==="
timeout 10s ./zep-air-admin $BASE pipe dd if=/dev/urandom bs=1K count=4 >$TMP/out 2>$TMP/err || true
echo "stdout: $(wc -c < $TMP/out) bytes"
echo "stderr:"
cat $TMP/err
echo "---"
echo "PIPE benched!"

# Cleanup
kill $CRON $SERV 2>/dev/null; wait 2>/dev/null
rm -rf $TMP

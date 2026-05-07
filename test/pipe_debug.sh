#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."

PORT=18455
TMP=/tmp/zep-pipe-dbg
rm -rf $TMP 2>/dev/null || sudo rm -rf $TMP 2>/dev/null || true
mkdir -p $TMP/{pki,storage,node}
PKI=$TMP/pki
SDB=$TMP/srv.db
NDB=$TMP/node/z.db

# PKI
openssl genrsa -out $PKI/ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key $PKI/ca.key -sha256 -days 365 -out $PKI/ca.crt -subj "/CN=D" 2>/dev/null
for cn in srv admin n1; do
    openssl genrsa -out $PKI/$cn.key 2048 2>/dev/null
    openssl req -new -key $PKI/$cn.key -out $PKI/$cn.csr -subj "/CN=$cn" 2>/dev/null
    openssl x509 -req -in $PKI/$cn.csr -CA $PKI/ca.crt -CAkey $PKI/ca.key -CAcreateserial -out $PKI/$cn.crt -days 365 -sha256 2>/dev/null
done
sed -i "/srv/d" /etc/hosts 2>/dev/null || true
echo "127.0.0.1 srv" | sudo tee -a /etc/hosts >/dev/null

# Server setup + start
./zep-air-serve --setup --cert $PKI/srv.crt --key $PKI/srv.key --ca $PKI/ca.crt --admin-cert $PKI/admin.crt --db $SDB 2>/dev/null
./zep-air-serve --verbose --port $PORT --cert $PKI/srv.crt --key $PKI/srv.key --ca $PKI/ca.crt --db $SDB --storage $TMP/storage >$TMP/srv.out 2>$TMP/srv.err &
SERV=$!
echo "server=$SERV"
sleep 2

# Register
B="--server https://srv:$PORT --cert $PKI/admin.crt --key $PKI/admin.key --ca $PKI/ca.crt"
./zep-air-admin $B join --role client --node n1 --cert $PKI/n1.crt 2>/dev/null
./zep-air-admin $B config set pipe_restrict "zfs,dd" 2>/dev/null

# Node config
./zep-air --db $NDB config set node_name n1 2>/dev/null
./zep-air --db $NDB config set server_url "https://srv:$PORT" 2>/dev/null
./zep-air --db $NDB config set cert_path $PKI/n1.crt 2>/dev/null
./zep-air --db $NDB config set key_path $PKI/n1.key 2>/dev/null
./zep-air --db $NDB config set ca_path $PKI/ca.crt 2>/dev/null

# Cron
./zep-air --db $NDB cron --daemon --interval 1 >/dev/null 2>&1 &
CRON=$!
echo "cron=$CRON"
sleep 2

# Pipe test
echo "=== PIPE ==="
timeout 10s ./zep-air-admin $B pipe dd if=/dev/urandom bs=1M count=20 >$TMP/out 2>$TMP/err || true
echo "stdout: $(wc -c < $TMP/out) bytes"
echo "stderr:"
cat $TMP/err
echo "--- server err ---"
grep pipe_done $TMP/srv.err 2>/dev/null || echo "(no pipe_done)"
echo "--- server log tail ---"
tail -5 $TMP/srv.err

# Cleanup
kill $CRON $SERV 2>/dev/null; wait 2>/dev/null
rm -rf $TMP 2>/dev/null
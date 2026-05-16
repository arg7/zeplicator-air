#!/bin/bash
# Pull resume standalone test — uses lib.sh test infrastructure
set -u
source "$(dirname "$0")/lib.sh"

init_bins
cp -f "$PROJ_DIR/zep-air" "$PROJ_DIR/zep-air-serve" "$PROJ_DIR/zep-air-admin" /usr/local/bin/ 2>/dev/null || true
ZEP="/usr/local/bin/zep-air"
SERV_BIN="/usr/local/bin/zep-air-serve"
ADMIN="/usr/local/bin/zep-air-admin"

# cleanup
for p in rpool rclient; do sudo zpool destroy "$p" 2>/dev/null || true; done
sudo pkill -f "zep-air" 2>/dev/null; sleep 1

init_tmp zpr
hosts_add master.zep.lan
sudo chmod 777 "$TMP" "$TMP/store" "$TMP/pki" 2>/dev/null || true
mkdir -p "$TMP/server-db" 2>/dev/null
sudo chmod 777 "$TMP/server-db" 2>/dev/null || true

PKI="$TMP/pki"
STORE="$TMP/store"
SDB="$TMP/server-db/zep-air.db"
ZCMD="--db"

pki_ca; pki_server master.zep.lan; pki_nodes admin master client

# Pools — master pool (mounted, writable), client pool (mountpoint=none)
img="$TMP/master.img"
truncate -s 512M "$img"
sudo zpool create -m "$TMP/pools/master" rpool "$img" 2>/dev/null
sudo zfs allow -u root clone,create,destroy,mount,promote,receive,rollback,send,snapshot rpool 2>/dev/null
sudo mkdir -p "$TMP/pools/master"
sudo dd if=/dev/urandom of="$TMP/pools/master/bigfile" bs=1024 count=1536 2>/dev/null

img2="$TMP/client.img"
truncate -s 512M "$img2"
sudo zpool create -m none rclient "$img2" 2>/dev/null
sudo zfs allow -u root clone,create,destroy,mount,promote,receive,rollback,send,snapshot rclient 2>/dev/null

# Server
sudo "$SERV_BIN" --setup --cert "$PKI/server.crt" --key "$PKI/server.key" --ca "$PKI/ca.crt" --admin-cert "$PKI/admin.crt" --db "$SDB" 2>/dev/null
sudo chmod 666 "$SDB" 2>/dev/null

"$SERV_BIN" --port 19448 --cert "$PKI/server.crt" --key "$PKI/server.key" --ca "$PKI/ca.crt" --db "$SDB" --storage "$STORE" &
SERV=$!
sleep 2
kill -0 $SERV 2>/dev/null || { echo "Server failed to start"; exit 1; }

admin_base "https://master.zep.lan:19448" "$PKI/admin.crt" "$PKI/admin.key" "$PKI/ca.crt"

# Cluster config
cat > "$TMP/cluster.json" << 'CEOF'
{"name":"test","pools":{"za-pool-1":{"za-data-1":{"labels":{"min":5,"hour":10,"day":5}}}}}
CEOF
"$ADMIN" $ADMIN_BASE cluster set --file "$TMP/cluster.json" >/dev/null

# Register nodes with roles (uses lib.sh node_join which handles cert upload)
node_join master master "" test "za-pool-1/za-data-1:rpool"
node_join client client "" test "za-pool-1/za-data-1:rclient"

# Master node config
node_config "$TMP/master.db" master "https://master.zep.lan:19448" "$PKI/master.crt" "$PKI/master.key"
node_config_set "$TMP/master.db" cluster test
node_config_set "$TMP/master.db" mapping "za-pool-1/za-data-1:rpool"
node_config_set "$TMP/master.db" push_zip_cmd "zstd -c -1"
node_config_set "$TMP/master.db" pull_unzip_cmd "zstd -d"

# Client node config
node_config "$TMP/client.db" client "https://master.zep.lan:19448" "$PKI/client.crt" "$PKI/client.key"
node_config_set "$TMP/client.db" cluster test
node_config_set "$TMP/client.db" mapping "za-pool-1/za-data-1:rclient"
node_config_set "$TMP/client.db" push_zip_cmd "zstd -c -1"
node_config_set "$TMP/client.db" pull_unzip_cmd "zstd -d"
node_config_set "$TMP/client.db" resume 1
node_config_set "$TMP/client.db" pull_buf_cmd "head -c 1000000"

echo ""
echo "=== Test 1: Push ==="
out=$("$ZEP" $ZCMD "$TMP/master.db" push -f rpool -l hourly 2>&1)
echo "$out" | grep -q "Push complete" && ok "push succeeded" || bad "push failed"

echo ""
echo "=== Test 2: Truncated pull (zfs recv -s) ==="
zfs recv -A rclient 2>/dev/null || true
out=$("$ZEP" $ZCMD "$TMP/client.db" pull -f rclient -d master 2>&1)
echo "==="
echo "$out"
echo "==="

state=$("$ZEP" $ZCMD "$TMP/client.db" config get pull_state_rclient_hourly 2>/dev/null)
[[ "$state" != "(not set)" && -n "$state" ]] && ok "pull_state: $state" || bad "pull_state: $state"

tok=$(zfs get -Hp -o value receive_resume_token rclient 2>/dev/null)
[[ -n "$tok" && "$tok" != "-" ]] && ok "token set" || bad "token: '$tok'"

echo ""
echo "=== Test 3: Resume via cron daemon ==="
"$ZEP" $ZCMD "$TMP/client.db" config set pull_buf_cmd ""
cron_spawn "$TMP/client.db" 5
sleep 15
cron_kill_all

snaps=$(zfs list -r -t snapshot rclient 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $snaps -ge 1 ]] && ok "resume complete ($snaps snaps)" || bad "resume: $snaps snaps"

echo ""
server_stop
print_results
exit $fail
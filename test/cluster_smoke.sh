#!/bin/bash
# Zeplicator Air cluster test — full HTTP mode via zep-air-serve
set -u
source "$(dirname "$0")/lib.sh"

# Override binary paths for this test
ZEP="/usr/local/bin/zep-air"
SERV="/usr/local/bin/zep-air-serve"
ADMIN="/usr/local/bin/zep-air-admin"

init_bins
sudo cp "$PROJ_DIR/zep-air" "$PROJ_DIR/zep-air-serve" "$PROJ_DIR/zep-air-admin" /usr/local/bin/ 2>/dev/null || true

# ---- user setup ----
for user in za-master za-client-1 za-client-2; do
    id "$user" &>/dev/null || sudo useradd -r -s /bin/bash -d "/tmp/zep-air/home/$user" -m "$user" 2>/dev/null
done
hosts_add master.zep.lan client1.zep.lan client2.zep.lan
hosts_add za-master za-client-1 za-client-2

# ---- cleanup previous state ----
for pool in za-master-pool za-client-1-pool za-client-2-pool; do
    sudo zpool destroy "$pool" 2>/dev/null || true
done
pkill -f "zep-air-serve" 2>/dev/null || true
sleep 1

init_tmp zep-air
mkdir -p "$TMP/server-db"
sudo chmod 777 "$TMP" "$TMP/store" "$TMP/pki" "$TMP/server-db"

# ---- PKI ----
pki_ca
pki_server master.zep.lan
pki_nodes za-master za-client-1 za-client-2 admin

# ---- ZFS pools ----
for user in za-master za-client-1 za-client-2; do
    img="$TMP/${user}.img"
    truncate -s 256M "$img"
    sudo chown "$user:$user" "$img"
    pool="${user}-pool"
    sudo zpool create -m "$TMP/pools/${user}" "$pool" "$img" 2>/dev/null
    sudo zfs allow -u "$user" clone,create,destroy,mount,promote,receive,rollback,send,snapshot "$pool" 2>/dev/null
    sudo zfs create -o mountpoint=none "${pool}/slave" 2>/dev/null
    sudo mkdir -p "$TMP/pools/${user}" 2>/dev/null
    sudo chown -R "$user:$user" "$TMP/pools/${user}" 2>/dev/null || true
done
sudo zfs create -o mountpoint=none za-master-pool/master 2>/dev/null
sudo zfs allow -u za-master clone,create,destroy,mount,promote,receive,rollback,send,snapshot za-master-pool 2>/dev/null

# ---- server ----
SDB="$TMP/server-db/zep-air.db"
sudo "$SERV" --setup --cert "$PKI/server.crt" --key "$PKI/server.key" \
    --ca "$PKI/ca.crt" --admin-cert "$PKI/admin.crt" --db "$SDB" 2>/dev/null

"$SERV" --port 18443 --cert "$PKI/server.crt" --key "$PKI/server.key" \
    --ca "$PKI/ca.crt" --db "$SDB" --storage "$TMP/store" &
SERV_PID=$!
sleep 2
if ! kill -0 $SERV_PID 2>/dev/null; then
    echo "Server failed to start"; exit 1
fi

# ---- register + configure nodes ----
admin_base "https://master.zep.lan:18443" "$PKI/admin.crt" "$PKI/admin.key" "$PKI/ca.crt"

# First batch: register without cluster (auto-register certs)
node_join master za-master
node_join client za-client-1
node_join client za-client-2

for user in za-master za-client-1 za-client-2; do
    db="$TMP/${user}.db"
    node_config "$db" "$user" "https://master.zep.lan:18443" "$PKI/${user}.crt" "$PKI/${user}.key"
done

# Cluster + mapping on nodes
node_config_set "$TMP/za-master.db" cluster test
node_config_set "$TMP/za-master.db" mapping "za-pool-1/za-data-1:za-master-pool/master"
node_config_set "$TMP/za-client-1.db" mapping "za-pool-1/za-data-1:za-client-1-pool/slave"
node_config_set "$TMP/za-client-2.db" mapping "za-pool-1/za-data-1:za-client-2-pool/slave"

# Cluster on server
cat > "$TMP/cluster.json" << 'CEOF'
{"name":"test","pools":{"za-pool-1":{"za-data-1":{"labels":{"min":60,"hour":24,"day":30}}}}}
CEOF
"$ADMIN" $ADMIN_BASE cluster set --file "$TMP/cluster.json" >/dev/null

# Second batch: register with cluster + mapping
node_join master za-master "" test "za-pool-1/za-data-1:za-master-pool/master"
node_join client za-client-1 "" test "za-pool-1/za-data-1:za-client-1-pool/slave"
node_join client za-client-2 "" test "za-pool-1/za-data-1:za-client-2-pool/slave"

echo ""

# --- tests ---
ZCMD="--db"

# test 1
echo -e "${CYAN}Test 1: master push full (HTTP)${NC}"
out=$(sudo -u za-master "$ZEP" $ZCMD "$TMP/za-master.db" push -f za-master-pool/master -l hour 2>&1)
echo "$out" | grep -q "Push complete" && ok "push succeeded" || bad "push failed"
echo "$out" | grep -q "full base" && ok "full send detected" || bad "not full send"

# test 2
echo -e "${CYAN}Test 2: master push incremental (HTTP)${NC}"
sleep 1
out=$(sudo -u za-master "$ZEP" $ZCMD "$TMP/za-master.db" push -f za-master-pool/master -l hour 2>&1)
echo "$out" | grep -q "Push complete" && ok "push succeeded" || bad "push failed"
echo "$out" | grep -q "incremental" && ok "incremental send detected" || bad "not incremental"

# test 3
echo -e "${CYAN}Test 3: client-1 pull (HTTP)${NC}"
out=$(sudo -u za-client-1 "$ZEP" $ZCMD "$TMP/za-client-1.db" pull -f za-client-1-pool/slave -d za-master 2>&1)
snaps=$(sudo zfs list -r -t snap za-client-1-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $snaps -eq 2 ]] && ok "client-1 has 2 snapshots" || bad "client-1 has $snaps snapshots"

# test 4
echo -e "${CYAN}Test 4: client-2 pull (HTTP)${NC}"
out=$(sudo -u za-client-2 "$ZEP" $ZCMD "$TMP/za-client-2.db" pull -f za-client-2-pool/slave -d za-master 2>&1)
snaps=$(sudo zfs list -r -t snap za-client-2-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $snaps -eq 2 ]] && ok "client-2 has 2 snapshots" || bad "client-2 has $snaps snapshots"

# test 5
echo -e "${CYAN}Test 5: GUID consistency${NC}"
g_master=$(sudo zfs get -t snap -r -Hp -o value guid za-master-pool/master 2>/dev/null | grep -E '^[0-9]+$' | sort -n || true)
g_c1=$(sudo zfs get -t snap -r -Hp -o value guid za-client-1-pool/slave 2>/dev/null | grep -E '^[0-9]+$' | sort -n || true)
g_c2=$(sudo zfs get -t snap -r -Hp -o value guid za-client-2-pool/slave 2>/dev/null | grep -E '^[0-9]+$' | sort -n || true)
diff -q <(echo "$g_master") <(echo "$g_c1") && ok "client-1 GUIDs match" || bad "client-1 GUID mismatch"
diff -q <(echo "$g_master") <(echo "$g_c2") && ok "client-2 GUIDs match" || bad "client-2 GUID mismatch"

# test 6
echo -e "${CYAN}Test 6: replica chain via HTTP (c1 -> c2)${NC}"
sudo zfs create -o mountpoint=none za-client-1-pool/master 2>/dev/null || true
sudo zfs allow -u za-client-1 clone,create,destroy,mount,promote,receive,rollback,send,snapshot za-client-1-pool 2>/dev/null || true
sudo -u za-client-1 "$ZEP" $ZCMD "$TMP/za-client-1.db" push -f za-client-1-pool/master -l hour >/dev/null 2>&1
sudo zfs create -o mountpoint=none za-client-2-pool/slave2 2>/dev/null || true
sudo -u za-client-2 "$ZEP" $ZCMD "$TMP/za-client-2.db" pull -f za-client-2-pool/slave2 -d za-client-1 >/dev/null 2>&1
snaps=$(sudo zfs list -r -t snap za-client-2-pool/slave2 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $snaps -ge 1 ]] && ok "replica chain works ($snaps snaps)" || bad "replica chain failed ($snaps snaps)"

# test 7
echo -e "${CYAN}Test 7: idempotent pull${NC}"
before=$(sudo zfs list -r -t snap za-client-1-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
sudo -u za-client-1 "$ZEP" $ZCMD "$TMP/za-client-1.db" pull -f za-client-1-pool/slave -d za-master >/dev/null 2>&1
after=$(sudo zfs list -r -t snap za-client-1-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $before -eq $after ]] && ok "idempotent ($before snaps)" || bad "duplicates: $before -> $after"

# test 8
echo -e "${CYAN}Test 8: admin API rejects non-admin cert${NC}"
out=$("$ADMIN" --server https://master.zep.lan:18443 \
    --cert "$PKI/za-master.crt" --key "$PKI/za-master.key" --ca "$PKI/ca.crt" \
    join --role client --node evil --cert "$PKI/za-master.crt" 2>&1)
echo "$out" | grep -qE '403|Admin' && ok "admin API rejects non-admin cert" || bad "admin API accepted non-admin cert"

# test 9
echo -e "${CYAN}Test 9: push works with node cert${NC}"
out=$(sudo -u za-master "$ZEP" $ZCMD "$TMP/za-master.db" push -f za-master-pool/master -l daily 2>&1)
echo "$out" | grep -q "Push complete" && ok "push with node cert succeeded" || bad "push with node cert failed"

# ---- pipe tests: need cron daemons ----
for user in za-master za-client-1 za-client-2; do
    sudo -u "$user" "$ZEP" --db "$TMP/${user}.db" cron --daemon --interval 2 &
    CRON_PIDS+=($!)
done
sleep 3
pipe_allow zfs

PIPE_ADM="--server https://master.zep.lan:18443 --cert $PKI/admin.crt --key $PKI/admin.key --ca $PKI/ca.crt"

# test 10
echo -e "${CYAN}Test 10: pipe zfs list -t snap${NC}"
out=$(timeout 12s "$ADMIN" $PIPE_ADM pipe --node za-master zfs list -t snap 2>/dev/null)
echo "$out" | grep -q '@' && ok "pipe zfs list returned snapshots" || bad "pipe zfs list failed"

# test 11
echo -e "${CYAN}Test 11: pipe zfs send | zstream dump -v${NC}"
last_snap=$(sudo zfs list -t snap -o name -s creation za-master-pool/master 2>/dev/null | tail -1 | tr -d '[:space:]')
if [ -n "$last_snap" ]; then
    timeout 12s "$ADMIN" $PIPE_ADM pipe --node za-master zfs send "$last_snap" 2>/dev/null \
        | zstream dump -v >/dev/null 2>&1
    [ $? -eq 0 ] && ok "pipe zfs send valid stream ($last_snap)" \
                  || bad "pipe zfs send stream invalid"
else
    bad "no snapshot found for pipe zfs send"
fi

# test 12 — pipe send pipeline: zfs list | zstd -c → admin | zstd -d
echo -e "${CYAN}Test 12: pipe send pipeline (zfs list | zstd -c → zstd -d)${NC}"
out=$(timeout 12s "$ADMIN" $PIPE_ADM pipe --node za-master "zfs list -H -o name -t snap za-master-pool/master | zstd -c" 2>/dev/null | zstd -d 2>/dev/null)
echo "$out" | grep -q '@' && ok "pipe send pipeline returned snapshots" || bad "pipe send pipeline failed"

# test 13 — pipe recv pipeline: echo | zstd -c → admin → zstd -d | head -c 5
echo -e "${CYAN}Test 13: pipe recv pipeline (zstd -d | head -c 5)${NC}"
pipe_allow "zfs,head"
out=$(echo "hello world!" | zstd -c | timeout 12s "$ADMIN" $PIPE_ADM pipe --node za-master "zstd -d | head -c 5" 2>/dev/null)
echo "$out" | grep -q "hello" && ok "pipe recv pipeline returned 'hello'" || bad "pipe recv pipeline failed: got '$out'"
pipe_allow zfs

# ---- SSH mesh: passwordless SSH between test accounts ----
SSH_KEY="/tmp/zep-air/ssh/mesh_key"
mkdir -p /tmp/zep-air/ssh
ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "zep-air-mesh" >/dev/null 2>&1
# Create shared group for mesh key access
sudo groupadd -f zep-mesh 2>/dev/null || true
for user in za-master za-client-1 za-client-2; do
    id "$user" &>/dev/null && sudo usermod -aG zep-mesh "$user" 2>/dev/null || true
done
sudo chown root:zep-mesh "$SSH_KEY"
sudo chmod 640 "$SSH_KEY"
sudo chmod 644 "${SSH_KEY}.pub"
SSH_PUB="$(cat "${SSH_KEY}.pub")"
for user in za-master za-client-1 za-client-2; do
    sudo mkdir -p "/tmp/zep-air/home/$user/.ssh"
    echo "$SSH_PUB" | sudo tee "/tmp/zep-air/home/$user/.ssh/authorized_keys" >/dev/null
    sudo chmod 700 "/tmp/zep-air/home/$user/.ssh"
    sudo chmod 600 "/tmp/zep-air/home/$user/.ssh/authorized_keys"
    # Per-user SSH config: use shared mesh key, skip host key checks
    cat > "/tmp/zep-air/home/$user/.ssh/config" << SSHEOF
Host 127.0.1.1
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
Host *.zep.lan zep.lan za-master za-client-1 za-client-2
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    IdentityFile $SSH_KEY
    IdentitiesOnly yes
    LogLevel ERROR
SSHEOF
    sudo chmod 600 "/tmp/zep-air/home/$user/.ssh/config"
    # known_hosts: empty, verification skipped via config
    > "/tmp/zep-air/home/$user/.ssh/known_hosts"
    sudo chmod 644 "/tmp/zep-air/home/$user/.ssh/known_hosts"
    sudo chown -R "$user:$user" "/tmp/zep-air/home/$user/.ssh"
done
# System-wide known_hosts bypass for root
sudo mkdir -p /etc/ssh/ssh_config.d
cat > /etc/ssh/ssh_config.d/zep-air-mesh.conf << 'SSHEOF'
Host 127.0.1.1
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
SSHEOF

# ---- cleanup ----
cron_kill_all
server_stop

exit_on_fail
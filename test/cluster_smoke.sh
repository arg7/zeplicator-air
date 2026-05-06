#!/bin/bash
# Zeplicator Air cluster test — full HTTP mode via zep-air-serve
set -u

RED='\033[31m'; GREEN='\033[32m'; CYAN='\033[36m'; NC='\033[0m'
pass=0; fail=0
ZEP="/usr/local/bin/zep-air"
SERV="/usr/local/bin/zep-air-serve"
ADMIN="/usr/local/bin/zep-air-admin"

ok()  { echo -e "  ${GREEN}OK${NC}  $1"; pass=$((pass+1)); }
bad() { echo -e "  ${RED}FAIL${NC} $1"; fail=$((fail+1)); }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
make -C "$SCRIPT_DIR/.." -s 2>&1 || true
sudo cp "$SCRIPT_DIR/../zep-air" "$SCRIPT_DIR/../zep-air-serve" "$SCRIPT_DIR/../zep-air-admin" /usr/local/bin/ 2>/dev/null || true

# ---- user setup ----
for user in za-master za-client-1 za-client-2; do
    id "$user" &>/dev/null || sudo useradd -r -s /bin/bash -d "/tmp/zep-air/home/$user" -m "$user" 2>/dev/null
done
for fqdn in master.zep.lan client1.zep.lan client2.zep.lan; do
    grep -q "$fqdn" /etc/hosts || echo "127.0.1.1 $fqdn" | sudo tee -a /etc/hosts >/dev/null
done

# ---- cleanup ----
for pool in za-master-pool za-client-1-pool za-client-2-pool; do
    sudo zpool destroy "$pool" 2>/dev/null || true
done
pkill -f "zep-air-serve" 2>/dev/null || true
sleep 1
sudo rm -rf /tmp/zep-air
mkdir -p /tmp/zep-air/{store,pki,server-db}
sudo chmod 777 /tmp/zep-air /tmp/zep-air/store /tmp/zep-air/pki /tmp/zep-air/server-db

# ---- PKI ----
PKI=/tmp/zep-air/pki
openssl genrsa -out $PKI/ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key $PKI/ca.key -sha256 -days 3650 \
  -out $PKI/ca.crt -subj "/C=IT/O=CompEd/CN=Zep-Air testing" 2>/dev/null

# server cert
openssl genrsa -out $PKI/server.key 2048 2>/dev/null
openssl req -new -key $PKI/server.key -out $PKI/server.csr \
  -subj "/C=IT/O=CompEd/CN=master.zep.lan" 2>/dev/null
cat > $PKI/server.ext << 'XEOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
XEOF
openssl x509 -req -in $PKI/server.csr -CA $PKI/ca.crt -CAkey $PKI/ca.key \
  -CAcreateserial -out $PKI/server.crt -days 365 -sha256 \
  -extfile $PKI/server.ext 2>/dev/null
chmod 644 $PKI/server.key

# node certs
cat > $PKI/client.ext << 'XEOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
XEOF
for cn in za-master za-client-1 za-client-2 admin; do
    openssl genrsa -out "$PKI/${cn}.key" 2048 2>/dev/null
    openssl req -new -key "$PKI/${cn}.key" -out "$PKI/${cn}.csr" \
        -subj "/C=IT/O=CompEd/CN=${cn}" 2>/dev/null
    openssl x509 -req -in "$PKI/${cn}.csr" -CA $PKI/ca.crt -CAkey $PKI/ca.key \
        -CAcreateserial -out "$PKI/${cn}.crt" -days 365 -sha256 \
        -extfile $PKI/client.ext 2>/dev/null
    chmod 644 "$PKI/${cn}.key"
done

# ---- ZFS pools ----
for user in za-master za-client-1 za-client-2; do
    img="/tmp/zep-air/${user}.img"
    truncate -s 256M "$img"
    sudo chown "$user:$user" "$img"
    pool="${user}-pool"
    sudo zpool create -m "/tmp/zep-air/pools/${user}" "$pool" "$img" 2>/dev/null
    sudo zfs allow -u "$user" clone,create,destroy,mount,promote,receive,rollback,send,snapshot "$pool" 2>/dev/null
    sudo zfs create -o mountpoint=none "${pool}/slave" 2>/dev/null
    sudo mkdir -p "/tmp/zep-air/pools/${user}" 2>/dev/null
    sudo chown -R "$user:$user" "/tmp/zep-air/pools/${user}" 2>/dev/null || true
done
sudo zfs create -o mountpoint=none za-master-pool/master 2>/dev/null
sudo zfs allow -u za-master clone,create,destroy,mount,promote,receive,rollback,send,snapshot za-master-pool 2>/dev/null

# ---- server setup + start ----
SDB=/tmp/zep-air/server-db/zep-air.db
sudo "$SERV" --setup \
    --cert "$PKI/server.crt" --key "$PKI/server.key" --ca "$PKI/ca.crt" \
    --admin-cert "$PKI/admin.crt" --db "$SDB" 2>/dev/null

"$SERV" --port 18443 --cert "$PKI/server.crt" --key "$PKI/server.key" \
    --ca "$PKI/ca.crt" --db "$SDB" --storage /tmp/zep-air/store &
SERV_PID=$!
sleep 2

if ! kill -0 $SERV_PID 2>/dev/null; then
    echo "Server failed to start"; exit 1
fi

# ---- register nodes via admin ----
BASE="--server https://master.zep.lan:18443 --cert $PKI/admin.crt --key $PKI/admin.key --ca $PKI/ca.crt"
"$ADMIN" $BASE join --role master --node za-master --cert "$PKI/za-master.crt" >/dev/null
"$ADMIN" $BASE join --role client --node za-client-1 --cert "$PKI/za-client-1.crt" >/dev/null
"$ADMIN" $BASE join --role client --node za-client-2 --cert "$PKI/za-client-2.crt" >/dev/null

# ---- configure nodes ----
for user in za-master za-client-1 za-client-2; do
    db="/tmp/zep-air/${user}.db"
    sudo rm -f "$db"
    sudo -u "$user" "$ZEP" --db "$db" config set node_name "$user"
    sudo -u "$user" "$ZEP" --db "$db" config set server_url "https://master.zep.lan:18443"
    sudo -u "$user" "$ZEP" --db "$db" config set cert_path "$PKI/${user}.crt"
    sudo -u "$user" "$ZEP" --db "$db" config set key_path "$PKI/${user}.key"
    sudo -u "$user" "$ZEP" --db "$db" config set ca_path "$PKI/ca.crt"
done

echo ""

# ---- test 1: master push full ----
echo -e "${CYAN}Test 1: master push full (HTTP)${NC}"
out=$(sudo -u za-master "$ZEP" --db /tmp/zep-air/za-master.db push -f za-master-pool/master -l hourly 2>&1)
echo "$out" | grep -q "Push complete" && ok "push succeeded" || bad "push failed"
echo "$out" | grep -q "full base" && ok "full send detected" || bad "not full send"

# ---- test 2: master push incremental ----
echo -e "${CYAN}Test 2: master push incremental (HTTP)${NC}"
sleep 1
out=$(sudo -u za-master "$ZEP" --db /tmp/zep-air/za-master.db push -f za-master-pool/master -l hourly 2>&1)
echo "$out" | grep -q "Push complete" && ok "push succeeded" || bad "push failed"
echo "$out" | grep -q "incremental" && ok "incremental send detected" || bad "not incremental"

# ---- test 3: client-1 pull ----
echo -e "${CYAN}Test 3: client-1 pull (HTTP)${NC}"
out=$(sudo -u za-client-1 "$ZEP" --db /tmp/zep-air/za-client-1.db pull -f za-client-1-pool/slave -d za-master 2>&1)
snaps=$(sudo zfs list -r -t snapshot za-client-1-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $snaps -eq 2 ]] && ok "client-1 has 2 snapshots" || bad "client-1 has $snaps snapshots"

# ---- test 4: client-2 pull ----
echo -e "${CYAN}Test 4: client-2 pull (HTTP)${NC}"
out=$(sudo -u za-client-2 "$ZEP" --db /tmp/zep-air/za-client-2.db pull -f za-client-2-pool/slave -d za-master 2>&1)
snaps=$(sudo zfs list -r -t snapshot za-client-2-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $snaps -eq 2 ]] && ok "client-2 has 2 snapshots" || bad "client-2 has $snaps snapshots"

# ---- test 5: GUID consistency ----
echo -e "${CYAN}Test 5: GUID consistency${NC}"
g_master=$(sudo zfs get -r -Hp -o value guid za-master-pool/master 2>/dev/null | grep -E '^[0-9]+$' | sort | tail -2 || true)
g_c1=$(sudo zfs get -r -Hp -o value guid za-client-1-pool/slave 2>/dev/null | grep -E '^[0-9]+$' | sort || true)
g_c2=$(sudo zfs get -r -Hp -o value guid za-client-2-pool/slave 2>/dev/null | grep -E '^[0-9]+$' | sort || true)
echo "$g_c1" | grep -q "$(echo "$g_master" | tail -1)" && ok "client-1 latest GUID matches" || bad "client-1 GUID mismatch"
echo "$g_c2" | grep -q "$(echo "$g_master" | tail -1)" && ok "client-2 latest GUID matches" || bad "client-2 GUID mismatch"

# ---- test 6: replica chain (c1 -> c2) ----
echo -e "${CYAN}Test 6: replica chain via HTTP (c1 -> c2)${NC}"
sudo zfs create -o mountpoint=none za-client-1-pool/master 2>/dev/null || true
sudo zfs allow -u za-client-1 clone,create,destroy,mount,promote,receive,rollback,send,snapshot za-client-1-pool 2>/dev/null || true
sudo -u za-client-1 "$ZEP" --db /tmp/zep-air/za-client-1.db push -f za-client-1-pool/master -l hourly >/dev/null 2>&1
sudo zfs create -o mountpoint=none za-client-2-pool/slave2 2>/dev/null || true
sudo -u za-client-2 "$ZEP" --db /tmp/zep-air/za-client-2.db pull -f za-client-2-pool/slave2 -d za-client-1 >/dev/null 2>&1
snaps=$(sudo zfs list -r -t snapshot za-client-2-pool/slave2 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $snaps -ge 1 ]] && ok "replica chain works ($snaps snaps)" || bad "replica chain failed ($snaps snaps)"

# ---- test 7: idempotent pull ----
echo -e "${CYAN}Test 7: idempotent pull${NC}"
before=$(sudo zfs list -r -t snapshot za-client-1-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
sudo -u za-client-1 "$ZEP" --db /tmp/zep-air/za-client-1.db pull -f za-client-1-pool/slave -d za-master >/dev/null 2>&1
after=$(sudo zfs list -r -t snapshot za-client-1-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $before -eq $after ]] && ok "idempotent ($before snaps)" || bad "duplicates: $before -> $after"

# ---- test 8: admin API rejects non-admin cert ----
echo -e "${CYAN}Test 8: admin API rejects non-admin cert${NC}"
out=$("$ADMIN" --server https://master.zep.lan:18443 \
    --cert "$PKI/za-master.crt" --key "$PKI/za-master.key" --ca "$PKI/ca.crt" \
    join --role client --node evil --cert "$PKI/za-master.crt" 2>&1)
echo "$out" | grep -qE '403|Admin' && ok "admin API rejects non-admin cert" || bad "admin API accepted non-admin cert"

# ---- test 9: push works with node cert (not admin) ----
echo -e "${CYAN}Test 9: push works with node cert${NC}"
out=$(sudo -u za-master "$ZEP" --db /tmp/zep-air/za-master.db push -f za-master-pool/master -l daily 2>&1)
echo "$out" | grep -q "Push complete" && ok "push with node cert succeeded" || bad "push with node cert failed"

# ---- stop server ----
kill $SERV_PID 2>/dev/null; wait $SERV_PID 2>/dev/null

echo ""
echo -e "${GREEN}Passed: $pass${NC}  ${RED}Failed: $fail${NC}"
exit $fail

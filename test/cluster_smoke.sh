#!/bin/bash
# Zeplicator Air cluster emulation test
set -u

RED='\033[31m'; GREEN='\033[32m'; CYAN='\033[36m'; NC='\033[0m'
pass=0; fail=0
ZEP="/usr/local/bin/zep-air"

ok()  { echo -e "  ${GREEN}OK${NC}  $1"; pass=$((pass+1)); }
bad() { echo -e "  ${RED}FAIL${NC} $1"; fail=$((fail+1)); }

# ---- build and install ----
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
make -C "$SCRIPT_DIR/.." -s 2>&1 || true
sudo cp "$SCRIPT_DIR/../zep-air" "$SCRIPT_DIR/../zep-air-serve" /usr/local/bin/ 2>/dev/null || true

# ---- user setup ----
for user in za-master za-client-1 za-client-2; do
    id "$user" &>/dev/null || sudo useradd -r -s /bin/bash -d "/tmp/zep-air/home/$user" -m "$user" 2>/dev/null
done

for fqdn in master.zep.lan client1.zep.lan client2.zep.lan; do
    grep -q "$fqdn" /etc/hosts || echo "127.0.1.1 $fqdn" | sudo tee -a /etc/hosts >/dev/null
done

# ---- cleanup old state ----
for pool in za-master-pool za-client-1-pool za-client-2-pool; do
    sudo zpool destroy "$pool" 2>/dev/null || true
done
sudo rm -rf /tmp/zep-air

# ---- create pools ----
mkdir -p /tmp/zep-air/store
sudo chmod 777 /tmp/zep-air /tmp/zep-air/store

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

zfs_pools_ok=true
sudo zpool list za-master-pool &>/dev/null || zfs_pools_ok=false
sudo zpool list za-client-1-pool &>/dev/null || zfs_pools_ok=false
sudo zpool list za-client-2-pool &>/dev/null || zfs_pools_ok=false
$zfs_pools_ok || { echo "Failed to create ZFS pools"; exit 1; }

# ---- configure nodes ----
for user in za-master za-client-1 za-client-2; do
    db="/tmp/zep-air/${user}.db"
    sudo rm -f "$db"
    sudo -u "$user" "$ZEP" --db "$db" config set storage_root /tmp/zep-air/store
    sudo -u "$user" "$ZEP" --db "$db" config set node_name "$user"
done

echo ""

# ---- test 1: master push full snapshot ----
echo -e "${CYAN}Test 1: master push full${NC}"
out=$(sudo -u za-master "$ZEP" --db /tmp/zep-air/za-master.db push -f za-master-pool/master -l hourly 2>&1)
echo "$out" | grep -q "Push complete" && ok "push succeeded" || bad "push failed"
echo "$out" | grep -q "full base" && ok "full send detected" || bad "not full send"

# ---- test 2: master push incremental ----
echo -e "${CYAN}Test 2: master push incremental${NC}"
sleep 1
out=$(sudo -u za-master "$ZEP" --db /tmp/zep-air/za-master.db push -f za-master-pool/master -l hourly 2>&1)
echo "$out" | grep -q "Push complete" && ok "push succeeded" || bad "push failed"
echo "$out" | grep -q "incremental" && ok "incremental send detected" || bad "not incremental send"

# ---- test 3: client-1 pull ----
echo -e "${CYAN}Test 3: client-1 pull${NC}"
out=$(sudo -u za-client-1 "$ZEP" --db /tmp/zep-air/za-client-1.db pull -f za-client-1-pool/slave -d za-master 2>&1)
snaps=$(sudo zfs list -r -t snapshot za-client-1-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $snaps -eq 2 ]] && ok "client-1 has 2 snapshots" || bad "client-1 has $snaps snapshots"

# ---- test 4: client-2 pull ----
echo -e "${CYAN}Test 4: client-2 pull${NC}"
out=$(sudo -u za-client-2 "$ZEP" --db /tmp/zep-air/za-client-2.db pull -f za-client-2-pool/slave -d za-master 2>&1)
snaps=$(sudo zfs list -r -t snapshot za-client-2-pool/slave 2>/dev/null | grep -c '@' | tr -d '[:space:]' || echo 0)
[[ $snaps -eq 2 ]] && ok "client-2 has 2 snapshots" || bad "client-2 has $snaps snapshots"

# ---- test 5: GUID consistency ----
echo -e "${CYAN}Test 5: GUID consistency${NC}"
g_master=$(sudo zfs get -r -Hp -o value guid za-master-pool/master 2>/dev/null | grep -Ev '^[0-9]+$' -v | sort | tail -2 || true)
g_c1=$(sudo zfs get -r -Hp -o value guid za-client-1-pool/slave 2>/dev/null | grep -E '^[0-9]+$' | sort || true)
g_c2=$(sudo zfs get -r -Hp -o value guid za-client-2-pool/slave 2>/dev/null | grep -E '^[0-9]+$' | sort || true)
echo "$g_c1" | grep -q "$(echo "$g_master" | tail -1)" && ok "client-1 latest GUID matches" || bad "client-1 GUID mismatch"
echo "$g_c2" | grep -q "$(echo "$g_master" | tail -1)" && ok "client-2 latest GUID matches" || bad "client-2 GUID mismatch"

# ---- test 6: client-1 pushes, client-2 pulls (replica chain) ----
echo -e "${CYAN}Test 6: replica chain (c1 -> c2)${NC}"
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

# ---- summary ----
echo ""
echo -e "${GREEN}Passed: $pass${NC}  ${RED}Failed: $fail${NC}"
exit $fail

#!/bin/bash
# test/lib.sh — shared test infrastructure for Zeplicator Air
# Source this in test scripts:  source "$(dirname "$0")/lib.sh"

RED='\033[31m'; GREEN='\033[32m'; CYAN='\033[36m'; NC='\033[0m'

pass=0; fail=0
ok()  { echo -e "  ${GREEN}OK${NC}  $1"; pass=$((pass+1)); }
bad() { echo -e "  ${RED}FAIL${NC} $1"; fail=$((fail+1)); }

CRON_PIDS=()

# ── binaries ──
init_bins() {
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROJ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
    ZEP="${ZEP:-$PROJ_DIR/zep-air}"
    SERV="${SERV:-$PROJ_DIR/zep-air-serve}"
    ADMIN="${ADMIN:-$PROJ_DIR/zep-air-admin}"
    [ "${NOBUILD:-}" ] || make -C "$PROJ_DIR" -s 2>&1 || true
}

# ── temp directory ──
init_tmp() {
    local name="${1:-zep-test}"
    TMP="/tmp/$name"
    rm -rf "$TMP"
    mkdir -p "$TMP"
    PKI="$TMP/pki"
    STORE="$TMP/storage"
    SDB="$TMP/srv.db"
    mkdir -p "$PKI" "$STORE"
}

# ── PKI ──
pki_ca() {
    openssl genrsa -out "$PKI/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "$PKI/ca.key" -sha256 -days 3650 \
        -out "$PKI/ca.crt" -subj "/CN=Zep-Test-CA" 2>/dev/null
}

pki_server() {
    local fqdn="${1:-srv.zep.lan}"
    openssl genrsa -out "$PKI/server.key" 2048 2>/dev/null
    openssl req -new -key "$PKI/server.key" -out "$PKI/server.csr" \
        -subj "/CN=$fqdn" 2>/dev/null
    cat > "$PKI/server.ext" << 'XEOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
XEOF
    openssl x509 -req -in "$PKI/server.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
        -CAcreateserial -out "$PKI/server.crt" -days 365 -sha256 \
        -extfile "$PKI/server.ext" 2>/dev/null
    chmod 644 "$PKI/server.key"
}

pki_nodes() {
    for cn in "$@"; do
        openssl genrsa -out "$PKI/$cn.key" 2048 2>/dev/null
        openssl req -new -key "$PKI/$cn.key" -out "$PKI/$cn.csr" \
            -subj "/CN=$cn" 2>/dev/null
        openssl x509 -req -in "$PKI/$cn.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
            -CAcreateserial -out "$PKI/$cn.crt" -days 365 -sha256 2>/dev/null
        chmod 644 "$PKI/$cn.key"
    done
}

# ── /etc/hosts ──
hosts_add() {
    for fqdn in "$@"; do
        grep -q "$fqdn" /etc/hosts || echo "127.0.1.1 $fqdn" | sudo tee -a /etc/hosts >/dev/null
    done
}

hosts_del() {
    for fqdn in "$@"; do sudo sed -i "/$fqdn/d" /etc/hosts 2>/dev/null || true; done
}

# ── server ──
server_setup() {
    "$SERV" --setup --cert "$PKI/server.crt" --key "$PKI/server.key" \
        --ca "$PKI/ca.crt" --admin-cert "$PKI/admin.crt" --db "$SDB" 2>/dev/null
}

server_start() {
    local port="${1:-18443}"
    local extra="${2:-}"
    if [ "${SERV_VERBOSE:-}" ]; then
        "$SERV" --verbose $extra --port "$port" --cert "$PKI/server.crt" \
            --key "$PKI/server.key" --ca "$PKI/ca.crt" --db "$SDB" \
            --storage "$STORE" &
    else
        "$SERV" $extra --port "$port" --cert "$PKI/server.crt" \
            --key "$PKI/server.key" --ca "$PKI/ca.crt" --db "$SDB" \
            --storage "$STORE" 2>/dev/null &
    fi
    SERV_PID=$!
    sleep 2
    if ! kill -0 $SERV_PID 2>/dev/null; then
        echo "Server failed to start"; exit 1
    fi
}

server_stop() {
    kill $SERV_PID 2>/dev/null
    timeout 10s bash -c "wait $SERV_PID" 2>/dev/null || true
}

# ── admin base URL string ──
admin_base() {
    local url="${1:-https://srv.zep.lan:18443}"
    ADMIN_CERT="${2:-$PKI/admin.crt}"
    ADMIN_KEY="${3:-$PKI/admin.key}"
    ADMIN_CA="${4:-$PKI/ca.crt}"
    ADMIN_BASE="--server $url --cert $ADMIN_CERT --key $ADMIN_KEY --ca $ADMIN_CA"
}

# ── node registration ──
node_join() {
    local role="$1" node="$2" cert_path="${3:-}" cluster="${4:-}" mapping="${5:-}"
    [ -n "$cert_path" ] || cert_path="$PKI/$node.crt"
    local args="--role $role --node $node --cert $cert_path"
    [ -n "$cluster" ] && args="$args --cluster $cluster"
    [ -n "$mapping" ] && args="$args --map $mapping"
    "$ADMIN" $ADMIN_BASE join $args >/dev/null
}

node_config() {
    local db="$1" node="$2" server_url="$3" cert_path="$4" key_path="${5:-$cert_path}"
    rm -f "$db"
    "$ZEP" --db "$db" config set node_name "$node"
    "$ZEP" --db "$db" config set server_url "$server_url"
    "$ZEP" --db "$db" config set cert_path "$cert_path"
    [ -n "$key_path" ] && "$ZEP" --db "$db" config set key_path "$key_path"
    "$ZEP" --db "$db" config set ca_path "$PKI/ca.crt"
}

node_config_set() {
    local db="$1" key="$2" val="$3"
    "$ZEP" --db "$db" config set "$key" "$val"
}

# ── cron daemon ──
cron_spawn() {
    local db="$1" interval="${2:-2}"
    "$ZEP" --db "$db" cron --daemon --interval "$interval" 2>/dev/null &
    CRON_PIDS+=($!)
    sleep 2
}

cron_kill_all() {
    for pid in "${CRON_PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    for pid in "${CRON_PIDS[@]:-}"; do
        timeout 10s bash -c "wait $pid" 2>/dev/null || true
    done
    CRON_PIDS=()
}

# ── pipe_allow ──
pipe_allow() {
    "$ADMIN" $ADMIN_BASE config set pipe_allow "$1" >/dev/null
}

# ── pipe_allow_tools ──
pipe_allow_tools() {
    "$ADMIN" $ADMIN_BASE config set pipe_allow_tools "$1" >/dev/null
}

# ── cleanup ──
cleanup() {
    server_stop 2>/dev/null || true
    cron_kill_all 2>/dev/null || true
    [ -n "${TMP:-}" ] && rm -rf "$TMP" 2>/dev/null || true
}

# ── results ──
print_results() {
    echo ""
    echo -e "${GREEN}Passed: $pass${NC}  ${RED}Failed: $fail${NC}"
}

exit_on_fail() {
    print_results
    exit $fail
}

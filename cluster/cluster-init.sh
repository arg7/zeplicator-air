#!/bin/bash
# cluster/cluster-init.sh — initialize a Zeplicator Air cluster
# Usage: cluster-init.sh [--env <env-file>] [--zfs] [--no-start]
#        cluster-init.sh <cluster-name> [--zfs] [--no-start]
#
# With a cluster name: reads cluster/<name>.env
# With --env: reads the given env file
# Without either: uses cluster/cluster.env

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

###############################################################################
# 1. Load environment
###############################################################################
ENV_FILE=""
DO_ZFS=0
NO_START=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env) ENV_FILE="$2"; shift 2 ;;
        --zfs) DO_ZFS=1; shift ;;
        --no-start) NO_START=1; shift ;;
        -h|--help)
            echo "Usage: $0 [--env <file>] [--zfs] [--no-start] [<cluster-name>]"
            echo "  --zfs        Create ZFS pools (requires root, loopback sparse files)"
            echo "  --no-start   Skip starting server for node registration"
            exit 0 ;;
        *)
            if [[ -z "$ENV_FILE" ]]; then
                ENV_FILE="${PROJ_DIR}/cluster/${1}.env"
            fi
            shift ;;
    esac
done

if [[ -z "$ENV_FILE" ]]; then
    ENV_FILE="${PROJ_DIR}/cluster/cluster.env"
fi

if [[ ! -f "$ENV_FILE" ]]; then
    echo "Error: env file not found: $ENV_FILE"
    echo "Copy cluster/env.template to $ENV_FILE and edit, then re-run."
    exit 1
fi

source "$ENV_FILE"

# Derived paths
PKI_DIR="${ZEP_BASE}/pki"
SERVER_DB="${ZEP_BASE}/server.db"
SERVER_STORAGE="${ZEP_BASE}/store"
PID_DIR="${ZEP_BASE}/pids"
SERVER_URL="https://${SERVER_HOST}:${SERVER_PORT}"

# Validate required vars
require() { [[ -n "${!1:-}" ]] || { echo "Error: $1 not set in $ENV_FILE"; exit 1; }; }
require ZEP_BASE
require SERVER_HOST
require CLUSTER_NAME

ZEP="${ZEP:-${PROJ_DIR}/zep-air}"
SERV="${SERV:-${PROJ_DIR}/zep-air-serve}"
ADMIN="${ADMIN:-${PROJ_DIR}/zep-air-admin}"
SUDO_NODES="${SUDO_NODES:-0}"

run_as() {
    local user="$1"; shift
    if [[ "$SUDO_NODES" == "1" ]]; then
        sudo -u "$user" "$@"
    else
        "$@"
    fi
}

RED='\033[31m'; GREEN='\033[32m'; NC='\033[0m'
say() { echo -e "${GREEN}==>${NC} $1"; }

###############################################################################
# 2. Create directories
###############################################################################
OWNER="${SUDO_USER:-$(whoami)}"
say "Creating directories under ${ZEP_BASE} ..."
sudo mkdir -p "$PKI_DIR" "$SERVER_STORAGE" "$PID_DIR"
sudo chown -R "${OWNER}:${OWNER}" "$ZEP_BASE"
for d in "$PKI_DIR" "$SERVER_STORAGE" "$PID_DIR"; do
    mkdir -p "$d"
done

###############################################################################
# 2b. /etc/hosts
###############################################################################
say "Adding ${SERVER_HOST} to /etc/hosts ..."
grep -q "${SERVER_HOST}" /etc/hosts 2>/dev/null || \
    echo "127.0.1.1 ${SERVER_HOST}" | sudo tee -a /etc/hosts >/dev/null

###############################################################################
# 3. PKI — CA + server + admin + nodes
###############################################################################
say "Generating PKI ..."

# CA
if [[ ! -f "${PKI_DIR}/ca.crt" ]]; then
    openssl genrsa -out "${PKI_DIR}/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "${PKI_DIR}/ca.key" \
        -sha256 -days "${CA_DAYS:-3650}" -out "${PKI_DIR}/ca.crt" \
        -subj "/CN=${CA_CN:-Zep-CA}" 2>/dev/null
    chmod 644 "${PKI_DIR}/ca.key"
fi

# Server cert
if [[ ! -f "${PKI_DIR}/server.crt" ]]; then
    openssl genrsa -out "${PKI_DIR}/server.key" 2048 2>/dev/null
    openssl req -new -key "${PKI_DIR}/server.key" -out "${PKI_DIR}/server.csr" \
        -subj "/CN=${SERVER_HOST}" 2>/dev/null
    cat > "${PKI_DIR}/server.ext" << 'XEOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
XEOF
    openssl x509 -req -in "${PKI_DIR}/server.csr" \
        -CA "${PKI_DIR}/ca.crt" -CAkey "${PKI_DIR}/ca.key" \
        -CAcreateserial -out "${PKI_DIR}/server.crt" \
        -days "${NODE_DAYS:-365}" -sha256 \
        -extfile "${PKI_DIR}/server.ext" 2>/dev/null
    chmod 644 "${PKI_DIR}/server.key"
    cat "${PKI_DIR}/server.crt" "${PKI_DIR}/server.key" > "${PKI_DIR}/server.pem"
    rm -f "${PKI_DIR}/server.csr" "${PKI_DIR}/server.ext"
fi

# Admin cert
if [[ ! -f "${PKI_DIR}/admin.crt" ]]; then
    openssl genrsa -out "${PKI_DIR}/admin.key" 2048 2>/dev/null
    openssl req -new -key "${PKI_DIR}/admin.key" -out "${PKI_DIR}/admin.csr" \
        -subj "/CN=admin" 2>/dev/null
    cat > "${PKI_DIR}/admin.ext" << 'XEOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
XEOF
    openssl x509 -req -in "${PKI_DIR}/admin.csr" \
        -CA "${PKI_DIR}/ca.crt" -CAkey "${PKI_DIR}/ca.key" \
        -CAcreateserial -out "${PKI_DIR}/admin.crt" \
        -days "${NODE_DAYS:-365}" -sha256 \
        -extfile "${PKI_DIR}/admin.ext" 2>/dev/null
    chmod 644 "${PKI_DIR}/admin.key"
    cat "${PKI_DIR}/admin.crt" "${PKI_DIR}/admin.key" > "${PKI_DIR}/admin.pem"
    rm -f "${PKI_DIR}/admin.csr" "${PKI_DIR}/admin.ext"
fi

# Node certs
for entry in ${NODES:-}; do
    IFS=':' read -r cn role poolfs <<< "$entry"
    if [[ -f "${PKI_DIR}/${cn}.crt" ]]; then continue; fi
    openssl genrsa -out "${PKI_DIR}/${cn}.key" 2048 2>/dev/null
    openssl req -new -key "${PKI_DIR}/${cn}.key" -out "${PKI_DIR}/${cn}.csr" \
        -subj "/CN=${cn}" 2>/dev/null
    openssl x509 -req -in "${PKI_DIR}/${cn}.csr" \
        -CA "${PKI_DIR}/ca.crt" -CAkey "${PKI_DIR}/ca.key" \
        -CAcreateserial -out "${PKI_DIR}/${cn}.crt" \
        -days "${NODE_DAYS:-365}" -sha256 2>/dev/null
    chmod 644 "${PKI_DIR}/${cn}.key"
    cat "${PKI_DIR}/${cn}.crt" "${PKI_DIR}/${cn}.key" > "${PKI_DIR}/${cn}.pem"
    rm -f "${PKI_DIR}/${cn}.csr"
done

say "PKI ready: ${PKI_DIR}/"

###############################################################################
# 4. ZFS pools (optional, requires root)
###############################################################################
if [[ "$DO_ZFS" -eq 1 && -n "${ZFS_POOLS:-}" ]]; then
    say "Creating ZFS pools ..."
    for pool in ${ZFS_POOLS:-}; do
        if zpool list -H -o name "$pool" &>/dev/null; then
            say "  Pool '$pool' already exists — skipping"
            continue
        fi
        img="${ZEP_BASE}/${pool}.img"
        truncate -s "${ZFS_POOL_SIZE:-256M}" "$img"
        zpool create -m "${ZEP_BASE}/mnt/${pool}" "$pool" "$img"
        say "  Created pool: $pool"
    done

    # Create datasets per node
    for entry in ${NODES:-}; do
        IFS=':' read -r cn role poolfs <<< "$entry"
        pool="${poolfs%%/*}"
        ds="${poolfs#*/}"
        if zfs list -H -o name "$pool/$ds" &>/dev/null 2>&1; then continue; fi
        zfs create -o mountpoint=none "$pool/$ds"
        say "  Created dataset: $pool/$ds"
    done

    say "Creating node user accounts and ZFS permissions ..."
    for entry in ${NODES:-}; do
        IFS=':' read -r cn role poolfs <<< "$entry"
        pool="${poolfs%%/*}"
        id "$cn" &>/dev/null || {
            useradd -r -s /bin/bash -d "${ZEP_BASE}/home/${cn}" -m "$cn" 2>/dev/null
            say "  Created user: $cn"
        }
        zfs allow -u "$cn" clone,create,destroy,mount,promote,receive,rollback,send,snapshot "$pool" 2>/dev/null || true
        img="${ZEP_BASE}/${pool}.img"
        [[ -f "$img" ]] && chown "${cn}:${cn}" "$img" 2>/dev/null || true
    done
fi

###############################################################################
# 5. Server setup
###############################################################################
say "Server DB setup ..."
rm -f "$SERVER_DB"
sudo "$SERV" --setup \
    --cert "${PKI_DIR}/server.crt" --key "${PKI_DIR}/server.key" \
    --ca "${PKI_DIR}/ca.crt" --admin-cert "${PKI_DIR}/admin.crt" \
    --db "$SERVER_DB" 2>/dev/null
sudo chown "${OWNER}:${OWNER}" "$SERVER_DB"

###############################################################################
# 6. Server-side config (start temporarily, configure, then stop)
###############################################################################
if [[ "$NO_START" -eq 1 ]]; then
    say "Skipping server start (--no-start). Register nodes and set config manually:"
    echo "  Server: $SERV --port $SERVER_PORT --cert ${PKI_DIR}/server.crt --key ${PKI_DIR}/server.key --ca ${PKI_DIR}/ca.crt --db $SERVER_DB --storage $SERVER_STORAGE"
    echo "  Admin base: $ADMIN --server $SERVER_URL --cert ${PKI_DIR}/admin.crt --key ${PKI_DIR}/admin.key --ca ${PKI_DIR}/ca.crt"
else
    say "Starting server temporarily for node registration ..."
    "$SERV" --port "$SERVER_PORT" \
        --cert "${PKI_DIR}/server.crt" --key "${PKI_DIR}/server.key" \
        --ca "${PKI_DIR}/ca.crt" --db "$SERVER_DB" \
        --storage "$SERVER_STORAGE" 2>/dev/null &
    SERV_PID=$!
    sleep 2
    if ! kill -0 "$SERV_PID" 2>/dev/null; then
        echo -e "${RED}Error: server failed to start${NC}"
        exit 1
    fi

    ADMIN_BASE="--server $SERVER_URL --cert ${PKI_DIR}/admin.crt --key ${PKI_DIR}/admin.key --ca ${PKI_DIR}/ca.crt"

    # Cluster definition
    say "Setting cluster definition ..."
    cat > /tmp/zep-cluster-$$.json << JSONEOF
{"name":"${CLUSTER_NAME}","pools":{"${CLUSTER_POOL:-za-pool-1}":{"${CLUSTER_FS:-za-data-1}":{"labels":${CLUSTER_LABELS:-"{\"hourly\":60}"}}}}}
JSONEOF
    "$ADMIN" $ADMIN_BASE cluster set --file /tmp/zep-cluster-$$.json >/dev/null
    rm -f /tmp/zep-cluster-$$.json

    # pipe_allow
    say "Configuring pipe_allow ..."
    [[ -z "${PIPE_ALLOW:-}" ]] || "$ADMIN" $ADMIN_BASE config set pipe_allow "$PIPE_ALLOW" >/dev/null
    [[ -z "${PIPE_ALLOW_TOOLS:-}" ]] || "$ADMIN" $ADMIN_BASE config set pipe_allow_tools "$PIPE_ALLOW_TOOLS" >/dev/null

    # Register nodes
    for entry in ${NODES:-}; do
        IFS=':' read -r cn role poolfs <<< "$entry"
        say "Registering node $cn (role=$role) ..."
        "$ADMIN" $ADMIN_BASE join \
            --role "$role" --node "$cn" \
            --cert "${PKI_DIR}/${cn}.crt" \
            --cluster "$CLUSTER_NAME" \
            --map "${CLUSTER_POOL:-za-pool-1}/${CLUSTER_FS:-za-data-1}:${poolfs}" >/dev/null
    done

    # Stop temp server
    kill "$SERV_PID" 2>/dev/null || true
    for i in $(seq 1 10); do
        kill -0 "$SERV_PID" 2>/dev/null || break
        sleep 1
    done
    kill -9 "$SERV_PID" 2>/dev/null || true
    say "Server stopped (temporary)."
fi

###############################################################################
# 7. Node-local DB configuration
###############################################################################
say "Configuring node databases ..."
for entry in ${NODES:-}; do
    IFS=':' read -r cn role poolfs <<< "$entry"
    node_db="${ZEP_BASE}/home/${cn}/${cn}.db"
    rm -f "$node_db"

    "$ZEP" --db "$node_db" config set node_name  "$cn"
    "$ZEP" --db "$node_db" config set server_url "$SERVER_URL"
    "$ZEP" --db "$node_db" config set cert_path  "${PKI_DIR}/${cn}.crt"
    "$ZEP" --db "$node_db" config set key_path   "${PKI_DIR}/${cn}.key"
    "$ZEP" --db "$node_db" config set ca_path    "${PKI_DIR}/ca.crt"
    "$ZEP" --db "$node_db" config set cluster    "$CLUSTER_NAME"
    "$ZEP" --db "$node_db" config set mapping    "${CLUSTER_POOL:-za-pool-1}/${CLUSTER_FS:-za-data-1}:${poolfs}"
    [[ -z "${KEY_PASSWORD:-}" ]] || "$ZEP" --db "$node_db" config set key_password "$KEY_PASSWORD"
done

say "Configuring admin database ..."
admin_db="${ZEP_BASE}/admin.db"
rm -f "$admin_db"
"$ZEP" --db "$admin_db" config set server_url   "$SERVER_URL"
"$ZEP" --db "$admin_db" config set cert_path     "${PKI_DIR}/admin.crt"
"$ZEP" --db "$admin_db" config set key_path      "${PKI_DIR}/admin.key"
"$ZEP" --db "$admin_db" config set ca_path       "${PKI_DIR}/ca.crt"
[[ -z "${KEY_PASSWORD:-}" ]] || "$ZEP" --db "$admin_db" config set key_password "$KEY_PASSWORD"

###############################################################################
# 8. Generate cluster.env for cluster-ctl.sh / cluster-destroy.sh
###############################################################################
ctl_env="${ENV_FILE}"
if [[ "$ctl_env" != *"/cluster.env" ]] && [[ "$ctl_env" != *"/cluster/cluster.env" ]]; then
    cp "$ENV_FILE" "${PROJ_DIR}/cluster/cluster.env" 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}=== Cluster '${CLUSTER_NAME}' initialized ===${NC}"
echo ""
echo "  Configuration: $ENV_FILE"
echo "  PKI:           ${PKI_DIR}/"
echo "  Server DB:     ${SERVER_DB}"
echo "  Storage:       ${SERVER_STORAGE}"
echo "  Node DBs:      ${ZEP_BASE}/home/<cn>/<cn>.db"
echo "  Admin DB:      ${admin_db}"
echo ""
echo "Next steps:"
echo "  cluster-ctl.sh start              # launch server + nodes"
echo "  cluster-ctl.sh stop               # stop all daemons"
echo "  cluster-destroy.sh                # teardown everything"
echo ""
echo "Admin commands (no manual --cert/--ca needed):"
echo "  zep-air-admin --db $admin_db config list"

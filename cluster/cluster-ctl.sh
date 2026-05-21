#!/bin/bash
# cluster/cluster-ctl.sh — start/stop/restart server + node daemons
# Usage: cluster-ctl.sh [--env <file>] start|stop|restart|status
#        cluster-ctl.sh <cluster-name> start|stop|restart|status

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
PROJ_DIR="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"

###############################################################################
# 1. Load environment
###############################################################################
ENV_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env) ENV_FILE="$2"; shift 2 ;;
        start|stop|restart|status) break ;;
        -h|--help)
            echo "Usage: $0 [--env <file>] start|stop|restart|status [<cluster-name>]"
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
    if [[ -f "${PROJ_DIR}/cluster/cluster.env" ]]; then
        echo "  (no ${ENV_FILE}, using cluster/cluster.env)"
        ENV_FILE="${PROJ_DIR}/cluster/cluster.env"
    else
        echo "Error: env file not found: $ENV_FILE"
        exit 1
    fi
fi

ACTION="${1:-status}"

source "$ENV_FILE"

ZEP_BASE="${ZEP_BASE:-/var/lib/zep-air}"
SERVER_PORT="${SERVER_PORT:-8443}"
SERVER_HOST="${SERVER_HOST:-master.zep.lan}"
PID_DIR="${ZEP_BASE}/pids"
SERVER_PIDFILE="${PID_DIR}/server.pid"
CRON_PIDFILE="${PID_DIR}/crons.pid"

SERVER_START_TIMEOUT="${SERVER_START_TIMEOUT:-15}"
NODE_START_TIMEOUT="${NODE_START_TIMEOUT:-10}"

wait_for_running() {
    local pid="$1" timeout="$2" label="$3"
    local waited=0
    while [[ "$waited" -lt "$timeout" ]]; do
        if is_running "$pid" 2>/dev/null; then return 0; fi
        sleep 1
        waited=$((waited + 1))
    done
    echo -e "  ${YELLOW}${label} (PID $pid) did not start within ${timeout}s — continuing${NC}" >&2
    return 1
}

PKI_DIR="${ZEP_BASE}/pki"
SERVER_DB="${ZEP_BASE}/server.db"
SERVER_STORAGE="${ZEP_BASE}/store"
SERVER_URL="https://${SERVER_HOST}:${SERVER_PORT}"

BIN_DIR="/usr/local/bin"
ZEP="${ZEP:-$BIN_DIR/zep-air}"
SERV="${SERV:-$BIN_DIR/zep-air-serve}"
ADMIN="${ADMIN:-$BIN_DIR/zep-air-admin}"
CRON_INTERVAL="${CRON_INTERVAL:-60}"
START_CLIENTS="${START_CLIENTS:-1}"
SUDO_NODES="${SUDO_NODES:-0}"
VERB="${VERB:-}"
KEY_PASSWORD="${KEY_PASSWORD:-}"

run_as() {
    local user="$1"; shift
    if [[ "$SUDO_NODES" == "1" ]]; then
        sudo -u "$user" "$@"
    else
        "$@"
    fi
}

mkdir -p "$PID_DIR" 2>/dev/null || {
    OWNER="${SUDO_USER:-$(whoami)}"
    sudo chown "${OWNER}:${OWNER}" "$PID_DIR" 2>/dev/null || true
    mkdir -p "$PID_DIR"
}

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; NC='\033[0m'
say() { echo -e "${GREEN}==>${NC} $1"; }

###############################################################################
# 2. Helper functions
###############################################################################
is_running() {
    local pid="$1"
    kill -0 "$pid" 2>/dev/null
}

server_pid() {
    if [[ -f "$SERVER_PIDFILE" ]]; then
        cat "$SERVER_PIDFILE"
    else
        pgrep -f "zep-air-serve.*${SERVER_DB}" 2>/dev/null | grep -v "pgrep" | head -1 || true
    fi
}

cron_pids() {
    if [[ -f "$CRON_PIDFILE" ]]; then
        cat "$CRON_PIDFILE" || true
    fi
}

###############################################################################
# 3. Status
###############################################################################
do_status() {
    echo "Cluster: ${CLUSTER_NAME:-unknown}"
    echo "  Env:   $ENV_FILE"
    echo "  Base:  $ZEP_BASE"
    echo "  Port:  $SERVER_PORT"
    echo ""

    local spid
    spid=$(server_pid)
    if [[ -n "$spid" ]] >/dev/null 2>&1 && is_running "$spid"; then
        echo -e "  Server: ${GREEN}running${NC} (PID $spid)"
    else
        echo -e "  Server: ${RED}stopped${NC}"
    fi

    for pid in $(cron_pids); do
        if is_running "$pid"; then
            echo -e "  Cron:   ${GREEN}running${NC} (PID $pid)"
        else
            echo -e "  Cron:   ${YELLOW}stale pid file entry: $pid${NC}"
        fi
    done

    if [[ -z "$(cron_pids)" ]]; then
        echo -e "  Nodes:  ${RED}no cron daemons running${NC}"
    fi
}

###############################################################################
# 4. Start
###############################################################################
do_start() {
    #rm -f /tmp/zep-server.log /tmp/zep-*.log 2>/dev/null || true

    local spid
    spid=$(server_pid)
    if is_running "${spid:-}" 2>/dev/null; then
        echo -e "${YELLOW}Server already running (PID $spid)${NC}"
    else
        say "Starting server on port $SERVER_PORT ..."
        if [[ -n "$VERB" ]]; then
            "$SERV" --logging DEBUG,INFO,WARN,ERROR,AUDIT --port "$SERVER_PORT" \
                --cert "${PKI_DIR}/server.crt" --key "${PKI_DIR}/server.key" \
                --ca "${PKI_DIR}/ca.crt" --db "$SERVER_DB" \
                --storage "$SERVER_STORAGE" ${KEY_PASSWORD:+-P "${KEY_PASSWORD}"} >/tmp/zep-server.log 2>&1 &
        else
            "$SERV" --port "$SERVER_PORT" \
                --cert "${PKI_DIR}/server.crt" --key "${PKI_DIR}/server.key" \
                --ca "${PKI_DIR}/ca.crt" --db "$SERVER_DB" \
                --storage "$SERVER_STORAGE" ${KEY_PASSWORD:+-P "${KEY_PASSWORD}"} >/tmp/zep-server.log 2>&1 &
        fi
        local new_pid=$!
        wait_for_running "$new_pid" "$SERVER_START_TIMEOUT" "Server" || true
        if is_running "$new_pid"; then
            echo "$new_pid" > "$SERVER_PIDFILE"
            echo -e "  Server started (PID $new_pid)"
        else
            echo -e "${RED}Server failed to start${NC}"
            exit 1
        fi
    fi

     say "Starting node cron daemons (interval=${CRON_INTERVAL}s) ..."
     local cron_pids_file_content=""
     for entry in ${NODES:-}; do
         IFS=':' read -r cn role poolfs <<< "$entry"
         if [[ "$START_CLIENTS" == "0" && "$role" == "client" ]]; then
             echo -e "  ${YELLOW}$cn ($role) — skipped (START_CLIENTS=0)${NC}"
             continue
         fi
        local node_db="${ZEP_BASE}/home/${cn}/${cn}.db"
        if [[ "$SUDO_NODES" == "1" ]]; then
            sudo -u "$cn" test -f "$node_db" || {
                echo -e "  ${YELLOW}No DB for $cn ($node_db) — skipping${NC}"
                continue
            }
            if [[ -n "$VERB" ]]; then
                nohup sudo -u "$cn" sh -c "\"$ZEP\" --logging DEBUG,INFO,WARN,ERROR,AUDIT --db \"$node_db\" cron --daemon --interval \"$CRON_INTERVAL\" > /tmp/zep-${cn}.log 2>&1" </dev/null >/dev/null 2>&1 &
            else
                nohup sudo -u "$cn" sh -c "\"$ZEP\" --db \"$node_db\" cron --daemon --interval \"$CRON_INTERVAL\" > /tmp/zep-${cn}.log 2>&1" </dev/null >/dev/null 2>&1 &
            fi
        else
            [[ -f "$node_db" ]] || {
                echo -e "  ${YELLOW}No DB for $cn ($node_db) — skipping${NC}"
                continue
            }
            if [[ -n "$VERB" ]]; then
                nohup "$ZEP" --logging DEBUG,INFO,WARN,ERROR,AUDIT --db "$node_db" cron --daemon --interval "$CRON_INTERVAL" </dev/null >/tmp/zep-${cn}.log 2>&1 &
            else
                nohup "$ZEP" --db "$node_db" cron --daemon --interval "$CRON_INTERVAL" </dev/null >/tmp/zep-${cn}.log 2>&1 &
            fi
        fi
        local cpid=$!
        disown $cpid 2>/dev/null || true
        cron_pids_file_content="${cron_pids_file_content}${cpid}\n"
        echo -e "  $cn started (PID $cpid)"
    done
    echo -ne "$cron_pids_file_content" > "$CRON_PIDFILE"
}

###############################################################################
# 5. Stop
###############################################################################
do_stop() {
    # Stop cron daemons first
    say "Stopping cron daemons ..."
    local stopped=0
    for pid in $(cron_pids); do
        if is_running "$pid"; then
            kill "$pid" 2>/dev/null || true
            stopped=$((stopped + 1))
        fi
    done
    # Wait for them to exit
    for i in $(seq 1 10); do
        local alive=0
        for pid in $(cron_pids); do is_running "$pid" 2>/dev/null >/dev/null 2>&1 && alive=$((alive + 1)); done
        [[ "$alive" -eq 0 ]] >/dev/null 2>&1 && break
        sleep 1
    done
    # Force kill stragglers
    for pid in $(cron_pids); do kill -9 "$pid" 2>/dev/null || true; done
    rm -f "$CRON_PIDFILE"
    echo "  ${stopped} cron daemon(s) stopped"

    # Stop server
    say "Stopping server ..."
    local spid
    spid=$(server_pid)
    if is_running "${spid:-}" 2>/dev/null; then
        kill "$spid" 2>/dev/null || true
        for i in $(seq 1 10); do
            is_running "$spid" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$spid" 2>/dev/null || true
        echo "  Server stopped (was PID $spid)"
    else
        echo "  Server not running"
    fi
    rm -f "$SERVER_PIDFILE"
}

do_restart() {
    do_stop
    sleep 2
    do_start
}

###############################################################################
# Dispatch
###############################################################################
case "$ACTION" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_restart ;;
    status)  do_status ;;
    *)       echo "Usage: $0 [--env <file>] start|stop|restart|status"; exit 1 ;;
esac

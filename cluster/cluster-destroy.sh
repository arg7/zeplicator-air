#!/bin/bash
# cluster/cluster-destroy.sh — stop all processes and unwind cluster setup
# Usage: cluster-destroy.sh [--env <file>] [--force] [--keep-pools]
#        cluster-destroy.sh <cluster-name> [--force] [--keep-pools]
#
# Without --force: prompts for confirmation before destructive actions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

###############################################################################
# 1. Load environment
###############################################################################
ENV_FILE=""
FORCE=0
KEEP_POOLS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env) ENV_FILE="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --keep-pools) KEEP_POOLS=1; shift ;;
        -h|--help)
            echo "Usage: $0 [--env <file>] [--force] [--keep-pools] [<cluster-name>]"
            echo "  --force       Skip confirmation prompts"
            echo "  --keep-pools  Do not destroy ZFS pools"
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

source "$ENV_FILE"

ZEP_BASE="${ZEP_BASE:-/var/lib/zep-air}"
CLUSTER_NAME="${CLUSTER_NAME:-unknown}"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; NC='\033[0m'
say() { echo -e "${GREEN}==>${NC} $1"; }
warn() { echo -e "${YELLOW}==>${NC} $1"; }

###############################################################################
# 2. Confirmation
###############################################################################
echo ""
warn "This will destroy cluster '${CLUSTER_NAME}'"
echo ""
echo "  Data directory: ${ZEP_BASE}"
echo "  ZFS pools:      ${ZFS_POOLS:-none}"
echo "  Nodes:          ${NODES:-none}"
echo ""

if [[ "$FORCE" -ne 1 ]]; then
    read -p "Type 'yes' to confirm: " ans
    if [[ "$ans" != "yes" ]]; then
        echo "Aborted."
        exit 0
    fi
fi

###############################################################################
# 3. Stop all daemons
###############################################################################
CTL_SCRIPT="${PROJ_DIR}/cluster/cluster-ctl.sh"
if [[ -x "$CTL_SCRIPT" ]]; then
    say "Stopping all daemons via cluster-ctl.sh ..."
    "$CTL_SCRIPT" --env "$ENV_FILE" stop 2>/dev/null || true
else
    say "Stopping processes ..."
    pkill -f "zep-air-serve.*${ZEP_BASE}" 2>/dev/null || true
    pkill -f "zep-air.*cron.*${ZEP_BASE}" 2>/dev/null || true
    sleep 2
    pkill -9 -f "zep-air-serve.*${ZEP_BASE}" 2>/dev/null || true
    pkill -9 -f "zep-air.*cron.*${ZEP_BASE}" 2>/dev/null || true
fi

###############################################################################
# 4. Destroy ZFS pools
###############################################################################
if [[ "$KEEP_POOLS" -ne 1 && -n "${ZFS_POOLS:-}" ]]; then
    say "Destroying ZFS pools ..."
    for pool in ${ZFS_POOLS:-}; do
        if zpool list -H -o name "$pool" &>/dev/null 2>&1; then
            zfs unmount -f "$pool" 2>/dev/null || true
            for ds in $(zfs list -H -o name -r "$pool" 2>/dev/null | tac); do
                zfs destroy -f "$ds" 2>/dev/null || true
            done
            sleep 1
            zpool destroy -f "$pool" 2>/dev/null || warn "Could not destroy pool $pool"
            say "  Destroyed pool: $pool"
        fi
    done
    for pool in ${ZFS_POOLS:-}; do
        img="${ZEP_BASE}/${pool}.img"
        rm -f "$img"
    done
fi

###############################################################################
# 5. Remove data directory
###############################################################################
if [[ -d "$ZEP_BASE" ]]; then
    say "Removing ${ZEP_BASE} ..."
    rm -rf "$ZEP_BASE"
fi

###############################################################################
# 6. Remove hosts entries
###############################################################################
if [[ -n "${SERVER_HOST:-}" ]]; then
    say "Removing /etc/hosts entry for ${SERVER_HOST} ..."
    sudo sed -i "/${SERVER_HOST}/d" /etc/hosts 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}=== Cluster '${CLUSTER_NAME}' destroyed ===${NC}"

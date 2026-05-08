#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

PORT=18455
FQDN=srv

init_bins
init_tmp zep-pipe-dbg
SERV_VERBOSE=1

pki_ca
pki_server "$FQDN"
pki_nodes "$FQDN" admin n1
cp "$PKI/$FQDN.crt" "$PKI/server.crt"
cp "$PKI/$FQDN.key" "$PKI/server.key"
hosts_add "$FQDN"

server_setup

"$SERV" --verbose --port "$PORT" --cert "$PKI/server.crt" \
    --key "$PKI/server.key" --ca "$PKI/ca.crt" --db "$SDB" \
    --storage "$STORE" >"$TMP/srv.out" 2>"$TMP/srv.err" &
SERV_PID=$!
sleep 2

admin_base "https://$FQDN:$PORT"
node_join client n1
pipe_allow "zfs,dd"

NDB="$TMP/node/z.db"
mkdir -p "$(dirname "$NDB")"
node_config "$NDB" n1 "https://$FQDN:$PORT" "$PKI/n1.crt" "$PKI/n1.key"

cron_spawn "$NDB" 1

echo "=== PIPE ==="
timeout 10s "$ADMIN" $ADMIN_BASE pipe dd if=/dev/urandom bs=1M count=20 >"$TMP/out" 2>"$TMP/err" || true
echo "stdout: $(wc -c < "$TMP/out") bytes"
echo "stderr:"
cat "$TMP/err"
echo "--- server err ---"
grep pipe_done "$TMP/srv.err" 2>/dev/null || echo "(no pipe_done)"
echo "--- server log tail ---"
tail -5 "$TMP/srv.err"

cleanup
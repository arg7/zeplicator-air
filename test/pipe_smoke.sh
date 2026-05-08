#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

PORT=18449
FQDN=bench.zep.lan

init_bins
init_tmp zep-pipe-test

pki_ca
pki_server "$FQDN"
pki_nodes "$FQDN" admin benchie
cp "$PKI/$FQDN.crt" "$PKI/server.crt"
cp "$PKI/$FQDN.key" "$PKI/server.key"
hosts_add "$FQDN"

server_setup
server_start "$PORT"

admin_base "https://$FQDN:$PORT"
node_join client benchie
pipe_allow "zfs,dd"

NDB="$TMP/node/z.db"
mkdir -p "$(dirname "$NDB")"
node_config "$NDB" benchie "https://$FQDN:$PORT" "$PKI/benchie.crt" "$PKI/benchie.key"

cron_spawn "$NDB" 1

echo "=== PIPE 4KB ==="
timeout 10s "$ADMIN" $ADMIN_BASE pipe dd if=/dev/urandom bs=1K count=4 >"$TMP/out" 2>"$TMP/err" || true
echo "stdout: $(wc -c < "$TMP/out") bytes"
echo "stderr:"
cat "$TMP/err"
echo "---"
echo "PIPE benched!"

cleanup
#!/bin/bash
# Create CA, server cert, and admin cert for Zeplicator Air
set -eu

CA_SUBJ="${1:-/C=IT/O=CompEd/CN=Zep-Air testing}"
VALIDITY="${2:-3650}"
SERVER_FQDN="${3:-master.zep.lan}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Zeplicator Air PKI setup ==="
echo "  CA subject : $CA_SUBJ"
echo "  Validity   : $VALIDITY days"
echo "  Server FQDN: $SERVER_FQDN"
echo ""

# --- extract O= and C= from CA subject for server/admin certs ---
CA_O="$(echo "$CA_SUBJ" | sed -n 's/.*O=\([^,/]*\).*/\1/p')"
CA_C="$(echo "$CA_SUBJ" | sed -n 's/.*C=\([^,/]*\).*/\1/p')"
[[ -z "$CA_O" ]] && CA_O="CompEd"
[[ -z "$CA_C" ]] && CA_C="IT"

# --- CA ---
echo "→ Creating CA key and certificate..."
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$VALIDITY" \
    -out ca.crt -subj "$CA_SUBJ" 2>/dev/null
echo "  CA: $(openssl x509 -in ca.crt -noout -fingerprint -sha256 | sed 's/.*=//')"

# --- Server ---
echo "→ Creating server key and certificate (CN=$SERVER_FQDN)..."
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -out server.csr \
    -subj "/C=${CA_C}/O=${CA_O}/CN=${SERVER_FQDN}" 2>/dev/null
cat > server.ext << 'XEOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
XEOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days "$VALIDITY" -sha256 \
    -extfile server.ext 2>/dev/null
rm -f server.csr server.ext
echo "  Server: $(openssl x509 -in server.crt -noout -fingerprint -sha256 | sed 's/.*=//')"

# --- Admin ---
echo "→ Creating admin key and certificate (CN=admin)..."
openssl genrsa -out admin.key 2048 2>/dev/null
openssl req -new -key admin.key -out admin.csr \
    -subj "/C=${CA_C}/O=${CA_O}/CN=admin" 2>/dev/null
cat > admin.ext << 'XEOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
XEOF
openssl x509 -req -in admin.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out admin.crt -days "$VALIDITY" -sha256 \
    -extfile admin.ext 2>/dev/null
rm -f admin.csr admin.ext
echo "  Admin: $(openssl x509 -in admin.crt -noout -fingerprint -sha256 | sed 's/.*=//')"

# --- Permissions ---
chmod 600 *.key
chmod 644 *.crt

echo ""
echo "=== Done ==="
echo "  CA:        ca.crt  ca.key"
echo "  Server:    server.crt  server.key  (CN=$SERVER_FQDN)"
echo "  Admin:     admin.crt  admin.key   (CN=admin)"
echo ""
echo "Next: ./mk-node.sh <CN> [validity_days]"

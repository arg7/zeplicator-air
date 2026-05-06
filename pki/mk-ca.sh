#!/bin/bash
# Create CA, server cert, and admin cert for Zeplicator Air
set -eu

CA_SUBJ="${1:-/C=IT/O=CompEd/CN=Zep-Air testing}"
VALIDITY="${2:-3650}"
SERVER_FQDN="${3:-master.zep.lan}"
ENCRYPT=""

usage() {
    cat << EOF
Usage: $0 [subject] [validity_days] [server_fqdn] [-p]

  subject        CA subject DN (default: /C=IT/O=CompEd/CN=Zep-Air testing)
  validity_days  Certificate lifetime in days (default: 3650)
  server_fqdn    Server CN for TLS (default: master.zep.lan)
  -p             Password-encrypt private keys (AES-256)

Output:
  ca.crt / ca.key / ca.pem
  server.crt / server.key / server.pem
  admin.crt / admin.key / admin.pem
  Each .pem = cert + key concatenated.
EOF
}

for arg in "$@"; do
    [[ "$arg" == "-p" ]] && ENCRYPT="-p"
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Zeplicator Air PKI setup ==="
echo "  CA subject : $CA_SUBJ"
echo "  Validity   : $VALIDITY days"
echo "  Server FQDN: $SERVER_FQDN"
[[ -n "$ENCRYPT" ]] && echo "  Keys       : AES-256 encrypted"
echo ""

CA_O="$(echo "$CA_SUBJ" | sed -n 's/.*O=\([^,/]*\).*/\1/p')"
CA_C="$(echo "$CA_SUBJ" | sed -n 's/.*C=\([^,/]*\).*/\1/p')"
[[ -z "$CA_O" ]] && CA_O="CompEd"
[[ -z "$CA_C" ]] && CA_C="IT"

encrypt_key() {
    local key="$1"
    if [[ -n "$ENCRYPT" ]]; then
        openssl rsa -aes256 -in "$key" -out "${key}.tmp" 2>/dev/null
        mv "${key}.tmp" "$key"
    fi
}

bundle() {
    local name="$1"
    cat "${name}.crt" "${name}.key" > "${name}.pem"
    chmod 600 "${name}.pem"
}

# --- CA ---
echo "→ Creating CA key and certificate..."
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$VALIDITY" \
    -out ca.crt -subj "$CA_SUBJ" 2>/dev/null
encrypt_key ca.key
bundle ca
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
encrypt_key server.key
bundle server
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
encrypt_key admin.key
bundle admin
echo "  Admin: $(openssl x509 -in admin.crt -noout -fingerprint -sha256 | sed 's/.*=//')"

chmod 644 *.crt
chmod 600 *.key *.pem

echo ""
echo "=== Done ==="
echo "  ca.crt        CA certificate (public)"
echo "  server.pem    Server cert + key (use with zep-air-serve)"
echo "  admin.pem     Admin cert + key (use with zep-air-admin)"
[[ -n "$ENCRYPT" ]] && echo "  Keys are AES-256 encrypted — provide password at startup."
echo ""
echo "  Distributables: ca.crt  admin.pem  server.pem"
echo "  Next: ./mk-node.sh <CN> [validity] [-p]"

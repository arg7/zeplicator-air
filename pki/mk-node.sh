#!/bin/bash
# Create a node key and certificate for Zeplicator Air
# Reads CA subject from ca.crt, replaces CN with user-provided value.
set -eu

CN="${1:-}"
VALIDITY="${2:-3650}"

if [[ -z "$CN" ]]; then
    echo "Usage: $0 <CommonName> [validity_days]"
    echo ""
    echo "  CommonName     Node FQDN or identifier (e.g. za-master, srv2.lan)"
    echo "  validity_days  Certificate lifetime in days (default: 3650)"
    echo ""
    echo "  Requires ca.crt and ca.key in the same directory."
    echo "  Subject C= and O= are inherited from the CA certificate."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f ca.crt ]] || [[ ! -f ca.key ]]; then
    echo "Error: ca.crt and ca.key not found in $SCRIPT_DIR"
    echo "Run ./mk-ca.sh first."
    exit 1
fi

# Extract O= and C= from CA cert
CA_SUBJ="$(openssl x509 -in ca.crt -noout -subject | sed 's/subject=//')"
CA_O="$(echo "$CA_SUBJ" | sed -n 's/.*O *= *\([^,/]*\).*/\1/p')"
CA_C="$(echo "$CA_SUBJ" | sed -n 's/.*C *= *\([^,/]*\).*/\1/p')"
[[ -z "$CA_O" ]] && CA_O="CompEd"
[[ -z "$CA_C" ]] && CA_C="IT"

NODE_SUBJ="/C=${CA_C}/O=${CA_O}/CN=${CN}"

echo "→ Creating node key and certificate"
echo "  CN       : $CN"
echo "  Subject  : $NODE_SUBJ"
echo "  Validity : $VALIDITY days"
echo ""

openssl genrsa -out "${CN}.key" 2048 2>/dev/null
openssl req -new -key "${CN}.key" -out "${CN}.csr" \
    -subj "$NODE_SUBJ" 2>/dev/null

cat > "${CN}.ext" << 'XEOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
XEOF

openssl x509 -req -in "${CN}.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out "${CN}.crt" -days "$VALIDITY" -sha256 \
    -extfile "${CN}.ext" 2>/dev/null

rm -f "${CN}.csr" "${CN}.ext"
chmod 600 "${CN}.key"
chmod 644 "${CN}.crt"

FP="$(openssl x509 -in "${CN}.crt" -noout -fingerprint -sha256 | sed 's/.*=//')"
echo "  Created: ${CN}.crt  ${CN}.key"
echo "  Fingerprint: $FP"
echo ""
echo "  Register with:"
echo "  zep-air-admin join --role master|client --node $CN --cert ${CN}.crt"

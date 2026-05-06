#!/bin/bash
# Create a node key and certificate for Zeplicator Air
set -eu

CN=""
VALIDITY="3650"
ENCRYPT=""

usage() {
    cat << EOF
Usage: $0 <CommonName> [validity_days] [-p]

  CommonName     Node FQDN or identifier (e.g. za-master, srv2.lan)
  validity_days  Certificate lifetime in days (default: 3650)
  -p             Password-encrypt private key (AES-256)

  Requires ca.crt and ca.key in the same directory.
  Subject C= and O= are inherited from the CA certificate.

Output:
  <CN>.crt / <CN>.key / <CN>.pem
  .pem = cert + key concatenated — copy this one file to the node.
EOF
}

for arg in "$@"; do
    if [[ "$arg" == "-p" ]]; then
        ENCRYPT="-p"
    elif [[ -z "$CN" ]]; then
        CN="$arg"
    elif [[ "$arg" != "-p" ]]; then
        VALIDITY="$arg"
    fi
done

if [[ -z "$CN" ]]; then
    usage
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f ca.crt ]] || [[ ! -f ca.key ]]; then
    echo "Error: ca.crt and ca.key not found in $SCRIPT_DIR"
    echo "Run ./mk-ca.sh first."
    exit 1
fi

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
[[ -n "$ENCRYPT" ]] && echo "  Key      : AES-256 encrypted"
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

if [[ -n "$ENCRYPT" ]]; then
    openssl rsa -aes256 -in "${CN}.key" -out "${CN}.key.tmp" 2>/dev/null
    mv "${CN}.key.tmp" "${CN}.key"
fi

cat "${CN}.crt" "${CN}.key" > "${CN}.pem"
chmod 600 "${CN}.key" "${CN}.pem"
chmod 644 "${CN}.crt"

FP="$(openssl x509 -in "${CN}.crt" -noout -fingerprint -sha256 | sed 's/.*=//')"
echo "  Created: ${CN}.crt  ${CN}.key  ${CN}.pem"
echo "  Fingerprint: $FP"
echo ""
echo "  Copy ${CN}.pem to the node."
echo "  Register with:"
echo "  zep-air-admin join --role master|client --node $CN --cert ${CN}.crt"

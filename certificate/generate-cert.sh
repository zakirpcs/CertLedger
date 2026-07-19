#!/bin/sh
set -e

CERT_DIR="/certs"
CERT="$CERT_DIR/certledger.crt"
KEY="$CERT_DIR/certledger.key"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "[certificate] TLS certificate already exists — skipping generation."
    openssl x509 -noout -subject -enddate -in "$CERT" | sed 's/^/[certificate]   /'
    exit 0
fi

echo "[certificate] Generating self-signed TLS certificate..."
mkdir -p "$CERT_DIR"

# Detect the host's primary outbound IP so the cert SAN covers LAN access
HOST_IP=$(ip route get 1.1.1.1 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')

SAN="DNS:frontend,DNS:certledger,DNS:localhost,IP:127.0.0.1"
if [ -n "$HOST_IP" ]; then
    SAN="$SAN,IP:$HOST_IP"
    echo "[certificate] Host IP $HOST_IP added to certificate SANs."
fi

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout "$KEY" \
    -out  "$CERT" \
    -subj "/C=US/ST=Local/L=Local/O=CertLedger/CN=certledger" \
    -addext "subjectAltName=$SAN" \
    2>/dev/null

echo "[certificate] Certificate generated (valid 10 years)."
echo "[certificate] SANs : $SAN"
echo "[certificate] SHA-256 fingerprint:"
openssl x509 -noout -fingerprint -sha256 -in "$CERT" \
    | sed 's/^/[certificate]   /'

#!/usr/bin/env bash
set -euo pipefail
# This script generates a quick self-signed CA and server/client certs for local testing of Envoy mTLS.
# Do NOT use in production.

DIR=$(cd "$(dirname "$0")" && pwd)
CERT_DIR=$(cd "$DIR/.." && pwd)/certs
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

DAYS=${DAYS:-365}
CN_SERVER=${CN_SERVER:-core-proxy.local}
CN_CLIENT=${CN_CLIENT:-core-webapp}

echo "[1/5] Generate CA key/cert"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" -subj "/CN=core-proxy-dev-ca" -out ca.crt

cat > server.cnf <<EOF
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[ dn ]
CN = ${CN_SERVER}
[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = ${CN_SERVER}
IP.1 = 127.0.0.1
EOF

cat > client.cnf <<EOF
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[ dn ]
CN = ${CN_CLIENT}
[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

echo "[2/5] Generate server key/csr"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config server.cnf

echo "[3/5] Sign server cert"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days "$DAYS" -sha256 -extensions v3_req -extfile server.cnf

echo "[4/5] Generate client key/csr"
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -config client.cnf

echo "[5/5] Sign client cert"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days "$DAYS" -sha256 -extensions v3_req -extfile client.cnf

rm -f server.csr client.csr server.cnf client.cnf

ls -l "$CERT_DIR"
echo "\nDone. Files: ca.crt ca.key server.crt server.key client.crt client.key"
echo "To enable mTLS: set require_client_certificate: true in envoy.yaml and point your web app gRPC client to use client.crt/client.key and trust ca.crt."

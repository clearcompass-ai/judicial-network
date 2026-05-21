#!/usr/bin/env bash
# scripts/gen-dev-certs.sh — real mutual-TLS material for local dev.
#
# Zero-trust, no backdoor: the JN composer enforces
# tls.RequireAndVerifyClientCert, and config.Validate REJECTS an empty
# auth.mode. There is NO no-auth path. This script makes the SECURE path
# the easy path for dev — it mints a real (dev) CA + a server cert + a
# client cert whose `did:` URI SAN becomes the authenticated caller DID
# (api/middleware/mtls.go), exactly like production. Same code path; the
# only "dev" thing is that the CA is local.
#
# Certs are ECDSA P-256 (works with the listener's TLS 1.3 floor). The
# secp256k1 keys the protocol cosigns with are a SEPARATE concern (witness
# fixtures / keystore) — these are transport certs only.
#
# Usage:
#   ./scripts/gen-dev-certs.sh                         # caller = did:web:state:tn:davidson
#   ./scripts/gen-dev-certs.sh did:web:state:tn:coa    # custom caller DID
#   CERT_DIR=/tmp/certs ./scripts/gen-dev-certs.sh
#
# Output (default .run/certs/, gitignored):
#   ca.crt  server.crt server.key  client.crt client.key
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${CERT_DIR:-${REPO_ROOT}/.run/certs}"
CALLER_DID="${1:-did:web:state:tn:davidson}"
DAYS="${CERT_DAYS:-365}"

command -v openssl >/dev/null 2>&1 || { echo "FATAL: openssl not on PATH" >&2; exit 1; }
case "${CALLER_DID}" in
    did:*) ;;
    *) echo "FATAL: caller must be a DID (did:...), got: ${CALLER_DID}" >&2; exit 2 ;;
esac

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

echo "== dev CA =="
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days "${DAYS}" \
    -subj "/CN=attesta-dev-ca" -out ca.crt

echo "== server cert (CN=localhost, SAN DNS:localhost,IP:127.0.0.1) =="
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=localhost" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "${DAYS}" -sha256 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n") \
    -out server.crt

echo "== client cert (caller DID in URI SAN: ${CALLER_DID}) =="
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -subj "/CN=${CALLER_DID}" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "${DAYS}" -sha256 \
    -extfile <(printf "subjectAltName=URI:%s\nextendedKeyUsage=clientAuth\n" "${CALLER_DID}") \
    -out client.crt

rm -f server.csr client.csr ca.srl

echo "== verify chain + SAN =="
openssl verify -CAfile ca.crt server.crt
openssl verify -CAfile ca.crt client.crt
echo -n "client cert URI SAN: "
openssl x509 -in client.crt -noout -ext subjectAltName | grep -o 'URI:[^,]*'

cat <<EOF

== real mTLS dev material ready (${CERT_DIR}) ==

Wire it into the JN config (auth.mode MUST be set — there is no no-auth mode):
  "auth": {
    "mode": "mtls",
    "client_ca_file": "${CERT_DIR}/ca.crt",
    "tls_cert_file":  "${CERT_DIR}/server.crt",
    "tls_key_file":   "${CERT_DIR}/server.key"
  }

Then every call must present the client cert (its did: SAN = the caller):
  curl --cacert ${CERT_DIR}/ca.crt \\
       --cert   ${CERT_DIR}/client.crt \\
       --key    ${CERT_DIR}/client.key \\
       https://localhost:<listen_port>/healthz

A request without a CA-verified client cert is rejected at the TLS
handshake (RequireAndVerifyClientCert) — before any handler runs.
EOF

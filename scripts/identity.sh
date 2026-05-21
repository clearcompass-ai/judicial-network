#!/usr/bin/env bash
# scripts/identity.sh — "Identity Infra": Step 0 for every walkthrough.
#
# Mints each actor's identity ONCE and writes a manifest the case steps
# source. An actor's identity is:
#   (a) a signing key + DID  (judicial-cli keygen)
#   (b) an mTLS client cert  (did: in the URI SAN) for JN API access,
#       issued against ONE shared dev CA.
#
# Identity model (see docs/walkthrough/00-identity-infra.md):
#   court / log       did:web:state:tn:*   compiled-in; not minted; signs tree heads
#   officers          did:pkh EOA          court-SSO embedded wallet in prod
#   external parties  did:pkh EOA          MetaMask / Coinbase / WalletConnect in prod
#
# To the JN every actor here is one method — a did:pkh EOA — verified
# pure-CPU (EIP-191 / EIP-712, did/verifier_batch.go), zero RPC, wallet-
# and chain-agnostic. Locally judicial-cli signs with the key file; in
# prod the SAME DID signs via the wallet (eth_signTypedData_v4 →
# SigAlgoEIP712). Same verification path either way.
#
# Usage:
#   ./scripts/identity.sh                 # default roster (Case 1 + reusable)
#   ACTORS="judge:pkh-eip155:1 clerk:pkh-eip155:1" ./scripts/identity.sh
#   . .run/identities/manifest.env        # load DIDs/keys/certs into a case
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"
OUT="${REPO_ROOT}/.run/identities"
CERTS="${REPO_ROOT}/.run/certs"
CLI="${REPO_ROOT}/bin/judicial-cli"
COURT_DID="${COURT_DID:-did:web:state:tn:davidson}"
DAYS="${CERT_DAYS:-365}"

# name:method:chain — chain is did:pkh metadata (verification is chain-agnostic).
ACTORS="${ACTORS:-clerk-brown:pkh-eip155:1 judge-adams:pkh-eip155:1 justice-edwards:pkh-eip155:1 cooper:pkh-eip155:1 davis:pkh-eip155:8453 acme-ceo:pkh-eip155:42161 beta-cfo:pkh-eip155:137}"

command -v openssl >/dev/null 2>&1 || { echo "FATAL: openssl not on PATH" >&2; exit 1; }
mkdir -p "${OUT}" "${CERTS}"
[ -x "${CLI}" ] || { echo "== building judicial-cli =="; go build -o "${CLI}" ./cmd/judicial-cli; }

# ── one shared dev CA + server cert (the JN listener identity) ────────
if [ ! -s "${CERTS}/ca.crt" ]; then
    echo "== shared dev CA + server cert =="
    openssl ecparam -name prime256v1 -genkey -noout -out "${CERTS}/ca.key"
    openssl req -x509 -new -key "${CERTS}/ca.key" -sha256 -days "${DAYS}" \
        -subj "/CN=attesta-dev-ca" -out "${CERTS}/ca.crt"
    openssl ecparam -name prime256v1 -genkey -noout -out "${CERTS}/server.key"
    openssl req -new -key "${CERTS}/server.key" -subj "/CN=localhost" -out "${CERTS}/server.csr"
    openssl x509 -req -in "${CERTS}/server.csr" -CA "${CERTS}/ca.crt" -CAkey "${CERTS}/ca.key" \
        -CAcreateserial -days "${DAYS}" -sha256 \
        -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n") \
        -out "${CERTS}/server.crt"
    rm -f "${CERTS}/server.csr"
fi

# did_of <keyfile> → the DID recorded in a judicial-cli key file.
# Lets re-runs REUSE an actor's existing identity (stable DIDs) instead
# of re-minting. The file is judicial-cli's own MarshalIndent JSON, so
# the "did" field is well-formed; "did_method" is NOT matched (no
# closing quote right after `did`).
did_of() {
    sed -n 's/.*"did"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -1
}

# issue_client <name> <did> → a client cert with the DID in the URI SAN.
issue_client() {
    local name="$1" did="$2"
    openssl ecparam -name prime256v1 -genkey -noout -out "${CERTS}/${name}.client.key"
    openssl req -new -key "${CERTS}/${name}.client.key" -subj "/CN=${did}" -out "${CERTS}/${name}.csr"
    openssl x509 -req -in "${CERTS}/${name}.csr" -CA "${CERTS}/ca.crt" -CAkey "${CERTS}/ca.key" \
        -CAcreateserial -days "${DAYS}" -sha256 \
        -extfile <(printf "subjectAltName=URI:%s\nextendedKeyUsage=clientAuth\n" "${did}") \
        -out "${CERTS}/${name}.client.crt" 2>/dev/null
    rm -f "${CERTS}/${name}.csr"
}

manifest="${OUT}/manifest.env"
: > "${manifest}"
echo "# Identity Infra manifest — source into any walkthrough case." >> "${manifest}"
echo "COURT_DID=${COURT_DID}" >> "${manifest}"
echo "TLS_CA=${CERTS}/ca.crt" >> "${manifest}"
echo "TLS_SERVER_CERT=${CERTS}/server.crt" >> "${manifest}"
echo "TLS_SERVER_KEY=${CERTS}/server.key" >> "${manifest}"

# Re-run-safe: an actor with an existing key file keeps its DID (and
# cert, unless missing); only absent actors are minted. So `make
# identity` is idempotent and adding an actor to ACTORS mints just that
# one — Step 0 is a STABLE base every case can re-source.
echo "== actors (mint if absent, reuse if present) =="
printf "  %-16s %-40s %s\n" "ACTOR" "DID" "KEY"
for spec in ${ACTORS}; do
    name="${spec%%:*}"; rest="${spec#*:}"; method="${rest%%:*}"; chain="${rest##*:}"
    keyfile="${OUT}/${name}.key.json"
    if [ -s "${keyfile}" ]; then
        did="$(did_of "${keyfile}")"
        [ -n "${did}" ] || { echo "FATAL: ${keyfile} exists but has no DID — delete it and re-run" >&2; exit 1; }
        [ -s "${CERTS}/${name}.client.crt" ] || issue_client "${name}" "${did}"
    else
        did="$("${CLI}" keygen --out "${keyfile}" --method "${method}" --chain-id "${chain}" 2>/dev/null | grep '^did=' | cut -d= -f2-)"
        [ -n "${did}" ] || { echo "FATAL: keygen produced no DID for ${name}" >&2; exit 1; }
        issue_client "${name}" "${did}"
    fi
    var="$(echo "${name}" | tr 'a-z-' 'A-Z_')"
    {
        echo "${var}_DID=${did}"
        echo "${var}_KEY=${keyfile}"
        echo "${var}_CERT=${CERTS}/${name}.client.crt"
        echo "${var}_CERT_KEY=${CERTS}/${name}.client.key"
    } >> "${manifest}"
    printf "  %-16s %-40s %s\n" "${name}" "${did}" "${keyfile}"
done
rm -f "${CERTS}/ca.srl"

cat <<EOF

== Identity Infra ready ==
  court / log : ${COURT_DID}   (did:web; signs tree heads)
  manifest    : ${manifest}
  signing keys: ${OUT}/<actor>.key.json
  mTLS certs  : ${CERTS}/<actor>.client.{crt,key}  (CA: ${CERTS}/ca.crt)

Use in any case (Step 0):
  . ${manifest}                       # load \$JUDGE_ADAMS_DID, \$JUDGE_ADAMS_KEY, ...
  # judge signs an order, clerk attests (judicial-cli submit, multi-signer)
  # JN verifies: ecrecover==did:pkh addr + on-log authority + cosignature policy

Same DIDs in production sign via the wallet (eth_signTypedData_v4 →
SigAlgoEIP712); verification is identical (pure-CPU, no RPC).
EOF

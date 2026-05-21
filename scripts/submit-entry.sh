#!/usr/bin/env bash
# scripts/submit-entry.sh — the COMMON action every case builds on.
#
# Signs an entry as a Step-0 manifest actor (+ optional attesters/co-signers)
# and submits it to the ledger. The judge+clerk pattern is just:
#     --signer judge-adams --attest clerk-brown
#
# Identities come from .run/identities/manifest.env (Step 0: `make identity`).
# This script is case-agnostic: a case supplies the schema + payload + roles;
# the common machinery (resolve keys → build SubmitSpec → submit) lives here.
#
# Usage:
#   ./scripts/submit-entry.sh \
#       --signer judge-adams --attest clerk-brown \
#       --schema tn-disclosure-order-v1 \
#       --destination "$COURT_DID" \
#       --payload ./order.json \
#       [--evidence did:web:state:tn:davidson:1 ...]   # cross-refs (repeatable)
#       [--endpoint http://localhost:8080] [--dry-run]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${REPO_ROOT}/.run/identities/manifest.env"
CLI="${REPO_ROOT}/bin/judicial-cli"
ENDPOINT="${LEDGER_ENDPOINT:-http://localhost:8080}"

SIGNER="" SCHEMA="" DEST="" PAYLOAD="" DRYRUN=0
ATTEST=() EVIDENCE=()
while [ $# -gt 0 ]; do
    case "$1" in
        --signer) SIGNER="$2"; shift 2 ;;
        --attest) ATTEST+=("$2"); shift 2 ;;
        --schema) SCHEMA="$2"; shift 2 ;;
        --destination) DEST="$2"; shift 2 ;;
        --payload) PAYLOAD="$2"; shift 2 ;;
        --evidence) EVIDENCE+=("$2"); shift 2 ;;
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --dry-run) DRYRUN=1; shift ;;
        *) echo "FATAL: unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -f "${MANIFEST}" ] || { echo "FATAL: no identities — run Step 0 first: make identity" >&2; exit 1; }
. "${MANIFEST}"
for req in SIGNER SCHEMA DEST PAYLOAD; do
    [ -n "${!req}" ] || { echo "FATAL: --${req,,} required" >&2; exit 2; }
done
[ -f "${PAYLOAD}" ] || { echo "FATAL: payload file not found: ${PAYLOAD}" >&2; exit 2; }
[ -x "${CLI}" ] || { echo "== building judicial-cli =="; go build -o "${CLI}" ./cmd/judicial-cli; }

# Resolve a manifest actor name → its signing key-file path (<NAME>_KEY).
key_of() {
    local var; var="$(echo "$1" | tr 'a-z-' 'A-Z_')_KEY"
    local path="${!var:-}"
    [ -n "${path}" ] || { echo "FATAL: unknown actor '$1' (not in manifest; run: make identity)" >&2; exit 1; }
    echo "${path}"
}

PRIMARY_KEY="$(key_of "${SIGNER}")"

cosigners_json="[]"
if [ "${#ATTEST[@]}" -gt 0 ]; then
    cosigners_json="["
    for a in "${ATTEST[@]}"; do cosigners_json+="\"$(key_of "$a")\","; done
    cosigners_json="${cosigners_json%,}]"
fi

evidence_json="[]"
if [ "${#EVIDENCE[@]}" -gt 0 ]; then
    evidence_json="["
    for e in "${EVIDENCE[@]}"; do
        seq="${e##*:}"; logdid="${e%:*}"
        evidence_json+="{\"log_did\":\"${logdid}\",\"sequence\":${seq}},"
    done
    evidence_json="${evidence_json%,}]"
fi

spec="$(mktemp)"
trap 'rm -f "${spec}"' EXIT
cat > "${spec}" <<JSON
{
  "schema": "${SCHEMA}",
  "destination": "${DEST}",
  "primary_signer_key": "${PRIMARY_KEY}",
  "cosigner_keys": ${cosigners_json},
  "evidence_pointers": ${evidence_json},
  "payload": $(cat "${PAYLOAD}")
}
JSON

echo "== ${SCHEMA} → ${DEST} =="
echo "   signer : ${SIGNER}  (${PRIMARY_KEY})"
[ "${#ATTEST[@]}" -gt 0 ] && echo "   attest : ${ATTEST[*]}"
[ "${#EVIDENCE[@]}" -gt 0 ] && echo "   evidence: ${EVIDENCE[*]}"

if [ "${DRYRUN}" -eq 1 ]; then
    echo "   (dry-run) SubmitSpec:"
    sed 's/^/   /' "${spec}"
    echo "   (dry-run) would run: judicial-cli submit --endpoint ${ENDPOINT} --spec <spec>"
    exit 0
fi

"${CLI}" submit --endpoint "${ENDPOINT}" --spec "${spec}"

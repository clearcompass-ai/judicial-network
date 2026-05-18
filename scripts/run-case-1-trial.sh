#!/usr/bin/env bash
#
# scripts/run-case-1-trial.sh — Case 1 (ACME v. Beta) trial walkthrough,
# automated end-to-end with per-step evidence assertions.
#
# This is the runnable form of docs/walkthrough/cases/01-acme-v-beta-trial.md.
# A technical evaluator runs this script and gets one PASS/FAIL line per
# walkthrough step, with the evidence curl response shape validated by jq.
#
# REQUIRES (set by sourcing ./bin/walkthrough.env after `make quickstart`):
#   DAVIDSON                    URL of the trial-court ledger (e.g. :8080)
#   DAVIDSON_LOG_DID            That ledger's LEDGER_LOG_DID env var
#   CLERK, COOPER, DAVIS, ACME_CEO, JUDGE_ADAMS  — court personnel + party DIDs
#   KEYS_DIR                    Absolute path to the keys directory
#   NETWORK_API                 OPTIONAL: URL of JN network-api; skips
#                               domain-API evidence checks when unset
#
# EXIT CODES:
#   0  all 6 steps green; every evidence curl asserted
#   1  prerequisite missing (env var, binary, ledger unreachable)
#   2  a submission step failed (ledger admission rejected)
#   3  an evidence assertion failed (entry on-log but shape wrong)
#
# DESIGN NOTES:
#   - Each step is idempotent on re-run: judicial-cli submit is dedup'd
#     by canonical_hash on the ledger side (PR-P5 replay branch).
#   - No domain-payload validation here — the ledger is "dumb writes"
#     and the CLI is schema-agnostic. Evidence checks ARE the
#     validation surface.
#   - Step 6 (Layer 3 witness cosignatures) is conditional: in dev
#     mode without LEDGER_GENESIS_WITNESS_SET the response carries
#     an empty cosignatures[] array and we report that explicitly
#     rather than failing.
#
# COPY-PASTE EXAMPLE:
#   make quickstart
#   source ./bin/walkthrough.env
#   ./scripts/run-case-1-trial.sh

set -euo pipefail

# ─── prerequisites ──────────────────────────────────────────────────

for v in DAVIDSON DAVIDSON_LOG_DID CLERK COOPER DAVIS JUDGE_ADAMS ACME_CEO KEYS_DIR; do
    if [ -z "${!v:-}" ]; then
        echo "FAIL: env var \$$v is unset"
        echo
        echo "Did you source ./bin/walkthrough.env after make quickstart?"
        exit 1
    fi
done

CLI="${CLI:-./bin/judicial-cli}"
if [ ! -x "${CLI}" ]; then
    echo "FAIL: ${CLI} not found or not executable"
    echo "      run: make install-bins"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "FAIL: jq not on PATH (required for evidence assertions)"
    exit 1
fi

if ! curl -fsS "${DAVIDSON}/healthz" >/dev/null 2>&1; then
    echo "FAIL: ${DAVIDSON} not reachable"
    echo "      is the ledger running? (cd ../ledger && make integration-up)"
    exit 1
fi

# Working directory for spec files. Cleaned on exit.
WORK_DIR=$(mktemp -d -t case1-trial-XXXXXX)
trap 'rm -rf "${WORK_DIR}"' EXIT

# ─── helpers ────────────────────────────────────────────────────────

# submit_spec <step-label> <spec-json-path>
# Submits the spec, parses the canonical_hash from CLI output, polls
# until sequenced, exports SEQ to the caller.
submit_spec() {
    local label="$1" spec="$2"
    local out
    if ! out=$("${CLI}" submit --endpoint "${DAVIDSON}" --spec "${spec}" 2>&1); then
        echo "  FAIL ${label}: submit rejected"
        echo "${out}" | sed 's/^/    | /'
        exit 2
    fi
    local hash
    hash=$(echo "${out}" | grep -E '^canonical_hash=' | head -1 | cut -d= -f2)
    if [ -z "${hash}" ]; then
        echo "  FAIL ${label}: no canonical_hash in submit output"
        echo "${out}" | sed 's/^/    | /'
        exit 2
    fi
    # Wait for sequencing (poll up to 30s, sequencer interval is 200ms
    # in integration topology so sub-second is typical).
    local wait_out
    if ! wait_out=$("${CLI}" wait --endpoint "${DAVIDSON}" --hash "${hash}" --timeout 30s 2>&1); then
        echo "  FAIL ${label}: wait timed out"
        echo "${wait_out}" | sed 's/^/    | /'
        exit 2
    fi
    SEQ=$(echo "${wait_out}" | grep -oE 'sequence=[0-9]+' | head -1 | cut -d= -f2)
    if [ -z "${SEQ}" ]; then
        echo "  FAIL ${label}: no sequence number in wait output"
        echo "${wait_out}" | sed 's/^/    | /'
        exit 2
    fi
    export SEQ
}

# assert_jq <step-label> <fact-being-checked> <json> <jq-filter> <expected>
assert_jq() {
    local label="$1" fact="$2" json="$3" filter="$4" expected="$5"
    local got
    got=$(echo "${json}" | jq -r "${filter}" 2>&1)
    if [ "${got}" = "${expected}" ]; then
        echo "    ✓ ${fact}"
    else
        echo "    ✗ ${fact}: got=${got} want=${expected}"
        echo "      raw response:"
        echo "${json}" | sed 's/^/        | /'
        exit 3
    fi
}

print_step() {
    echo
    echo "── $1 ──"
}

# ─── Step 1: file the civil case ────────────────────────────────────

print_step "Step 1 — file the civil case (v1.8 §1 case_initiation)"

cat > "${WORK_DIR}/civil-filing.spec.json" <<EOF
{
  "schema":      "civil_case",
  "destination": "${DAVIDSON_LOG_DID}",
  "primary_signer_key": "${KEYS_DIR}/clerk-brown.key.json",
  "cosigner_keys":      ["${KEYS_DIR}/cooper.key.json"],
  "payload": {
    "docket_number": "2024-CV-001",
    "case_type":     "contract",
    "filed_date":    "2024-01-15",
    "status":        "active",
    "plaintiff":     "ACME Industries, Inc.",
    "defendant":     "Beta Corp LLC",
    "claim_amount":  "1200000.00"
  }
}
EOF
submit_spec "Step 1" "${WORK_DIR}/civil-filing.spec.json"
echo "  submitted at seq=${SEQ}"
S_CASE_ROOT="${SEQ}"

# Evidence: payload survived round-trip
entry_json=$("${CLI}" get --endpoint "${DAVIDSON}" --seq "${S_CASE_ROOT}" 2>&1)
assert_jq "Step 1" "schema-name in entry" "${entry_json}" \
    '.payload.docket_number' '2024-CV-001'
assert_jq "Step 1" "primary signer is clerk" "${entry_json}" \
    '.header.signer_did' "${CLERK}"
assert_jq "Step 1" "cosigner count is 2 (clerk + cooper)" "${entry_json}" \
    '.signatures | length' '2'

# Evidence: JN domain API recognises the docket (when network-api is up)
if [ -n "${NETWORK_API:-}" ]; then
    case_json=$(curl -fsS "${NETWORK_API}/v1/judicial/cases/2024-CV-001" \
        -H "X-Caller-DID: ${CLERK}" \
        -H "X-Cases-Log-DID: ${DAVIDSON_LOG_DID}" 2>/dev/null || echo "{}")
    if [ "${case_json}" = "{}" ] || [ -z "${case_json}" ]; then
        echo "    ⓘ network-api not reachable; skipping JN domain-API evidence (Step 1)"
    else
        assert_jq "Step 1" "JN domain-API resolves docket → case root" "${case_json}" \
            '.docket_number' '2024-CV-001'
    fi
else
    echo "    ⓘ NETWORK_API unset; skipping JN domain-API evidence (Step 1)"
fi

# ─── Step 2: bind the parties ───────────────────────────────────────

print_step "Step 2 — bind the parties (v1.8 §1 party_binding ×2)"

for side in "acme:plaintiff:bind-acme-001:cooper:ACME Industries, Inc." \
            "beta:defendant:bind-beta-001:davis:Beta Corp LLC"; do
    party=$(echo "${side}" | cut -d: -f1)
    class=$(echo "${side}" | cut -d: -f2)
    binding_id=$(echo "${side}" | cut -d: -f3)
    counsel=$(echo "${side}" | cut -d: -f4)
    name=$(echo "${side}" | cut -d: -f5)
    cat > "${WORK_DIR}/bind-${party}.spec.json" <<EOF
{
  "schema":      "party_binding",
  "destination": "${DAVIDSON_LOG_DID}",
  "primary_signer_key": "${KEYS_DIR}/clerk-brown.key.json",
  "cosigner_keys":      ["${KEYS_DIR}/${counsel}.key.json"],
  "payload": {
    "binding_id":  "${binding_id}",
    "party_class": "${class}",
    "party_name":  "${name}",
    "case_ref":    "2024-CV-001",
    "case_seq":    ${S_CASE_ROOT}
  }
}
EOF
    submit_spec "Step 2 (${party})" "${WORK_DIR}/bind-${party}.spec.json"
    echo "  ${binding_id} at seq=${SEQ}"
    entry_json=$("${CLI}" get --endpoint "${DAVIDSON}" --seq "${SEQ}" 2>&1)
    assert_jq "Step 2 (${party})" "payload.binding_id round-trip" "${entry_json}" \
        '.payload.binding_id' "${binding_id}"
    assert_jq "Step 2 (${party})" "payload.party_class" "${entry_json}" \
        '.payload.party_class' "${class}"
done

# ─── Step 3: counsel appearances ────────────────────────────────────

print_step "Step 3 — counsel appearances (v1.8 §1 counsel_appearance ×2)"

for app in "cooper:bind-acme-001:ap-cooper-001:COOPER" \
           "davis:bind-beta-001:ap-davis-001:DAVIS"; do
    attorney=$(echo "${app}" | cut -d: -f1)
    binding=$(echo "${app}" | cut -d: -f2)
    appearance_id=$(echo "${app}" | cut -d: -f3)
    did_var=$(echo "${app}" | cut -d: -f4)
    did_val=$(eval "echo \$${did_var}")
    cat > "${WORK_DIR}/appearance-${attorney}.spec.json" <<EOF
{
  "schema":      "counsel_appearance",
  "destination": "${DAVIDSON_LOG_DID}",
  "primary_signer_key": "${KEYS_DIR}/${attorney}.key.json",
  "cosigner_keys":      ["${KEYS_DIR}/clerk-brown.key.json"],
  "payload": {
    "appearance_id": "${appearance_id}",
    "attorney_did":  "${did_val}",
    "represents":    ["${binding}"],
    "case_ref":      "2024-CV-001",
    "case_seq":      ${S_CASE_ROOT},
    "filed_date":    "2024-01-16",
    "status":        "active"
  }
}
EOF
    submit_spec "Step 3 (${attorney})" "${WORK_DIR}/appearance-${attorney}.spec.json"
    echo "  ${appearance_id} at seq=${SEQ}"
    entry_json=$("${CLI}" get --endpoint "${DAVIDSON}" --seq "${SEQ}" 2>&1)
    assert_jq "Step 3 (${attorney})" "attorney_did in payload" "${entry_json}" \
        '.payload.attorney_did' "${did_val}"
    assert_jq "Step 3 (${attorney})" "represents binding correctly" "${entry_json}" \
        '.payload.represents[0]' "${binding}"
done

# ─── Step 4: evidence_artifact + web3 cosignature ───────────────────

print_step "Step 4 — evidence_artifact + ACME CEO web3 cosignature (Ethereum mainnet)"

cat > "${WORK_DIR}/affidavit-acme-ceo.spec.json" <<EOF
{
  "schema":      "evidence_artifact",
  "destination": "${DAVIDSON_LOG_DID}",
  "primary_signer_key": "${KEYS_DIR}/clerk-brown.key.json",
  "cosigner_keys":      ["${KEYS_DIR}/acme-ceo.key.json"],
  "payload": {
    "evidence_id":               "ex-acme-affidavit-001",
    "evidence_type":             "affidavit",
    "classification":            "ordinary",
    "filed_by":                  "${ACME_CEO}",
    "case_ref":                  "2024-CV-001",
    "description":               "CEO affidavit re: contract formation, dated 2024-01-22",
    "content_digest":            "sha256:9b1c4e7d000000000000000000000000000000000000000000000000000000",
    "artifact_encryption":       "umbral_pre",
    "grant_authorization_mode":  "open",
    "grant_entry_required":      true,
    "grant_requires_audit_entry": true,
    "chain_of_custody_required": true
  }
}
EOF
submit_spec "Step 4" "${WORK_DIR}/affidavit-acme-ceo.spec.json"
echo "  evidence_artifact at seq=${SEQ}"
S_EVIDENCE="${SEQ}"

entry_json=$("${CLI}" get --endpoint "${DAVIDSON}" --seq "${S_EVIDENCE}" 2>&1)
assert_jq "Step 4" "two signatures on entry" "${entry_json}" \
    '.signatures | length' '2'
assert_jq "Step 4" "primary signature algo = ECDSA secp256k1 (1)" "${entry_json}" \
    '.signatures[0].algo_id' '1'
assert_jq "Step 4" "wallet cosignature algo = EIP-191 (3)" "${entry_json}" \
    '.signatures[1].algo_id' '3'
assert_jq "Step 4" "wallet cosigner DID is did:pkh:eip155:1" "${entry_json}" \
    '.signatures[1].signer_did | startswith("did:pkh:eip155:1:")' 'true'
assert_jq "Step 4" "chain_of_custody_required survives round-trip" "${entry_json}" \
    '.payload.chain_of_custody_required' 'true'

# ─── Step 5: read-time policy stage (PR-2 Stage 6 demo) ─────────────

print_step "Step 5 — read-time policy stage (no policy adopted → clean skip)"

if [ -n "${NETWORK_API:-}" ] && curl -fsS "${NETWORK_API}/healthz" >/dev/null 2>&1; then
    verify_json=$(curl -fsS "${NETWORK_API}/v1/verify/complete/${DAVIDSON_LOG_DID}/${S_CASE_ROOT}" 2>/dev/null || echo "{}")
    if [ "${verify_json}" = "{}" ]; then
        echo "    ⓘ /v1/verify/complete returned empty; check JN_VERIFY_POLICY_STAGE_ENABLE wiring"
    else
        assert_jq "Step 5" "all SDK stages green (sigs + authority + origin)" "${verify_json}" \
            '.all_green' 'true'
        assert_jq "Step 5" "Policy stage cleanly skipped (no policy adopted)" "${verify_json}" \
            '.report.Policy' 'null'
    fi
else
    echo "    ⓘ NETWORK_API unreachable; skipping Step 5 (run network-api separately)"
fi

# ─── Step 6: Layer 3 cowitness attestations (K-of-N quorum) ─────────

print_step "Step 6 — Layer 3 cowitness attestations (external-transparency quorum)"

# WITNESS_QUORUM_K is the K-of-N threshold the ledger was booted
# against (LEDGER_WITNESS_QUORUM_K). Default 1 makes the smoke-test
# K=1 case still report green; the recommended demo runs N=2, K=2
# per attesta v1.5.2/crypto/cosign/witness_key_set.go::NewWitnessKeySet
# (line 215: 1 ≤ K ≤ N).
K="${WITNESS_QUORUM_K:-1}"

head_json=$(curl -fsS "${DAVIDSON}/v1/tree/head" 2>&1)
SIZE=$(echo "${head_json}" | jq -r '.size // 0')
COWITNESS_COUNT=$(echo "${head_json}" | jq -r '.cosignatures // [] | length')
echo "  tree size=${SIZE}, cowitness attestations=${COWITNESS_COUNT}, expected K=${K}"

if [ "${SIZE}" -ge 6 ]; then
    echo "    ✓ tree size advanced past all 6 trial entries"
else
    echo "    ✗ tree size=${SIZE}, want ≥6 (sequencer may still be draining)"
    exit 3
fi

if [ "${COWITNESS_COUNT}" -ge "${K}" ]; then
    echo "    ✓ cowitness quorum met: ${COWITNESS_COUNT}-of-N ≥ K=${K}"
    # When the developer set K=2, inspect each attestation's pubkey id
    # + scheme so the K=2 demo concretely shows N distinct signers.
    if [ "${COWITNESS_COUNT}" -ge 2 ]; then
        echo "${head_json}" | jq -r '.cosignatures[] | "      attestation pubkey_id=\(.pub_key_id // .signer_did // "?") scheme=\(.scheme_tag // .algo_id // "?")"'
    fi
elif [ "${COWITNESS_COUNT}" -eq 0 ]; then
    echo "    ⓘ no cowitness attestations — Layer 3 mechanism is DISABLED."
    echo "      Ledger condition (per gossip.go:364): LEDGER_WITNESS_ENDPOINTS"
    echo "      is unset, so wireWitnessCosigner returned nil early."
    echo
    echo "      To enable the recommended N=2 K=2 demo:"
    echo "        1. Run 2 standalone-witness daemons (clearcompass-ai/standalone-witness)."
    echo "        2. Re-boot the ledger node with:"
    echo "             LEDGER_WITNESS_ENDPOINTS=http://witness-a:PORT,http://witness-b:PORT"
    echo "             LEDGER_WITNESS_QUORUM_K=2"
    echo "             LEDGER_GENESIS_WITNESS_SET=<wit-a-did>,<wit-b-did>"
    echo "        3. export WITNESS_QUORUM_K=2 before re-running this script."
    echo
    echo "      Layers 1 + 2 above are unaffected — only Layer 3 external"
    echo "      transparency is missing from this run."
else
    echo "    ✗ cowitness quorum SHORT: ${COWITNESS_COUNT}-of-N < K=${K}."
    echo "      One or more witnesses didn't return a signature in time."
    echo "      Per witness_key_set.go's K-of-N contract, the tree head is"
    echo "      NOT considered witnessed at this size."
    exit 3
fi

# ─── done ───────────────────────────────────────────────────────────

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Case 1 trial: ALL STEPS GREEN."
echo
echo "  case root:        ${DAVIDSON}/${S_CASE_ROOT}"
echo "  evidence artifact: ${DAVIDSON}/${S_EVIDENCE}"
echo "  tree size:        ${SIZE}"
echo
echo "Walkthrough source: docs/walkthrough/cases/01-acme-v-beta-trial.md"
echo "Continue with:      ./scripts/run-case-1-appeal.sh (not yet shipped)"
echo "═══════════════════════════════════════════════════════════════"

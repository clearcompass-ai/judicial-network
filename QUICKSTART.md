# Quickstart — five commands to a fully-asserted Case 1 trial run

For a technical evaluator (VC, security reviewer, prospective integrator)
who wants to see the judicial-network exercise its walkthrough end to
end against a real running stack, with **every step's evidence
asserted** by a script rather than eyeballed in a terminal.

## Architecture: three repos, three roles

| Repo | Role | This quickstart's reliance |
|---|---|---|
| `clearcompass-ai/ledger` | The dumb-write transparency log (two nodes for cross-exchange demo) | **External.** JN talks to it via HTTP. This repo does NOT boot it. |
| `clearcompass-ai/standalone-witness` | Independent witness daemon that cosigns tree heads (Layer 3 external transparency) | **Optional but recommended.** Without it, Step 6's Layer 3 evidence reports "no witnesses" — Layers 1 + 2 still work fully. |
| `clearcompass-ai/judicial-network` *(this repo)* | Domain-aware CLI + read-side API + the actor cast + the case walkthroughs | **What you run from.** |

Trust between JN and the ledger is **two env vars per ledger node**:
its URL and its `LEDGER_LOG_DID`. No shared secrets, no API keys, no
TLS pinning in dev. The cryptographic trust root is the SDK's
signature verification — the ledger admits any well-formed signed
entry whose destination DID matches its own `LEDGER_LOG_DID`. See
[`docs/walkthrough/02-real-dids.md`](docs/walkthrough/02-real-dids.md)
for the three-layer signature model (entry sigs / payload metadata /
witness tree-head cosignatures).

## The five commands

After cloning all three repos side by side and installing Docker
Compose v2 + Go 1.25.7+ + `jq`, the path to a fully-asserted Case 1
trial run is:

```bash
# (1) boot the ledger — SeaweedFS-backed, fully offline.
#     Brings up Postgres + SeaweedFS (S3-compatible) + 2 ledger nodes.
#     Replaces the older fake-gcs-server integration topology.
cd ../ledger
make integration-up                       # node-a :8080, node-b :8081

# (2) [optional] boot the standalone witness against both ledgers.
#     Without this, Step 6 of the trial walkthrough reports "no
#     witnesses" but everything else passes. See the standalone-witness
#     repo's own README for boot details.
cd ../standalone-witness
./scripts/run-local.sh                    # or follow that repo's quickstart

# (3) tell JN where the ledgers are. These four exports are the
#     entire trust-establishment surface — no other coordination.
cd ../judicial-network
export LEDGER_URL_DAVIDSON=http://localhost:8080
export LEDGER_URL_COA=http://localhost:8081
export LEDGER_LOG_DID_DAVIDSON=did:web:node-a.example   # baked into integration compose
export LEDGER_LOG_DID_COA=did:web:node-b.example        # baked into integration compose

# (4) mint the walkthrough's 9-actor cast (5 did:key + 4 did:pkh
#     across 4 different EVM chains: Ethereum, Polygon, Base, Optimism)
#     and write ./bin/walkthrough.env with every shell var.
make quickstart

# (5) run Case 1 trial end-to-end, asserting every evidence curl.
source ./bin/walkthrough.env
./scripts/run-case-1-trial.sh
```

Expected wall-clock time: ~3 minutes total. **The five commands
above are the whole experience.** No GCP, no MetaMask, no testnet
faucet, no shared secrets.

## What `make quickstart` actually does

Evidence available in [`Makefile`](Makefile) under the `quickstart`
target:

| Step | What | Effect |
|---|---|---|
| `quickstart-preflight` | Validates 4 env vars + curls both ledger `/healthz` endpoints | Fails fast with actionable error if anything's missing |
| `install-bins` | `go build` of `judicial-cli`, `network-api`, `court-tools`, `provider-tools`, `aggregator` | Five binaries in `./bin/` |
| `quickstart-keys` | Runs `judicial-cli keygen` per actor (idempotent — skip if `./bin/keys/$actor.key.json` exists) | 9 keypairs minted, each a real secp256k1 keypair with a real DID |
| `quickstart-env` | Walks `./bin/keys/`, extracts each DID via `jq`, writes `./bin/walkthrough.env` with every export | Sourced env file containing 4 ledger vars + 9 actor DID vars + 6 narrative aliases (`$CLERK`, `$ADAMS`, `$EDWARDS`, `$LEWIS`, `$OWENS`, `$MURPHY`) + `$KEYS_DIR` |

Pass `FORCE_RESET=1 make quickstart-keys` to discard and re-mint.

## What `./scripts/run-case-1-trial.sh` actually does

Evidence available in [`scripts/run-case-1-trial.sh`](scripts/run-case-1-trial.sh).

Six steps, each with a clear PASS / FAIL line per evidence assertion:

| Step | v1.8 § | What it submits | Evidence asserted |
|---|---|---|---|
| **1** | §1 case_initiation | civil_case entry (clerk + cooper) | `payload.docket_number=2024-CV-001`, primary signer is `$CLERK`, signature count = 2 |
| **2** | §1 party_binding ×2 | bind plaintiff + defendant | `binding_id` round-trip; `party_class` matches |
| **3** | §1 counsel_appearance ×2 | cooper + davis on record | `attorney_did` correct; `represents` references right binding |
| **4** | §4 evidence_admittance | CEO affidavit + web3 cosignature | 2 sigs, algo 1 + algo 3, wallet DID starts with `did:pkh:eip155:1:`, `chain_of_custody_required=true` |
| **5** | (PR-2 demo) | nothing — read-time verify of Step 1's entry | `.all_green=true`, `.report.Policy=null` (no policy adopted → clean skip) |
| **6** | (Layer 3) | nothing — fetch `/v1/tree/head` | tree size ≥ 6; witness cosig count reported (≥1 if standalone-witness is running, else informational) |

Failure modes:

- **exit 1**: prerequisite missing (env var unset, binary not built, ledger unreachable)
- **exit 2**: submission rejected by the ledger (admission gate failure)
- **exit 3**: entry on-log but evidence-curl response shape wrong (the load-bearing assertion — this is the case the script exists to catch)

## What's NOT in this quickstart

- **Case 1 appeal** + **Case 2** (Anderson family + succession + revocation) follow the same shape but as separate scripts that don't yet exist. Tracked as follow-up; the trial script is the canonical template for the remaining ones.

- **PolicyStage demo** (Step 5) requires `network-api` running with `JN_VERIFY_POLICY_STAGE_ENABLE=true` AND `ServerConfig.PolicyStage` map populated. The script auto-skips Step 5 when `$NETWORK_API` is unset, so this isn't a blocker — but it does mean Step 5's evidence is informational only in the default quickstart flow. To exercise it: `JN_VERIFY_POLICY_STAGE_ENABLE=true ./bin/network-api &` after `make quickstart`, then export `NETWORK_API=http://localhost:8082` before running the script.

- **Witness layer demo** (Step 6) requires the standalone-witness running and pointed at both ledgers. The script reports the witness count it sees; absent witnesses, Step 6 is informational only.

- **Strict v1.8 conformance** for Filer / Party signatures — see [`docs/walkthrough/02-real-dids.md`](docs/walkthrough/02-real-dids.md) §"Three signature layers" for the JN-extension flag. The quickstart exercises the current JN-extension pattern, not v1.8 strict.

## Operator sanity checks

```bash
# Ledger reachability (run after step 1 above)
curl -fsS http://localhost:8080/healthz       # → ok
curl -fsS http://localhost:8081/healthz       # → ok

# Standalone-witness reachability (after step 2)
# (port + endpoint per that repo's README)

# JN binaries built (after step 4)
./bin/judicial-cli version                     # → 0.0.1
ls ./bin/                                      # 5 binaries
ls ./bin/keys/                                 # 9 *.key.json files

# Confirm the 4 web3 chains are represented
for f in ./bin/keys/{acme-ceo,beta-cfo,anderson-mother,anderson-father}.key.json; do
    jq -r '.did' "$f"
done
# Expect:
#   did:pkh:eip155:1:0x...      (Ethereum mainnet — ACME CEO)
#   did:pkh:eip155:137:0x...    (Polygon            — Beta CFO)
#   did:pkh:eip155:8453:0x...   (Base               — Anderson mother)
#   did:pkh:eip155:10:0x...     (Optimism           — Anderson father)
```

## When the script fails

| Failure | Likely cause | Fix |
|---|---|---|
| `FAIL: $LEDGER_URL_DAVIDSON not reachable` | step 1 didn't complete; ledger not running | `cd ../ledger && make integration-up && make integration-status` |
| `submit rejected: destination_log_did_mismatch` | `LEDGER_LOG_DID_*` env vars don't match what the ledger has hardcoded in its integration compose | Use the values shown in step 3 verbatim, or override the ledger compose's `LEDGER_LOG_DID` |
| `FAIL Step 5: /v1/verify/complete returned empty` | network-api not running, or PolicyStage map not wired | See "What's NOT in this quickstart" above |
| `FAIL Step 6: tree size=N, want ≥6` | sequencer hasn't drained yet; try again in 1-2s, or check ledger `dev-logs` | Re-run; the sequencer interval in integration is 200ms so this is rare |

## Beyond the quickstart

- Full per-step narrative + v1.8 dictionary citations:
  [`docs/walkthrough/cases/01-acme-v-beta-trial.md`](docs/walkthrough/cases/01-acme-v-beta-trial.md)
- Three-layer signature model:
  [`docs/walkthrough/02-real-dids.md`](docs/walkthrough/02-real-dids.md)
- Event dictionary the walkthroughs map to:
  [`docs/event_dictionary_v1.8.md`](docs/event_dictionary_v1.8.md)

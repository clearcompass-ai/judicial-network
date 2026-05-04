# witness — standalone cosigning daemon

Closes the "operator self-signs unwitnessed in dev" gap from the
walkthrough. Runs an independent cosignature loop:

1. Periodically fetch the latest cosigned tree head from each
   configured operator endpoint via `*witness.TreeHeadClient`.
2. Skip if the head has not advanced since the last cosig
   (no-op cosignature suppression).
3. Sign the canonical 40-byte `WitnessCosignMessage` with the
   daemon's BLS witness key (`signFn` injected via deps).
4. POST the cosignature to `<operator>/v1/cosignatures`.

Probes (`/healthz`, `/readyz`, `/metrics`) follow the same shape
as the aggregator binary so cluster operators can scrape +
monitor uniformly across `cmd/network-api`,
`tools/cmd/aggregator`, and this binary.

## What this daemon does NOT do (yet)

- **Does not load the BLS key from disk.** `defaultSignerFunc` is
  a placeholder that returns an error; production swaps for a
  loader that parses the SDK's BLS PEM and calls
  `signatures.SignBLSCosignature`. That follow-up is small (~30
  LoC + a key-parsing test) but lives in a separate commit so
  this binary's wire-shape contract is reviewable without the
  cryptographic-material plumbing.
- **Does not detect equivocation.** The SDK has equivocation
  detection (`witness/equivocation.go`) but invoking it from a
  polling daemon requires a per-log historical store that's
  outside this binary's scope. Future commit.
- **Does not register the witness key on-chain.** Witness key
  registration is governance-driven; the daemon assumes its
  public key is already in the operator's accepted-witness set.

## Running

```sh
# Build the binary
go build -o ./bin/witness ./tools/cmd/witness

# Run with config file
./bin/witness --config /etc/jn/witness.json --listen-addr :8093
```

## Configuration

```json
{
  "witness_did":      "did:web:state:tn:witness:01",
  "witness_key_file": "/etc/witness/bls.key",
  "poll_interval":    "5s",
  "log_dids": [
    "did:web:state:tn:davidson:cases",
    "did:web:state:tn:davidson:officers"
  ],
  "operators": {
    "did:web:state:tn:davidson:cases":    "https://operator.davidson",
    "did:web:state:tn:davidson:officers": "https://operator.davidson"
  }
}
```

`Validate()` enforces:
- `witness_did`, `witness_key_file`, `log_dids`, `operators` all populated
- every `log_did` has a matching entry in `operators`

## Probes

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness. Always 200. k8s restarts on failure. |
| `GET /readyz`  | Readiness. 200 when ANY configured operator is reachable; 503 when all are down. |
| `GET /metrics` | Prometheus scrape. `jn_http_*` metric names match `cmd/network-api`. |

## Tests

| Test | What it pins |
|---|---|
| `TestParseFlags_*` | flag parsing |
| `TestLoadConfig_*` / `TestValidate_*` | config validation |
| `TestProcessLog_FetchFailure_PropagatesError` | per-log fetch failure surfaces |
| `TestTickOnce_PerLogFailureDoesNotBlock` | per-log failures don't block subsequent logs |
| `TestRun_ContextCancellation` | context-cancel path returns ctx.Err() |
| `TestDefaultSignerFunc_PlaceholderErrors` | placeholder signer returns clear error until BLS loader is wired |
| `TestWitnessProbes_*` | healthz / readyz (ANY-reachable) / metrics / 404 |

All tests run with `-race`. The daemon is independently
buildable + testable from the `tools/cmd/witness/` directory.

# ADR 0001 — Delegation store strategy is per-use-case, not global

**Status**: Accepted
**Date**: 2026-05-13
**Decides**: Where the delegation store lives for `attestation.DelegationResolver` consumers, and how reads + writes flow.

## Context

The attesta SDK (v1.2+) ships a `DelegationResolver` interface. Concrete implementations need a backing store of delegation entries to walk chains during constraint evaluation (`DelegationOriginDID`, `RequiredScopes`, recusal `DenyDIDs`). The question is **where the store lives** and **how reads flow** for each consumer of the resolver.

Three plausible global answers were considered:

| Option | Where the store lives | Tradeoff |
|---|---|---|
| Ledger-owned, read-API proxy | All reads hit the ledger over the network | Cleanest CQRS, but a network hop per Constraint evaluation |
| JN-owned, subscribed graph | JN replicates a delegation graph from ledger events | Local lookup, but a real sync surface to maintain (initial catch-up, continuous subscribe, rotation propagation, partition recovery, multi-network fan-in) |
| Cached projection, ledger-authoritative | JN runs an LRU + TTL local cache; misses fall back to ledger fetch | CQRS preserved (ledger is source of truth); local-latency reads after warm-up; no replication pipeline |

The framing as "ledger-owned vs JN-owned" misses two facts:

1. **Different use cases have different latency / consistency requirements.** A global pick is wrong; the right call is per-query.
2. **The cost of the JN-owned option is understated.** The "sync surface" is ~1–2 KLOC plus ops complexity (replication health, lag monitoring, partition handling). At 15-network scale (multi-ledger fan-in), this multiplies.

## Decision

**The delegation store strategy is per-use-case, not global.** Each query type binds to one strategy:

| Use case | Where the store lives | Consistency | Cost profile |
|---|---|---|---|
| Ledger admission of new entries | Ledger-local store + LRU cache | Strong | Hot path; aggressive caching mandatory |
| JN historical verification (e.g., "Dr. Sharma's 2026 SGU degree") | Cached projection on JN side, ledger-authoritative | Eventual (TTL acceptable) | Cold start slow; warm fast |
| JN real-time gate (e.g., "is this judge currently authorized to seal evidence") | Direct ledger fetch with short cache | Strong required | Per-query latency budget; few queries/sec |
| Multi-network cross-recognition (15-jurisdiction case) | Per-ledger cached projections (one per network) | Eventual (cache TTL per ledger) | Multi-ledger fan-out; partition tolerance matters |

## Consequences

### Implementation owners

| Use case | Owner repo | Notes |
|---|---|---|
| Ledger admission | `clearcompass-ai/ledger` | Already on the admission-refactor track (issue #75 decisions 9 + 10) |
| JN historical verification | `clearcompass-ai/judicial-network` | New work — issue to file. |
| JN real-time gate | `clearcompass-ai/judicial-network` | New work — issue to file. |
| JN cross-network recognition | `clearcompass-ai/judicial-network` | Future work — issue for roadmap visibility. |

### What this is NOT

This ADR does NOT decide:
- The cache size, eviction policy, or TTL values per row (per-impl tuning, not per-design).
- Whether to use a specific HTTP client / cache library (each row picks).
- The ledger's CosignatureOf / delegation-entry HTTP API shape (separate work for the ledger team to surface what JN needs).

### What the SDK provides (already shipped)

The matrix is implemented entirely on the consumer side. The attesta SDK provides:

- `attestation.DelegationResolver` interface (v1.2)
- `delegation.Resolver` concrete walker with cycle + max-depth guards (v1.2)
- `delegation.EntrySource` interface — the consumer-side data plug-in (v1.2)
- `delegation.InMemorySource` reference impl (v1.2)
- `attestation.VerifyEntryAttestationPolicy` composite (v1.2)
- `verifier.VerifyComplete` Stage 6 with `PolicyParams` (v1.4 — pending merge of attesta PR #23)

Each row of the matrix wires its own `EntrySource` impl over its specific store. No cross-consumer abstraction is introduced; the SDK provides primitives, each consumer wires them per use case.

### What the SDK is deliberately NOT asked to provide

- Cache primitives (LRU, TTL helpers) — each row picks.
- `MultiSourceResolver` (cross-network fan-out) — premature; trivial JN-side glue.
- Replication / subscription infrastructure for delegation events — JN's option only if a row demands it (currently no row does).

## Why this matters

Without this ADR, the next person implementing a JN verification path will likely:
- Pick "cleanest CQRS" (option 1, ledger-owned, network hop per eval) and ship a slow query, OR
- Pick "JN-owned subscribed graph" (option 2) and start building the sync surface that this ADR explicitly rejects as overweight.

The matrix above is the recorded decision. Future rows are added by extending the matrix with the same per-use-case discipline.

## Related

- attesta v1.2.0 — introduced `DelegationResolver` interface + `delegation/` package
- attesta v1.3.0 — added `SchemaParameters.AttestationPolicies` + `ControlHeader.AttestationPolicyName`
- attesta v1.4.0 (PR #23, pending) — `verifier.VerifyComplete` Stage 6
- `clearcompass-ai/ledger` issue #75 — admission-refactor decisions, including ledger-side resolver implementation

# JN-2 — Replace static `foreignSets` with journal-backed historical witness sets

> **Target repo:** clearcompass-ai/judicial-network
> **Labels:** `bug` · `long-term-verifiability` · `cross-log`
> **Depends on:** SDK-3 + AT-1 · **Relates to:** #69 (Gap A)
> **Status:** Proposal. Foreign witness sets are a static boot snapshot applied
> uniformly across all `asOf` positions, not the foreign log's rotation history.

## Why this exists

Scenario 1 (Foreign Root) requires verifying a foreign reference against the
foreign log's witness set *at the time the reference was minted*; Scenario 2
requires the year-1 set in year 15. JN resolves the foreign quorum from a static
config map built once at boot, so historical/point-in-time verification applies
the wrong (current) topology.

## Evidence (current behavior)

| File:line | Code | Problem |
|---|---|---|
| `cmd/network-api/multi_trust.go:120-141` | `buildForeignWitnessSets` builds `map[logDID]*WitnessKeySet` once via `crosslog.BuildWitnessSetsECDSAOnly(specs, nid)` from `PeerLogConfig.WitnessDIDs/QuorumK` | static boot snapshot |
| `verification/trust/multijurisdiction.go:30-35` | header: "the journal stores wire bytes + signatures **but not the trust topology that gates them**" | the static map is the topology applied at every asOf |
| `verification/trust/multijurisdiction.go:248-273` | `TrustRoot` returns `m.foreignSets[logDID]` | same set regardless of asOf |

## Impact

| Scenario | Failure today |
|---|---|
| **Scenario 1** | Foreign references aren't checked against the mint-time quorum |
| **Scenario 2 / Goal 13** | Year-1 foreign references verify against the current foreign set, not W1 |

## Proposed change

- Once SDK-3 + AT-1 land, resolve the foreign quorum per request via
  `journal.WitnessSetAt(logDID, asOf)` instead of `foreignSets[logDID]`.
- Keep the static map only as the genesis/bootstrap fallback when no journaled
  history exists for that log.
- Thread `asOf` (SDK-1/JN-4) so the resolved set matches the pinned head.

## Test plan

Realize #69's `TestMultiJurisdiction_AsOfHistorical` non-stubbed: rotate the
foreign witness set W1→W2; a year-1 TN reference into the foreign log verifies
under **W1** and **fails** under W2.

## Acceptance criteria

- [ ] Foreign quorum resolved historically from the journal (`WitnessSetAt`).
- [ ] Static map demoted to genesis/fallback.
- [ ] Year-1 foreign reference verifies under W1 after a rotation.

## Dependencies / related

- Depends on **SDK-3** + **AT-1**. Completes the witness-set half of
  **judicial-network#69** Gap A.

## Evidence trail

```bash
sed -n '115,141p' cmd/network-api/multi_trust.go
grep -rn "foreignSets\|BuildWitnessSetsECDSAOnly" cmd/network-api/ verification/trust/multijurisdiction.go
```

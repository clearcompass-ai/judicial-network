# scenario — appellate backlog (TN Court of Appeals & Court of Criminal Appeals)

The **active** scenario set (`ActiveCourts()`) is **Davidson County (trial) → TN
Supreme Court (court of last resort)** — both deployment-backed
(`deployments/tn/counties/davidson`, `deployments/tn/sup_ct`). The active flow
**short-circuits the intermediate appellate tier**: a Davidson case appeals /
transfers directly to the Supreme Court.

The two **intermediate appellate** courts that sit between them are **backlog**.

## Appeal/transfer topology (target)

```
Davidson County (trial)
        │
        ├─ civil ───────►  TN Court of Appeals          ┐
        │                  (tn/coa, did:web:state:tn:coa)│
        ├─ criminal ────►  TN Court of Criminal Appeals  ├──►  TN Supreme Court
        │                  (no deployment yet)           │     (tn/sup_ct, …:sc)
        └─ (active short-circuit) ───────────────────────┴──►  TN Supreme Court
```

Active today: the bottom arrow (Davidson → Supreme). When the appellate tier is
activated, civil appeals route through the Court of Appeals and criminal appeals
through the Court of Criminal Appeals.

## TN Court of Criminal Appeals — *modeled, blocked on a deployment*

- **Modeled:** ✅ `tn_criminal_appeals.go` carries the real 12-judge 2025 bench
  (panels of 3 in Jackson / Knoxville / Nashville) + `criminal_appellate` case
  types. The data is pinned by `TestCriminalAppeals_TwelveJudges`.
- **Blocker:** ❌ **no deployment.** A bundle (role catalog + cosignature mix)
  must be created at `deployments/tn/criminal_appeals/`, mirroring `tn/coa` (the
  civil Court of Appeals): appellate `judge` / `chief_judge` roles + the criminal
  appellate event types. `criminalAppealsExchangeDID` (`did:web:state:tn:cca`,
  currently a placeholder in `tn_criminal_appeals.go`) then moves into that
  deployment and is **derived, not restated**.
- **To activate:** (1) create the deployment; (2) confirm the role catalog has the
  appellate roles the model uses; (3) add `TennesseeCriminalAppeals()` to
  `ActiveCourts()` and assert its DID is deployment-backed.

## TN Court of Appeals — *deployment exists, not modeled*

- **Deployment:** ✅ exists — `tn/coa` (`did:web:state:tn:coa`), civil intermediate
  appellate.
- **Modeled:** ❌ no — there is no `TennesseeCourtOfAppeals()` yet; we don't have
  the real COA bench data (judges / divisions) supplied.
- **To activate:** (1) add a `TennesseeCourtOfAppeals()` model from the real bench
  (judges, presiding judge → `chief_judge`, the grand divisions); (2) add it to
  `ActiveCourts()`. **No deployment work needed.**

## Federal — *after the three TN courts*

Per the plan, Federal (its own jurisdiction + a new deployment) is added once the
three TN courts (Davidson, Court of Appeals, Court of Criminal Appeals) plus the
Supreme Court are fully wired through the seeder + generators.

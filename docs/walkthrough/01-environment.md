# §01 · Bring up your laptop topology

Goal: two operators running against **real Google Cloud Storage**,
a `judicial-cli` binary on your `$PATH`, and a clean log on both
exchanges.

The dev path uses your own GCS buckets in your own GCP project —
same code path as production. (For an offline / no-cloud
topology, see the operator's
`deployment/local/docker-compose.integration.yml` and `make
integration-up`. The walkthrough doesn't use that path; real GCS
is the default for daily development.)

## 1. Clone (or `cd` into) the three repos

```bash
mkdir -p ~/ortholog && cd ~/ortholog
git clone <fork>/ortholog-sdk           sdk
git clone <fork>/ortholog-operator      operator
git clone <fork>/judicial-network       jn
```

Each repo has the `claude/notice-of-appearance-event-rsEGt` branch
checked out (or substitute your team's working branch).

## 2. One-time GCS setup

This is the only step that requires anything outside Docker.

```bash
# Authenticate gcloud (writes Application Default Credentials)
gcloud auth application-default login

# Pick (or create) a GCP project where you can create buckets
export GOOGLE_PROJECT=your-gcp-project-id

# Two buckets — pick globally-unique names.
gcloud storage buckets create gs://yourname-davidson-entries \
    --location=US --project=$GOOGLE_PROJECT
gcloud storage buckets create gs://yourname-coa-entries \
    --location=US --project=$GOOGLE_PROJECT

# Tell the operator compose which buckets to use
export OPERATOR_DEV_BUCKET_DAVIDSON=yourname-davidson-entries
export OPERATOR_DEV_BUCKET_COA=yourname-coa-entries
```

Persist the three exports in your shell rc if you'll be running
the walkthrough often.

**Why real GCS?** The dev path is where GCS-related bugs need to
surface. Latency, IAM behaviour, multipart upload thresholds,
ListObjects pagination — all behave differently against the real
service vs. an emulator. Faking it would mask exactly the bugs
you want a developer to hit early.

## 3. Boot the dual-operator topology

The dev compose lives in the **operator** repo. From there:

```bash
cd ~/ortholog/operator
make dev-up
```

`make dev-up` runs `dev-preflight` first — it verifies your
gcloud ADC exists and both bucket env vars are set, and exits
non-zero with a clear message on any failure. Once preflight
passes, it builds the operator image, starts Postgres, creates
two databases (`ortholog_davidson`, `ortholog_coa`), and waits
for both operators to report `/healthz = ok`. Cold build: 3–5
min. Warm restart: ~15 seconds.

> The operator hits real GCS via `BYTE_STORE_BACKEND=gcs` plus
> Application Default Credentials mounted from
> `~/.config/gcloud/application_default_credentials.json`. No
> `BYTE_STORE_GCS_ENDPOINT` override — the Google Go SDK defaults
> to `storage.googleapis.com`.

Sanity:

```bash
$ curl -fsS http://localhost:8080/healthz       # Davidson trial
ok
$ curl -fsS http://localhost:8081/healthz       # TN Court of Appeals
ok
```

If either fails:

- Most common first-run error: `ortholog_coa` database missing.
  Fix: `make dev-down && make dev-up` (full reset; the init
  script only runs on fresh volumes).
- Operator log shows `bytestore init: ... permission denied`?
  Your ADC user lacks write access on the bucket. Run:
  ```bash
  gcloud storage buckets add-iam-policy-binding gs://$OPERATOR_DEV_BUCKET_DAVIDSON \
      --member=user:you@example.com --role=roles/storage.objectAdmin
  gcloud storage buckets add-iam-policy-binding gs://$OPERATOR_DEV_BUCKET_COA \
      --member=user:you@example.com --role=roles/storage.objectAdmin
  ```

Otherwise: `make dev-logs` and look for the offending line.

## 4. Inspect what the operators promise

The Maximum Merge Delay (MMD) is the operator's promise to sequence
any accepted entry within that wall-clock window:

```bash
$ curl -fsS http://localhost:8080/v1/admission/mmd
{"mmd_seconds":86400}
```

24 hours is the default in dev mode. The sequencer interval is
500 ms (compose env), so SCT-to-sequenced typically takes well
under a second.

Empty tree head:

```bash
$ curl -fsS http://localhost:8080/v1/tree/head
{"size":0,"root_hash":"","cosignatures":[],...}
```

## 5. Build the `judicial-cli`

```bash
cd ~/ortholog/jn
go build -o ~/.local/bin/judicial-cli ./cmd/judicial-cli
judicial-cli version
```

`~/.local/bin` is conventional; substitute whatever's on your
`$PATH`. The binary is ~10 MB and self-contained.

## 6. Set the two operator URLs as shell variables

You'll reference these constantly:

```bash
export DAVIDSON=http://localhost:8080
export COA=http://localhost:8081
```

Sanity: `curl -fsS $DAVIDSON/v1/admission/difficulty` returns a
JSON admission-difficulty object.

## 7. Inspect your real GCS buckets

```bash
gcloud storage ls gs://$OPERATOR_DEV_BUCKET_DAVIDSON
# Empty until the walkthrough runs.
```

Re-run after each walkthrough step to watch entry objects appear
in your bucket — one per sequenced entry, named by sequence.

## 8. Where everything lives

Bookmark these:

| What | Where |
|---|---|
| Operator HTTP route table | `operator/api/server.go:19-49` |
| Submission handler (POST `/v1/entries`) | `operator/api/submission.go` |
| Dev compose | `operator/deployment/local/docker-compose.dev.yml` |
| Integration compose | `operator/deployment/local/docker-compose.integration.yml` |
| Wire format | `sdk/core/envelope/serialize.go` |
| Signing primitive (did:key) | `sdk/crypto/signatures/entry_verify.go:342` (`SignEntry`) |
| Signing primitive (did:pkh) | `sdk/crypto/signatures/eth_sign.go` (`SignEthereumRecoverable`) |
| Cross-exchange seam (`EvidencePointers`) | `sdk/core/envelope/control_header.go:127` |
| Civil-case payload struct | `jn/schemas/civil_case.go:29` |
| Family-case payload struct | `jn/schemas/family_case.go:31` |

## Recap

After §01 you have:

- Two operators (Davidson `:8080`, COA `:8081`), each writing
  bytes to **your real GCS bucket**.
- One Postgres (`:5432`), three databases (`ortholog_davidson`,
  `ortholog_coa`, `court_tools`). The first two back the
  operators; the third backs the JN tools you'll boot in §03.
- Two GCS buckets you own, currently empty.
- One `judicial-cli` binary on your `$PATH`.

What's still missing for "the whole app":

- DIDs — mint them in **[§02](02-real-dids.md)**.
- The JN tools (court-tools + provider-tools) — boot them in
  **[§03](03-tools.md)**.

After §03 you'll have a complete dev-laptop deployment: protocol
layer (operators + Postgres + GCS) plus application layer (JN
tools), with the cases in `cases/` driving traffic through both.

## Trouble?

| Symptom | Fix |
|---|---|
| `dev-preflight FAIL: missing ADC` | `gcloud auth application-default login` |
| `dev-preflight FAIL: OPERATOR_DEV_BUCKET_*` unset | `export` both env vars (see §2) |
| Operator log: `permission denied` on bucket | Add `roles/storage.objectAdmin` to your ADC user (see §3) |
| Operator log: `bucket doesn't exist` | `gcloud storage buckets list --project=$GOOGLE_PROJECT` to confirm name |
| `dev-up` hangs > 2 min | `make dev-logs` — usually Postgres still initializing |
| `port 8080 already in use` | Previous run didn't shut down. `make dev-down` clears it. |
| Build fails in `cmd/judicial-cli/` | `go mod download` from JN repo. Confirm `go.mod` shows `ortholog-sdk v0.8.1`. |

Next: **[02-real-dids.md](02-real-dids.md)**.

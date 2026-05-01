# §01 · Bring up your laptop topology

Goal: two operators running, two GCS buckets ready, a `judicial-cli`
binary on your `$PATH`, and a clean log on both exchanges.

## 1. Clone (or `cd` into) the three repos

```bash
mkdir -p ~/ortholog && cd ~/ortholog
git clone <fork>/ortholog-sdk           sdk
git clone <fork>/ortholog-operator      operator
git clone <fork>/judicial-network       jn
```

Each repo has the `claude/notice-of-appearance-event-rsEGt` branch
checked out (or substitute your team's working branch).

## 2. Boot the dual-operator topology

The dev compose lives in the **operator** repo. From there:

```bash
cd ~/ortholog/operator
make dev-up
```

`make dev-up` builds the operator image, starts Postgres +
`fake-gcs-server`, creates two databases (`ortholog_davidson`,
`ortholog_coa`) and two GCS buckets (`davidson-entries`,
`coa-entries`), then waits for both operators to report
`/healthz = ok`. Cold build: 3–5 min. Warm restart: ~15 seconds.

> The dev topology uses `fsouza/fake-gcs-server` — an anonymous-mode
> GCS API emulator. The operator hits it via `BYTE_STORE_BACKEND=gcs`
> + `BYTE_STORE_GCS_ENDPOINT=http://gcs:4443` +
> `BYTE_STORE_GCS_ANONYMOUS=true`, exactly the same code path as a
> production deployment pointed at storage.googleapis.com.

Sanity:

```bash
$ curl -fsS http://localhost:8080/healthz       # Davidson trial
ok
$ curl -fsS http://localhost:8081/healthz       # TN Court of Appeals
ok
```

If either fails, run `make dev-logs` and look for the offending line.
The most common first-run error is the `ortholog_coa` database
missing — `make dev-down && make dev-up` resolves it.

## 3. Inspect what the operators promise

The Maximum Merge Delay (MMD) is the operator's promise to sequence
any accepted entry within that wall-clock window:

```bash
$ curl -fsS http://localhost:8080/v1/admission/mmd
{"mmd_seconds":86400}
```

24 hours is the default in dev mode. In our walkthrough, the
sequencer interval is 500 ms (see compose env), so SCT-to-sequenced
typically takes well under a second.

The current tree head (empty log = root of size 0):

```bash
$ curl -fsS http://localhost:8080/v1/tree/head
{"size":0,"root_hash":"","cosignatures":[],...}
```

Once we start submitting entries, this `size` advances and
`root_hash` becomes the Merkle root of the current log.

## 4. Build the `judicial-cli`

```bash
cd ~/ortholog/jn
go build -o ~/.local/bin/judicial-cli ./cmd/judicial-cli
judicial-cli version
```

`~/.local/bin` is conventional; substitute whatever you keep on your
`$PATH`. The binary is ~10 MB and self-contained.

Quick smoke test:

```bash
$ judicial-cli help
judicial-cli — judicial-network domain client
USAGE:
  judicial-cli <subcommand> [flags]
SUBCOMMANDS:
  keygen      Mint a did:key + secp256k1 keypair, write to disk.
  submit      Build, sign, and submit a signed entry from a JSON spec.
  ...
```

## 5. Set the two operator URLs as shell variables

You'll reference these constantly across the walkthrough; export them
once:

```bash
export DAVIDSON=http://localhost:8080
export COA=http://localhost:8081
```

Sanity: `curl -fsS $DAVIDSON/v1/admission/difficulty` returns a JSON
admission-difficulty object.

## 6. Optional — peek at the GCS buckets

`fake-gcs-server` has no web console, but its REST API is the same
GCS HTTP API a production deployment hits:

```bash
$ curl -fsS http://localhost:4443/storage/v1/b | jq '.items[].name'
"coa-entries"
"davidson-entries"

# Empty until the walkthrough runs:
$ curl -fsS 'http://localhost:4443/storage/v1/b/davidson-entries/o' | jq '.items // []'
[]
```

Keep that command handy — re-run after each walkthrough step to
see new entry objects appear in the buckets, one per sequenced
entry.

## 7. Where everything lives

Bookmark these for later reference; the walkthrough cites them:

| What | Where |
|---|---|
| Operator HTTP route table | `operator/api/server.go:19-49` |
| Submission handler (POST `/v1/entries`) | `operator/api/submission.go` |
| Wire format (canonical bytes) | `sdk/core/envelope/serialize.go` |
| Signing primitive | `sdk/crypto/signatures/entry_verify.go:342` (`SignEntry`) |
| Civil-case payload struct | `jn/schemas/civil_case.go:29` |
| Family-case payload struct | `jn/schemas/family_case.go:31` |
| Counsel-appearance payload struct | `jn/schemas/counsel_appearance.go:48` |
| Cross-exchange seam (`EvidencePointers`) | `sdk/core/envelope/control_header.go:127` |

## What's running, recap

After §01 you have:

- Two operators (Davidson `:8080`, COA `:8081`), each a
  domain-agnostic Ortholog operator, currently empty (size 0).
- One Postgres (`:5432`), two databases.
- One `fake-gcs-server` (`:4443`), two GCS buckets.
- One `judicial-cli` binary on your `$PATH`.

You have no DIDs yet. **§02 mints them.**

## Trouble?

| Symptom | Fix |
|---|---|
| `make: command not found` | macOS: `xcode-select --install`. Linux: `apt install make`. |
| `dev-up` hangs > 2 min | `make dev-logs` and look for the failing service. Most often Postgres needs a `dev-down` (volume reset). |
| `port 8080 already in use` | Either you already have something on that port, or the previous run didn't shut down cleanly. `make dev-down` clears it. |
| Build fails in `cmd/judicial-cli/` | `go mod download` from the JN repo root. Confirm `go.mod` shows `ortholog-sdk v0.8.0`. |

Next: **[02-real-dids.md](02-real-dids.md)**.

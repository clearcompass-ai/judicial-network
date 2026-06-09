# Configuration & secret injection (network-api / aggregator)

The JN service images are **orchestrator-agnostic**: nothing environment-specific
is baked in. The *same* image runs under docker-compose or Kubernetes; only the
injected configuration differs. This mirrors the baseproof fleet convention
(`baseproof/tooling` → `docs/CONFIG_INJECTION.md`).

## Two inputs, two mechanisms

| Input | Mechanism | docker-compose | Kubernetes |
|---|---|---|---|
| Plain config | environment variables | `environment:` | `envFrom: configMapRef` + `env:` |
| Secrets (DB DSN) | env from a secret | `environment:` (dev) | `env.valueFrom.secretKeyRef` |
| Certs / keys / bootstrap | a **file**, delivered by a **mount** | bind-mount `:ro` | Secret volume |

### The standard-mount convention

Every file input resolves: **explicit `API_*`/`TOOLS_*` env (or JSON config) →
else the standard mount path if a file exists there → else unset**. Drop a Secret
at the standard path and it works with zero env wiring. Implemented at the
binaries' composition roots (`api/config/operational.go` `ApplyEnvOverrides` →
`orStdFile`; `tools/aggregator/cmd/aggregator/main.go` → `orStdFile`;
`cmd/network-api/main.go` for the admission key).

## Standard paths

| | network-api (`/etc/network-api`) | aggregator (`/etc/aggregator`) |
|---|---|---|
| env prefix | `API_*` | `TOOLS_*` (+ `AGGREGATOR_OTLP_*`) |
| server mTLS | `tls/{tls.crt,tls.key,ca.crt}` ¹ | — (probe-only HTTP) |
| outbound ledger mTLS | `ledger-tls/{ca.crt,tls.crt,tls.key}` | `ledger-tls/{ca.crt,tls.crt,tls.key}` |
| admission key | `keys/admission-authority.pem` | — |
| network bootstrap | `bootstrap.json` | — |
| listen / probe port | 8443 (mTLS) | 8092 (probe) |
| DB (env, not a file) | — (stateless) | `TOOLS_DATABASE_URL` |

¹ network-api is **mTLS-only** (`RequireAndVerifyClientCert`), so its server TLS
Secret carries the client `ca.crt` alongside `tls.crt`/`tls.key`, and the chart
mounts the whole Secret at `/etc/network-api/tls`. (Unlike the ledger's
*optional* inbound mTLS, here the client CA is the expected posture.)

## Kubernetes (Helm)

Charts live under `deployment/helm/{network-api,aggregator}`. They render the
non-secret env into a ConfigMap (`envFrom`) and mount Secrets at the standard
paths — no cert path in env. Example (network-api):

```yaml
# values.yaml
serverTLS:       { existingSecret: jn-server-tls }   # → /etc/network-api/tls (tls.crt+tls.key+ca.crt)
bootstrap:       { existingSecret: jn-bootstrap }     # → /etc/network-api/bootstrap.json
admissionKey:    { existingSecret: jn-admission }     # → /etc/network-api/keys/admission-authority.pem (optional)
ledgerClientTLS: { existingSecret: jn-ledger-client } # → /etc/network-api/ledger-tls (optional)
config:
  ledgerEndpoint: "https://ledger.svc:8080"
  witnessQuorumK: "3"
```

The mTLS `/healthz` cannot be probed by kubelet (no client cert), so the chart
uses a **tcpSocket** liveness/readiness probe on 8443.

The aggregator takes its projection DB DSN from a Secret (`database.existingSecret`
with key `TOOLS_DATABASE_URL`, or an inline `database.url` the chart wraps in a
Secret) and optionally mounts ledger mTLS client material at
`/etc/aggregator/ledger-tls`.

## docker-compose

`deployment/local/docker-compose.{jn,aggregator,auditor}.yml` are the canonical
examples: `API_*`/`TOOLS_*` env plus a `:ro` bind mount of the cert dir
(`.run/certs:/run/jn/certs`). To use the zero-env standard paths instead, mount at
`/etc/network-api` (or `/etc/aggregator`) and drop the `*_FILE` env.

## Why this is agnostic

- Binaries read config from env (network-api also accepts a JSON config) and
  auto-detect files at the standard paths — no path, DSN, or endpoint is compiled
  in.
- Both images run as non-root uid `65532` with `/etc/<svc>` pre-created and
  owned by it, satisfying a k8s `runAsNonRoot` + read-only-root-filesystem
  PodSecurityContext.

/*
Package judicial is the judicial-domain HTTP layer of the JN api/.

api/exchange is domain-agnostic: it builds, signs, and submits whatever
opaque domain payload a caller hands it, gated by the Bundle resolved
from the entry's Destination. api/judicial is the COURT-AWARE front
door: handlers map court daily activities (file a case, issue an order,
seal a record, transfer a case to a different county) to the exact JN
domain functions that build the right entry shape, then return the
unsigned signing payload for the caller to sign and submit through
api/exchange.

Why a separate package, not more handlers in api/exchange:

  - Domain-agnostic invariant. api/exchange's docstring is explicit:
    "A court exchange, a hospital exchange, a land registry exchange
    — all expose these endpoints." Mixing court-specific handlers
    into api/exchange would break that.

  - Separation of concerns. api/exchange knows about envelope shape,
    signing, and ledger submission. api/judicial knows about
    dockets, sealing orders, appellate mandates, sealed party
    bindings, and the cosignature mix per event type. Both layers
    plug in via their own ServerConfig; the composer (api/server.go)
    mounts them under the same listener.

  - Direct connection to the JN domain layer. api/judicial imports
    cases/, appeals/, enforcement/, parties/, monitoring/,
    verification/, onboarding/, consortium/, delegation/, topology/.
    api/exchange MUST NOT.

Wire model — every handler does the SAME three things:

 1. Authenticate the caller via composer-level middleware (
    mTLS or JWT). The callerDID is read from
    middleware.CallerDIDFromContext.

 2. Decode the JSON request body into the matching domain Config
    struct (e.g., POST /v1/judicial/cases → cases.InitiationConfig).
    Required fields are validated by the domain function itself; the
    handler surfaces ErrInvalidRequest on JSON decode failure.

 3. Call the domain function to BUILD the entry (the handler does
    NOT sign or submit). Return the signing payload as JSON:

    { "entry_bytes": <base64>, "signing_payload": <base64>,
    "header": { "destination": "...", "signer_did": "...",
    "schema_ref": ..., ... } }

    The caller takes signing_payload, hashes it with SHA-256,
    signs the digest with their SCW (or external signer), then
    POSTs to /v1/entries/submit with the signed envelope bytes.

This split is THE SCW-only flow:

  - Court-internal signers (judges, clerks) and external party SCWs
    (Davis Inc., outside witnesses) both sign their own entries.
    api/judicial NEVER touches a key.
  - Multi-cosignature events (orders requiring witness signatures,
    sealed orders requiring co-judge approval) follow the same
    pattern: each cosigner builds an entry from their callerDID,
    signs, submits.

Layout: one file per domain area, following the JN domain package
boundary. cases.go for cases.*, appeals.go for appeals.*, etc. Each
file has its own _test.go pinning every handler's request decoding,
required-field validation, response shape, and 401 hygiene.
*/
package judicial

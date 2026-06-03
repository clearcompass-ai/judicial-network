// Package clients holds typed HTTP clients for each federation component
// (ledger, witness, auditor, aggregator, JN enforcer). Each embeds
// *httpx.Client, so Health()/Ready()/GetJSON/PostJSON are promoted, and adds
// component-specific typed methods.
//
// To extend: add a method that calls the embedded client and unmarshals into
// a type in ../types — no new plumbing. Keep these pure (no testing
// dependency) so a future cmd/validator can reuse them verbatim.
package clients

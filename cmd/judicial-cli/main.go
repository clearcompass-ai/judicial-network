/*
FILE PATH: cmd/judicial-cli/main.go

DESCRIPTION:
    judicial-cli — the judicial-network domain-aware client for talking
    to a running operator over HTTP. This binary lives in
    judicial-network (not the operator) because it knows about the
    judicial event payloads (CivilCase, CounselAppearance, etc.) and
    the cross-exchange composition pattern (EvidencePointers).

    The operator is "dumb writes": POST /v1/entries accepts canonical
    binary wire bytes. judicial-cli builds those bytes from a
    human-readable JSON spec, signs them with one or more secp256k1
    keys, and submits. It also offers ergonomic wrappers for the
    operator's read endpoints (get / head / wait / inclusion).

    Subcommands:
        keygen      mint a real did:key + secp256k1 private key
        submit      read a JSON spec, build envelope, sign, POST
        get         GET /v1/entries/{seq}        (or --raw for wire bytes)
        head        GET /v1/tree/head             (cosigned tree head)
        inclusion   GET /v1/tree/inclusion/{seq}  (Merkle inclusion proof)
        wait        poll /v1/entries-hash/{hex}   until sequenced
        version     print build version

    All transport is plain HTTP/HTTPS; no Privy, no embedded wallet.
    Secp256k1 keypairs live as JSON files on disk. Production callers
    swap key-loading for a signing service via the SDK's
    identity.IdentityProvider interface.

KEY ARCHITECTURAL DECISIONS:
  - CLI is schema-agnostic at the wire layer. It reads the payload as
    a raw JSON object and includes it in the envelope verbatim. This
    mirrors the operator's "I don't parse domain payloads" stance and
    keeps judicial-cli small (no per-schema dispatch table).
  - Walkthrough docs supply the per-schema JSON shapes, citing the
    judicial-network/schemas/ struct file:line. A typo in JSON
    surfaces only at the verifier (correct architectural location).
  - Cross-exchange composition is supported via the spec's
    "evidence_pointers" array — the entry's ControlHeader.EvidencePointers
    field is the SDK seam for cross-log references (cap 10 per
    operator/api/middleware/evidence_cap.go:20).

KEY DEPENDENCIES:
  - github.com/clearcompass-ai/ortholog-sdk/core/envelope
  - github.com/clearcompass-ai/ortholog-sdk/crypto/signatures
  - github.com/clearcompass-ai/ortholog-sdk/did
  - github.com/clearcompass-ai/ortholog-sdk/types
*/
package main

import (
	"flag"
	"fmt"
	"os"
)

const usage = `judicial-cli — judicial-network domain client

USAGE:
  judicial-cli <subcommand> [flags]

SUBCOMMANDS:
  keygen      Mint a did:key + secp256k1 keypair, write to disk.
              Example:  judicial-cli keygen --out alice.key.json

  submit      Build, sign, and submit a signed entry from a JSON spec.
              The spec includes signer key paths, destination, payload,
              and optional cosigners + evidence pointers.
              Example:  judicial-cli submit --endpoint http://localhost:8080 \
                                            --spec civil-case.spec.json

  get         Fetch entry metadata (or wire bytes with --raw).
              Example:  judicial-cli get --endpoint http://localhost:8080 --seq 1

  head        Fetch the cosigned tree head.
              Example:  judicial-cli head --endpoint http://localhost:8080

  inclusion   Fetch a Merkle inclusion proof.
              Example:  judicial-cli inclusion --endpoint http://localhost:8080 \
                                               --seq 1

  wait        Poll entries-hash until the entry is sequenced.
              Example:  judicial-cli wait --endpoint http://localhost:8080 \
                                          --hash <64-char-hex>

  version     Print build version.

EXIT CODES:
  0  success
  1  bad arguments / config
  2  HTTP/transport failure
  3  signing or wire-format failure
  4  remote returned an error response

For walkthrough usage see:
  judicial-network/docs/walkthrough/README.md
`

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	subcmd, args := os.Args[1], os.Args[2:]
	if err := dispatch(subcmd, args); err != nil {
		fmt.Fprintf(os.Stderr, "judicial-cli: %v\n", err)
		os.Exit(exitCode(err))
	}
}

func dispatch(subcmd string, args []string) error {
	switch subcmd {
	case "keygen":
		return runKeygen(args)
	case "submit":
		return runSubmit(args)
	case "get":
		return runGet(args)
	case "head":
		return runHead(args)
	case "inclusion":
		return runInclusion(args)
	case "wait":
		return runWait(args)
	case "version":
		fmt.Println(Version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q (run `judicial-cli help`)", subcmd)
	}
}

// ─── error categorization for exit codes ───────────────────────

type cliError struct {
	kind int
	err  error
}

func (e *cliError) Error() string {
	if e == nil || e.err == nil {
		return "<nil>"
	}
	return e.err.Error()
}

func (e *cliError) Unwrap() error { return e.err }

const (
	exitArgs      = 1
	exitTransport = 2
	exitWire      = 3
	exitRemote    = 4
)

func argsErr(format string, a ...interface{}) error {
	return &cliError{kind: exitArgs, err: fmt.Errorf(format, a...)}
}

func transportErr(format string, a ...interface{}) error {
	return &cliError{kind: exitTransport, err: fmt.Errorf(format, a...)}
}

func wireErr(format string, a ...interface{}) error {
	return &cliError{kind: exitWire, err: fmt.Errorf(format, a...)}
}

func remoteErr(format string, a ...interface{}) error {
	return &cliError{kind: exitRemote, err: fmt.Errorf(format, a...)}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ce, ok := err.(*cliError); ok && ce != nil {
		return ce.kind
	}
	return exitArgs
}

// flagSet returns a flag set with the subcommand's name in its
// usage line. Each subcommand calls this and registers its own
// flags before parsing.
func flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

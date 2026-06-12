// FILE PATH: tools/common/bridge.go
//
// The JN tools' shared surface, in two layers:
//
//   - DOMAIN types + tool config (types.go, config.go in this package):
//     judicial vocabulary (CaseRecord, OfficerRecord, docket/seal request
//     shapes) lifted here when LAW 5 took the agnostic layer to zero —
//     domain vocabulary lives with the domain.
//   - PLATFORM clients (this file): type aliases + constructor bindings to
//     libs/clitools, so every tool keeps ONE import for its shared surface
//     while the mechanics stay in their one home upstream.
package common

import (
	"github.com/baseproof/tooling/libs/clitools"
)

// Platform client surface — aliased verbatim from libs/clitools.
type (
	DB             = clitools.DB
	ExchangeClient = clitools.ExchangeClient
	VerifyClient   = clitools.VerifyClient
	LedgerClient   = clitools.LedgerClient
	RawEntry       = clitools.RawEntry
)

// Constructor bindings (aliases cannot carry funcs).
var (
	NewDB                       = clitools.NewDB
	NewExchangeClient           = clitools.NewExchangeClient
	NewMTLSExchangeClient       = clitools.NewMTLSExchangeClient
	NewVerifyClient             = clitools.NewVerifyClient
	NewMTLSVerifyClient         = clitools.NewMTLSVerifyClient
	NewLedgerClient             = clitools.NewLedgerClient
	NewMTLSLedgerClient         = clitools.NewMTLSLedgerClient
	NewServerVerifyLedgerClient = clitools.NewServerVerifyLedgerClient
)

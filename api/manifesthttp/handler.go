/*
FILE PATH: api/manifesthttp/handler.go

DESCRIPTION:

	GET /v1/network/bundle — the judicial network's mount of the SHARED
	platform serve handler (libs/networkbundle): one handler, every
	network, so ETag semantics and published-vs-enforced drift detection
	cannot diverge between the platform ledger and this composer.

	THIS file is wiring only. The judicial half — resolving a destination
	through the SAME frozen jurisdiction.Registry the SubmitGate enforces
	with, and projecting its Bundle via netmanifest.Build — is injected as
	the Compile closure. The serve mechanics (two-source truth rule,
	anchor re-canonicalization, ETag/304, drift headers, loud fallback)
	live in libs and are pinned by its tests.
*/
package manifesthttp

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/baseproof/tooling/libs/networkbundle"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/netmanifest"
)

// Config wires the handler. Lookup/Destinations come from the frozen
// jurisdiction.Registry; Input supplies the per-destination BuildInput
// (endpoints, admission posture, overlay) derived from boot state.
type Config struct {
	Lookup       func(destination string) (jurisdiction.Bundle, error)
	Destinations func() []string
	Input        func(destination string) networkbundle.BuildInput

	// Anchor is the manifest anchor schema position "<log-did>@<seq>"
	// (API_NETWORK_MANIFEST_SCHEMA). Empty ⇒ unpublished mode: the compiled
	// projection is served with X-Manifest-Published: false.
	Anchor string

	// LedgerBaseURL + Client resolve the published manifest from the ledger
	// (schema_ref query + raw entry fetch). Required when Anchor is set.
	LedgerBaseURL string
	Client        *http.Client

	Logger *slog.Logger
}

// New validates the wiring and mounts the shared serve handler over the
// jurisdiction projection.
func New(cfg Config) (http.Handler, error) {
	if cfg.Lookup == nil || cfg.Destinations == nil || cfg.Input == nil {
		return nil, fmt.Errorf("manifesthttp: Lookup, Destinations and Input are required")
	}
	return networkbundle.NewServeHandler(networkbundle.ServeConfig{
		Compile: func(destination string) (*networkbundle.Manifest, error) {
			b, err := cfg.Lookup(destination)
			if err != nil {
				// The registry has no bundle for it ⇒ the shared handler's 404.
				return nil, fmt.Errorf("%w: %v", networkbundle.ErrUnknownDestination, err)
			}
			return netmanifest.Build(b, cfg.Input(destination))
		},
		Destinations:  cfg.Destinations,
		Anchor:        cfg.Anchor,
		LedgerBaseURL: cfg.LedgerBaseURL,
		Client:        cfg.Client,
		Logger:        cfg.Logger,
	})
}

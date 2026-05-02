/*
FILE PATH: api/judicial/helpers.go

DESCRIPTION:
    Shared helpers used by every domain-specific file in this
    package: HTTP path/query parsing, base64 codec, and the
    logPositionRef wire shape every request payload uses to
    reference a specific (logDID, sequence) tuple.

    Kept in a dedicated file (under 300 lines) so the domain
    files stay focused on the handlers themselves.
*/
package judicial

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// logPositionRef is the JSON wire shape for a types.LogPosition.
// Every request body that needs to reference a specific log+seq uses
// this — case roots, scope pointers, evidence pointers, candidate
// delegations, etc. Centralized so the wire shape is consistent
// across every endpoint.
type logPositionRef struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
}

func (lp logPositionRef) toLogPosition() types.LogPosition {
	return types.LogPosition{LogDID: lp.LogDID, Sequence: lp.Sequence}
}

// pathSeq parses a uint64 path value. Returns false on parse failure
// so handlers can write a clean 400 with the parameter name.
func pathSeq(r *http.Request, name string) (uint64, bool) {
	raw := r.PathValue(name)
	var v uint64
	_, err := fmt.Sscan(raw, &v)
	return v, err == nil
}

// decodeBase64 decodes a base64 string. Empty input returns nil + nil
// (the domain functions accept empty Plaintext when an action has no
// document attached, e.g., a sentencing record without a written
// opinion).
func decodeBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// base64Encode is the inverse used in response building.
func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// buildPayloadFromEntry produces a buildResponse for any built entry.
// Used by handlers whose domain function returns multiple entries
// (e.g., county transfer's source amendment + delegation mirrors)
// where each entry needs its own signing payload in the response
// bundle.
func buildPayloadFromEntry(entry *envelope.Entry) buildResponse {
	signing := envelope.SigningPayload(entry)
	return buildResponse{
		SigningPayload: base64Encode(signing),
		EntryBytes:     base64Encode(signing),
		Header:         &entry.Header,
	}
}

// toLogPositions converts a slice of wire-shape refs to domain
// LogPositions. Common pre-dispatch transform.
func toLogPositions(refs []logPositionRef) []types.LogPosition {
	out := make([]types.LogPosition, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.toLogPosition())
	}
	return out
}

// sscanU64 parses a uint64 from a string. Wrapper around fmt.Sscan
// kept here so the calling files don't need to import "fmt" just for
// query-param parsing.
func sscanU64(s string, v *uint64) (int, error) {
	return fmt.Sscan(s, v)
}

// writeBuildResponseTo populates an existing buildResponse from an
// envelope.Entry. Used by composite responses that wrap buildResponse
// with additional fields (e.g., ArtifactCID after a filing).
func writeBuildResponseTo(resp *buildResponse, entry *envelope.Entry) {
	signing := envelope.SigningPayload(entry)
	resp.SigningPayload = base64Encode(signing)
	resp.EntryBytes = base64Encode(signing)
	resp.Header = &entry.Header
}

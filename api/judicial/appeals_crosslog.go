/*
FILE PATH: api/judicial/appeals_crosslog.go

DESCRIPTION:
    Cross-log appellate handlers behind 501 stubs. Each requires
    composing a CrossLogProof from raw HTTP inputs (source/local
    Merkle provers, source/local cosigned tree heads, anchor refs,
    fetcher) — that subsystem lands in C5 alongside the
    CrossLogProofBuilder helper that all cross-log routes share.

    Routes ARE registered (so callers get a clear 501 "wired in
    C5" instead of a 404), and the request bodies are NOT parsed
    yet (the eventual handlers will define their own request
    types). Each carries the auth check so the 401 contract holds
    even pre-implementation.
*/
package judicial

import "net/http"

// FileAppeal — needs CrossLogProof binding lower-court case to
// appellate court's log.
type appealInitiateHandler struct{ deps *Dependencies }

func (h *appealInitiateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"FileAppeal requires cross-log proof composition; wired in C5")
}

// IssueMandateReverse — publishes enforcement on lower court log
// referencing appellate decision via CrossLogProof.
type appealMandateReverseHandler struct{ deps *Dependencies }

func (h *appealMandateReverseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"IssueMandateReverse requires cross-log proof composition; wired in C5")
}

// TransferRecord — re-encrypts every artifact from source court
// under appellate keys; needs SourceDecryptor injection from a
// trust-boundary specific resolver. Wired in C5.
type appealRecordTransferHandler struct{ deps *Dependencies }

func (h *appealRecordTransferHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"TransferRecord requires SourceDecryptor injection; wired in C5")
}

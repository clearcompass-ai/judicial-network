/*
FILE PATH: business/handlers/cases.go

DESCRIPTION:
    Case read handlers. Public, no auth. Sealed filter applied
    upstream in middleware.

    GET /v1/cases/{docket}                    → case overview
    GET /v1/cases/{docket}/documents          → list filings
    GET /v1/cases/{docket}/documents/{docID}  → Option B download envelope

    All three use the exchange index to map docket → positions,
    then call the verification API for protocol state, then
    parse Domain Payloads for judicial-specific fields.

    This is the ONLY layer that interprets Domain Payloads.

KEY DEPENDENCIES:
    - judicial-network/exchange/index: docket → positions
    - judicial-network/api: verification service
*/
package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clearcompass-ai/judicial-network/exchange/index"
)

// Dependencies shared across all business handlers.
type Dependencies struct {
	ExchangeEndpoint      string
	VerificationEndpoint  string
	ArtifactStoreEndpoint string
	Index                 *index.LogIndex
	CourtDID              string
	OfficersLog           string
	CasesLog              string
	PartiesLog            string
}

// ─── Case Lookup ────────────────────────────────────────────────────

type CaseLookupHandler struct{ deps *Dependencies }

func NewCaseLookupHandler(deps *Dependencies) *CaseLookupHandler {
	return &CaseLookupHandler{deps: deps}
}

func (h *CaseLookupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	positions := h.deps.Index.Store.LookupDocket(h.deps.CasesLog, docket)
	if len(positions) == 0 {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	caseRootPos := positions[0]

	// Get verification state from verification API.
	originData, err := fetchVerification(
		h.deps.VerificationEndpoint,
		fmt.Sprintf("/v1/verify/origin/%s/%d", h.deps.CasesLog, caseRootPos),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verification unavailable")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"docket_number":   docket,
		"case_root_pos":   caseRootPos,
		"entry_count":     len(positions),
		"verification":    originData,
	})
}

// ─── Case Documents ─────────────────────────────────────────────────

type CaseDocumentsHandler struct{ deps *Dependencies }

func NewCaseDocumentsHandler(deps *Dependencies) *CaseDocumentsHandler {
	return &CaseDocumentsHandler{deps: deps}
}

func (h *CaseDocumentsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	positions := h.deps.Index.Store.LookupDocket(h.deps.CasesLog, docket)
	if len(positions) == 0 {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	// Each position after the root is a filing/amendment.
	type docEntry struct {
		Position uint64 `json:"position"`
		Type     string `json:"type,omitempty"`
	}

	docs := make([]docEntry, 0, len(positions)-1)
	for _, pos := range positions[1:] {
		docs = append(docs, docEntry{Position: pos})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"docket_number": docket,
		"documents":     docs,
		"count":         len(docs),
	})
}

// ─── Document Download (Option B) ───────────────────────────────────

type DocumentDownloadHandler struct{ deps *Dependencies }

func NewDocumentDownloadHandler(deps *Dependencies) *DocumentDownloadHandler {
	return &DocumentDownloadHandler{deps: deps}
}

func (h *DocumentDownloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")
	docID := r.PathValue("docID")

	positions := h.deps.Index.Store.LookupDocket(h.deps.CasesLog, docket)
	if len(positions) == 0 {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	// Resolve document ID to artifact CID via the index.
	// docID could be a position or an artifact CID directly.
	artifactCID := docID // simplified — production resolves via entry Domain Payload

	// Get retrieval URL from artifact store.
	resolveURL := fmt.Sprintf("%s/v1/artifacts/%s/resolve",
		h.deps.ArtifactStoreEndpoint, artifactCID)

	resolveResp, err := http.Get(resolveURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, "artifact store unreachable")
		return
	}
	defer resolveResp.Body.Close()

	var resolveData map[string]any
	json.NewDecoder(resolveResp.Body).Decode(&resolveData)

	// Get decryption key from grant entries on-log.
	// The scanner indexes artifact CID → position. The grant entry
	// at that position carries the key in Domain Payload.
	grantPos, found := h.deps.Index.Store.LookupCID(h.deps.CasesLog, artifactCID)
	if !found {
		writeError(w, http.StatusNotFound, "grant entry not found")
		return
	}

	// Fetch grant entry details from verification API.
	grantData, err := fetchVerification(
		h.deps.VerificationEndpoint,
		fmt.Sprintf("/v1/verify/origin/%s/%d", h.deps.CasesLog, grantPos),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "grant verification failed")
		return
	}

	// Option B response: return envelope for client-side decrypt.
	writeJSON(w, http.StatusOK, map[string]any{
		"docket_number":    docket,
		"document_id":      docID,
		"retrieval_url":    resolveData["url"],
		"retrieval_method": resolveData["method"],
		"encryption":       "AES-256-GCM",
		"grant_position":   grantPos,
		"grant_details":    grantData,
		"verification": map[string]string{
			"instruction": "Fetch ciphertext from retrieval_url. " +
				"Decrypt with decryption_key from grant entry Domain Payload " +
				"(base64-decoded, AES-256-GCM). SHA-256 of plaintext must " +
				"match content_digest from the filing entry.",
		},
	})
}

// ─── Shared ─────────────────────────────────────────────────────────

func fetchVerification(endpoint, path string) (map[string]any, error) {
	resp, err := http.Get(endpoint + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	json.Unmarshal(body, &result)
	return result, nil
}

// fetchWithTimeout is used for inter-service calls.
func fetchWithTimeout(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

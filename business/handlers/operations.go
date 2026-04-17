/*
FILE PATH: business/handlers/operations.go

DESCRIPTION:
    Write-path and domain-specific read handlers.

    POST /v1/cases/{docket}/file     → CMS files a document (mTLS + delegation auth)
    GET  /v1/parties/search          → party search by name or DID (public)
    GET  /v1/officers                → officer roster with roles (public)
    GET  /v1/docket/daily            → today's assignments (public)
    POST /v1/docket/daily            → publish daily docket (mTLS + delegation auth)

    Write endpoints require mTLS + on-log delegation with appropriate
    scope. The delegation auth middleware handles this upstream.
    The handler just does the work.

KEY DEPENDENCIES:
    - judicial-network/exchange: build/sign/submit entries, publish artifacts
    - judicial-network/exchange/index: domain identifier → position mapping
    - judicial-network/api: verification service for delegation walks
    - judicial-network/exchange/auth: SignerDIDFromContext
*/
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clearcompass-ai/judicial-network/exchange/auth"
)

// ─── Case Filing ────────────────────────────────────────────────────

type CaseFilingHandler struct{ deps *Dependencies }

func NewCaseFilingHandler(deps *Dependencies) *CaseFilingHandler {
	return &CaseFilingHandler{deps: deps}
}

func (h *CaseFilingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())
	docket := r.PathValue("docket")

	// Find case root position.
	positions := h.deps.Index.Store.LookupDocket(h.deps.CasesLog, docket)
	if len(positions) == 0 {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}
	caseRootPos := positions[0]

	// Read the document from multipart form.
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	file, header, err := r.FormFile("document")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing document field")
		return
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read document failed")
		return
	}

	filingType := r.FormValue("filing_type")
	if filingType == "" {
		filingType = "filing"
	}

	// Step 1: Publish artifact via exchange.
	artifactResp, err := publishArtifact(h.deps.ExchangeEndpoint, plaintext)
	if err != nil {
		writeError(w, http.StatusBadGateway, "artifact publish failed")
		return
	}

	// Step 2: Build + sign + submit filing entry via exchange.
	domainPayload, _ := json.Marshal(map[string]any{
		"docket_number":  docket,
		"filing_type":    filingType,
		"filename":       header.Filename,
		"artifact_cid":   artifactResp["cid"],
		"content_digest": artifactResp["content_digest"],
		"filed_date":     time.Now().UTC().Format("2006-01-02"),
	})

	entryReq, _ := json.Marshal(map[string]any{
		"builder":        "amendment",
		"signer_did":     callerDID,
		"target_root":    caseRootPos,
		"domain_payload": json.RawMessage(domainPayload),
	})

	entryResp, err := postToExchange(h.deps.ExchangeEndpoint+"/v1/entries/build-sign-submit", entryReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "entry submission failed")
		return
	}

	// Step 3: Grant artifact access via exchange.
	grantReq, _ := json.Marshal(map[string]any{
		"granter_did":  callerDID,
		"grantee_did":  "did:web:public", // public grant
		"artifact_key": artifactResp["encryption_key"],
		"schema_ref":   "tn-davidson-filing-v1",
	})

	cid, _ := artifactResp["cid"].(string)
	postToExchange(
		fmt.Sprintf("%s/v1/artifacts/%s/grant", h.deps.ExchangeEndpoint, cid),
		grantReq,
	)

	writeJSON(w, http.StatusCreated, entryResp)
}

// ─── Party Search ───────────────────────────────────────────────────

type PartySearchHandler struct{ deps *Dependencies }

func NewPartySearchHandler(deps *Dependencies) *PartySearchHandler {
	return &PartySearchHandler{deps: deps}
}

func (h *PartySearchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	did := r.URL.Query().Get("did")

	if name == "" && did == "" {
		writeError(w, http.StatusBadRequest, "provide name or did parameter")
		return
	}

	var positions []uint64
	if name != "" {
		positions = h.deps.Index.Store.LookupParty(h.deps.PartiesLog, name)
	}
	if did != "" {
		didPositions := h.deps.Index.Store.LookupDID(h.deps.PartiesLog, did)
		positions = append(positions, didPositions...)
	}

	type partyResult struct {
		Position uint64 `json:"position"`
	}

	results := make([]partyResult, 0, len(positions))
	for _, pos := range positions {
		results = append(results, partyResult{Position: pos})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"count":   len(results),
	})
}

// ─── Officer Roster ─────────────────────────────────────────────────

type OfficerRosterHandler struct{ deps *Dependencies }

func NewOfficerRosterHandler(deps *Dependencies) *OfficerRosterHandler {
	return &OfficerRosterHandler{deps: deps}
}

func (h *OfficerRosterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Call verification API to walk delegation tree from court DID.
	delegationData, err := fetchVerification(
		h.deps.VerificationEndpoint,
		fmt.Sprintf("/v1/verify/delegation/%s/%s", h.deps.OfficersLog, h.deps.CourtDID),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delegation walk failed")
		return
	}

	// Parse Domain Payloads for role, division, scope_limit.
	// This is where the business layer interprets what the protocol
	// layer returns as raw data.
	delegations, ok := delegationData["delegations"].([]any)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"officers": []any{}, "count": 0})
		return
	}

	type officer struct {
		DID       string   `json:"did"`
		Role      string   `json:"role"`
		Division  string   `json:"division"`
		Scope     []string `json:"scope"`
		Live      bool     `json:"live"`
		Depth     int      `json:"depth"`
	}

	officers := make([]officer, 0, len(delegations))
	for _, d := range delegations {
		dm, ok := d.(map[string]any)
		if !ok {
			continue
		}

		payload, _ := dm["domain_payload"].(map[string]any)
		role, _ := payload["role"].(string)
		division, _ := payload["division"].(string)

		var scope []string
		if sl, ok := payload["scope_limit"].([]any); ok {
			for _, s := range sl {
				if str, ok := s.(string); ok {
					scope = append(scope, str)
				}
			}
		}

		live, _ := dm["live"].(bool)
		depth := int(dm["depth"].(float64))

		officers = append(officers, officer{
			DID:      dm["delegate_did"].(string),
			Role:     role,
			Division: division,
			Scope:    scope,
			Live:     live,
			Depth:    depth,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"court_did": h.deps.CourtDID,
		"officers":  officers,
		"count":     len(officers),
	})
}

// ─── Daily Docket Read ──────────────────────────────────────────────

type DailyDocketReadHandler struct{ deps *Dependencies }

func NewDailyDocketReadHandler(deps *Dependencies) *DailyDocketReadHandler {
	return &DailyDocketReadHandler{deps: deps}
}

func (h *DailyDocketReadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Find today's daily assignment commentary entry via index.
	date := r.URL.Query().Get("date")
	if date == "" {
		date = time.Now().UTC().Format("2006-01-02")
	}

	// Look up by schema ref — the scanner indexes schema_ref → positions.
	positions := h.deps.Index.Store.LookupDocket(h.deps.CasesLog, "tn-daily-assignment-v1")

	// In production, filter by date in Domain Payload.
	// Here we return all assignment positions for the caller to filter.
	writeJSON(w, http.StatusOK, map[string]any{
		"date":              date,
		"assignment_entries": positions,
		"count":             len(positions),
	})
}

// ─── Daily Docket Write ─────────────────────────────────────────────

type DailyDocketWriteHandler struct{ deps *Dependencies }

func NewDailyDocketWriteHandler(deps *Dependencies) *DailyDocketWriteHandler {
	return &DailyDocketWriteHandler{deps: deps}
}

func (h *DailyDocketWriteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())

	var assignments json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&assignments); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	domainPayload, _ := json.Marshal(map[string]any{
		"schema_ref":      "tn-daily-assignment-v1",
		"assignment_date": time.Now().UTC().Format("2006-01-02"),
		"court_did":       h.deps.CourtDID,
		"assignments":     json.RawMessage(assignments),
	})

	entryReq, _ := json.Marshal(map[string]any{
		"builder":        "commentary",
		"signer_did":     callerDID,
		"domain_payload": json.RawMessage(domainPayload),
	})

	resp, err := postToExchange(h.deps.ExchangeEndpoint+"/v1/entries/build-sign-submit", entryReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "entry submission failed")
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// ─── Shared helpers ─────────────────────────────────────────────────

func publishArtifact(exchangeEndpoint string, plaintext []byte) (map[string]any, error) {
	resp, err := http.Post(
		exchangeEndpoint+"/v1/artifacts/publish",
		"application/octet-stream",
		bytes.NewReader(plaintext),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func postToExchange(url string, body []byte) (map[string]any, error) {
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

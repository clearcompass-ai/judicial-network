/*
FILE PATH: api/handlers/verify_batch.go

DESCRIPTION:
    POST /v1/verify/batch

    Batch EvaluateOrigin across multiple entries, potentially on
    different logs. Efficiency endpoint — one HTTP call instead of
    N sequential origin queries.

    Request body: array of { log_id, position } pairs.
    Response: array of origin evaluation results, same order.

    Cap at 500 entries per request to bound response time.

KEY DEPENDENCIES:
    - ortholog-sdk/verifier: EvaluateOrigin (guide §23.1)
*/
package handlers

import (
	"encoding/json"
	"net/http"
)

// VerifyBatchHandler handles POST /v1/verify/batch.
type VerifyBatchHandler struct {
	deps *Dependencies
}

func NewVerifyBatchHandler(deps *Dependencies) *VerifyBatchHandler {
	return &VerifyBatchHandler{deps: deps}
}

// BatchRequest is the request body.
type BatchRequest struct {
	Entries []BatchEntry `json:"entries"`
}

// BatchEntry identifies one entry to evaluate.
type BatchEntry struct {
	LogID    string `json:"log_id"`
	Position uint64 `json:"position"`
}

// BatchResult is one evaluation result.
type BatchResult struct {
	LogID    string `json:"log_id"`
	Position uint64 `json:"position"`
	State    string `json:"state,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (h *VerifyBatchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Entries) == 0 {
		writeError(w, http.StatusBadRequest, "entries array is empty")
		return
	}
	if len(req.Entries) > 500 {
		writeError(w, http.StatusBadRequest, "maximum 500 entries per request")
		return
	}

	results := make([]BatchResult, 0, len(req.Entries))

	for _, item := range req.Entries {
		result := BatchResult{
			LogID:    item.LogID,
			Position: item.Position,
		}

		query, ok := h.deps.resolveLog(item.LogID)
		if !ok {
			result.Error = "unknown log"
			results = append(results, result)
			continue
		}

		entry, err := query.FetchEntry(item.Position)
		if err != nil {
			result.Error = "entry not found"
			results = append(results, result)
			continue
		}

		originResult, err := h.deps.OriginEvaluator.EvaluateOrigin(item.Position, entry.Entry)
		if err != nil {
			result.Error = "evaluation failed"
			results = append(results, result)
			continue
		}

		result.State = originResult.State
		results = append(results, result)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"total":   len(results),
	})
}

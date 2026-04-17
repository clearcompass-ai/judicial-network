package courts

import (
	"net/http"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// CreateOrder handles POST /v1/cases/{docket}/orders.
// Submits a BuildPathBEntry via exchange — judge signs through delegation chain.
func (s *Server) CreateOrder(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	var req common.OrderRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.OrderType == "" || req.JudgeDID == "" || len(req.DelegationPositions) == 0 {
		writeError(w, http.StatusBadRequest, "order_type, judge_did, and delegation_positions required")
		return
	}

	casePos, err := s.lookupCasePosition(r, docket)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	result, err := s.exchange.SubmitPathB(
		req.JudgeDID, s.cfg.CasesLogDID, casePos, req.DelegationPositions,
		map[string]any{
			"action":     "order",
			"order_type": req.OrderType,
			"ruling":     req.Ruling,
			"docket":     docket,
		},
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"order_id":     result.Position,
		"log_position": result.Position,
	})
}

// CosignOrder handles POST /v1/cases/{docket}/orders/{orderID}/cosign.
func (s *Server) CosignOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CosignerDID string `json:"cosigner_did"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	orderID := r.PathValue("orderID")
	var orderPos uint64
	if _, err := parseUint(orderID, &orderPos); err != nil {
		writeError(w, http.StatusBadRequest, "invalid order ID")
		return
	}

	signerDID := req.CosignerDID
	if signerDID == "" {
		signerDID = SignerDIDFromContext(r.Context())
	}

	result, err := s.exchange.SubmitEntry(map[string]any{
		"builder":        "cosignature",
		"signer_did":     signerDID,
		"log_did":        s.cfg.CasesLogDID,
		"cosignature_of": orderPos,
		"domain_payload": map[string]any{
			"endorsement": "approved",
		},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"cosignature_position": result.Position,
	})
}

// ListOrders handles GET /v1/cases/{docket}/orders.
func (s *Server) ListOrders(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	var caseID int64
	err := s.db.QueryRowContext(r.Context(),
		`SELECT id FROM cases WHERE docket_number = $1`, docket,
	).Scan(&caseID)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	rows, err := s.db.QueryContext(r.Context(), `
		SELECT event_type, log_position, signer_did, COALESCE(authority_path,''),
		       COALESCE(payload_summary::text,'{}')
		FROM case_events
		WHERE case_id = $1 AND event_type IN ('path_b_order', 'cosignature')
		ORDER BY log_position ASC
	`, caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	var orders []map[string]any
	for rows.Next() {
		var eventType, signer, authority, payload string
		var pos uint64
		rows.Scan(&eventType, &pos, &signer, &authority, &payload)
		orders = append(orders, map[string]any{
			"event_type":     eventType,
			"log_position":   pos,
			"signer_did":     signer,
			"authority_path": authority,
		})
	}

	writeJSON(w, http.StatusOK, orders)
}

func parseUint(s string, target *uint64) (bool, error) {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false, http.ErrNotSupported
		}
		*target = *target*10 + uint64(c-'0')
	}
	return true, nil
}

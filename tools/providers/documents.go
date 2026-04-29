package providers

import (
	"errors"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// ListDocuments handles GET /v1/records/{docket}/documents.
func (s *Server) ListDocuments(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	if s.db == nil {
		writeProviderError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	// Check sealed/expunged.
	var sealed, expunged bool
	err := s.db.QueryRowContext(r.Context(),
		`SELECT sealed, expunged FROM cases WHERE docket_number = $1`, docket,
	).Scan(&sealed, &expunged)
	if err != nil {
		writeProviderError(w, http.StatusNotFound, "case not found")
		return
	}
	if expunged {
		writeProviderError(w, http.StatusNotFound, "case not found")
		return
	}

	var caseID int64
	s.db.QueryRowContext(r.Context(),
		`SELECT id FROM cases WHERE docket_number = $1`, docket,
	).Scan(&caseID)

	rows, err := s.db.QueryContext(r.Context(), `
		SELECT cid, COALESCE(content_digest,''), filing_position, signer_did, sealed
		FROM artifacts WHERE case_id = $1 AND expunged = FALSE
		ORDER BY filing_position ASC
	`, caseID)
	if err != nil {
		writeProviderError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	var docs []map[string]any
	for rows.Next() {
		var cid, digest, signer string
		var pos uint64
		var docSealed bool
		rows.Scan(&cid, &digest, &pos, &signer, &docSealed)

		doc := map[string]any{
			"artifact_cid": cid,
			"log_position": pos,
			"signer_did":   signer,
			"public":       !docSealed && !sealed,
		}
		if !docSealed && !sealed {
			doc["content_digest"] = digest
		}
		docs = append(docs, doc)
	}

	writeProviderJSON(w, http.StatusOK, docs)
}

// GetDocument handles GET /v1/records/{docket}/documents/{cid}.
// Fetches public (non-sealed) documents from artifact store.
func (s *Server) GetDocument(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")
	cidStr := r.PathValue("cid")

	if s.db != nil {
		// Check case-level sealing.
		var sealed, expunged bool
		err := s.db.QueryRowContext(r.Context(),
			`SELECT sealed, expunged FROM cases WHERE docket_number = $1`, docket,
		).Scan(&sealed, &expunged)
		if err != nil || expunged {
			writeProviderError(w, http.StatusNotFound, "document not found")
			return
		}
		if sealed {
			writeProviderError(w, http.StatusForbidden, "case is sealed")
			return
		}

		// Check artifact-level sealing.
		var artSealed bool
		err = s.db.QueryRowContext(r.Context(),
			`SELECT sealed FROM artifacts WHERE cid = $1`, cidStr,
		).Scan(&artSealed)
		if err != nil {
			writeProviderError(w, http.StatusNotFound, "artifact not found")
			return
		}
		if artSealed {
			writeProviderError(w, http.StatusForbidden, "document is sealed")
			return
		}
	}

	// Fetch from artifact store via SDK ContentStore. Per the
	// architecture spec, judicial-network never imports
	// ortholog-artifact-store/ directly — every wire call goes
	// through the SDK's ContentStore interface.
	cid, err := storage.ParseCID(cidStr)
	if err != nil {
		writeProviderError(w, http.StatusBadRequest, "invalid CID")
		return
	}
	cs := storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{
		BaseURL: s.cfg.ArtifactStoreURL,
	})
	ct, err := cs.Fetch(cid)
	if err != nil {
		if errors.Is(err, storage.ErrContentNotFound) {
			writeProviderError(w, http.StatusNotFound, "artifact not found")
			return
		}
		writeProviderError(w, http.StatusBadGateway, "artifact store: "+err.Error())
		return
	}

	// Stream ciphertext. Providers serve encrypted content only.
	// Decryption requires keys from the exchange (not available to providers).
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Artifact-CID", cidStr)
	w.Header().Set("X-Encrypted", "true")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(ct)
}

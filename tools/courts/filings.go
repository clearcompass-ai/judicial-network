package courts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// CreateFiling handles POST /v1/cases/{docket}/filings.
// Accepts multipart: document file + metadata.
// Encrypts → pushes to artifact store → submits amendment with CID.
func (s *Server) CreateFiling(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	casePos, err := s.lookupCasePosition(r, docket)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	// Parse multipart form (max 50MB).
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	file, header, err := r.FormFile("document")
	if err != nil {
		writeError(w, http.StatusBadRequest, "document file required")
		return
	}
	defer file.Close()

	filingType := r.FormValue("filing_type")
	description := r.FormValue("description")

	// Read document bytes.
	docBytes, err := io.ReadAll(io.LimitReader(file, 50<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read document: "+err.Error())
		return
	}

	// Encrypt.
	ciphertext, artKey, err := artifact.EncryptArtifact(docBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encrypt: "+err.Error())
		return
	}

	// Compute CID and content digest.
	cid := storage.Compute(ciphertext)
	digest := sha256.Sum256(docBytes)

	// Push to artifact store.
	if err := s.pushToArtifactStore(ciphertext, cid.String()); err != nil {
		writeError(w, http.StatusBadGateway, "artifact store: "+err.Error())
		return
	}

	// Submit amendment with artifact reference.
	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitAmendment(signerDID, s.cfg.CasesLogDID, casePos, map[string]any{
		"event":          "evidence_filed",
		"filing_type":    filingType,
		"description":    description,
		"filename":       header.Filename,
		"artifact_cid":   cid.String(),
		"content_digest": hex.EncodeToString(digest[:]),
		"filed_at":       time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	// TODO: Store artKey in ArtifactKeyStore for later retrieval.
	_ = artKey

	writeJSON(w, http.StatusCreated, map[string]any{
		"filing_id":      fmt.Sprintf("%s-%d", docket, result.Position),
		"artifact_cid":   cid.String(),
		"content_digest": hex.EncodeToString(digest[:]),
		"log_position":   result.Position,
	})
}

// ListFilings handles GET /v1/cases/{docket}/filings.
func (s *Server) ListFilings(w http.ResponseWriter, r *http.Request) {
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
		SELECT cid, COALESCE(content_digest,''), filing_position, signer_did, sealed
		FROM artifacts WHERE case_id = $1 ORDER BY filing_position ASC
	`, caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	var filings []map[string]any
	for rows.Next() {
		var cid, digest, signer string
		var pos uint64
		var sealed bool
		rows.Scan(&cid, &digest, &pos, &signer, &sealed)
		filings = append(filings, map[string]any{
			"artifact_cid":   cid,
			"content_digest": digest,
			"log_position":   pos,
			"signer_did":     signer,
			"sealed":         sealed,
		})
	}

	writeJSON(w, http.StatusOK, filings)
}

// GetFiling handles GET /v1/cases/{docket}/filings/{cid}.
// Fetches from artifact store, decrypts, streams to client.
func (s *Server) GetFiling(w http.ResponseWriter, r *http.Request) {
	cidStr := r.PathValue("cid")

	// Fetch ciphertext from artifact store.
	ct, err := s.fetchFromArtifactStore(cidStr)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	// TODO: Retrieve artKey from ArtifactKeyStore.
	// For now, return ciphertext with a header indicating encryption.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Artifact-CID", cidStr)
	w.Header().Set("X-Encrypted", "true")
	w.WriteHeader(http.StatusOK)
	w.Write(ct)
}

func (s *Server) pushToArtifactStore(ciphertext []byte, cidStr string) error {
	req, err := http.NewRequest("POST", s.cfg.ArtifactStoreURL+"/v1/artifacts", bytes.NewReader(ciphertext))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Artifact-CID", cidStr)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (s *Server) fetchFromArtifactStore(cidStr string) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/artifacts/%s", s.cfg.ArtifactStoreURL, cidStr)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

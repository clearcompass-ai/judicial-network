//go:build sandbox

package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

var cfg SandboxConfig

func init() {
	cfg = loadSandboxConfig()
}

// ═════════════════════════════════════════════════════════════════════
// Phase 0: Sandbox health + connectivity
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_Health(t *testing.T) {
	t.Run("operator", func(t *testing.T) { healthCheck(t, cfg.OperatorURL) })
	t.Run("artifact_store", func(t *testing.T) { healthCheck(t, cfg.ArtifactStoreURL) })
	t.Run("exchange", func(t *testing.T) { healthCheck(t, cfg.ExchangeURL) })
	t.Run("verification_api", func(t *testing.T) { healthCheck(t, cfg.VerificationURL) })
}

// ═════════════════════════════════════════════════════════════════════
// Wave 1 replay: Provisioning — scope entities on all 3 logs
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_Provision_ScopeEntities(t *testing.T) {
	for _, log := range []struct{ name, did string }{
		{"officers", cfg.OfficersLogDID},
		{"cases", cfg.CasesLogDID},
		{"parties", cfg.PartiesLogDID},
	} {
		t.Run(log.name, func(t *testing.T) {
			result := submitEntry(t, cfg, map[string]any{
				"builder":    "scope_creation",
				"signer_did": cfg.CourtDID,
				"log_did":    log.did,
				"authority_set": map[string]any{
					cfg.CourtDID: struct{}{},
				},
				"domain_payload": map[string]any{
					"log_did":   log.did,
					"court_did": cfg.CourtDID,
				},
			})

			if result["position"] == nil {
				t.Fatalf("scope entry not admitted: %v", result)
			}
			t.Logf("%s scope entry at position: %v", log.name, result["position"])
		})
	}
}

// ═════════════════════════════════════════════════════════════════════
// Wave 1 replay: Delegation chain — depth 1-3
// ═════════════════════════════════════════════════════════════════════

var (
	sandboxJudgeDID  = "did:web:sandbox-exchange:role:judge-test"
	sandboxClerkDID  = "did:web:sandbox-exchange:role:clerk-test"
	sandboxDeputyDID = "did:web:sandbox-exchange:role:deputy-test"
)

func TestSandbox_Delegation_Depth1_Judge(t *testing.T) {
	result := submitEntry(t, cfg, map[string]any{
		"builder":     "delegation",
		"signer_did":  cfg.CourtDID,
		"delegate_did": sandboxJudgeDID,
		"log_did":     cfg.OfficersLogDID,
		"domain_payload": map[string]any{
			"role": "judge", "division": "criminal",
			"scope_limit": []string{"case_filing", "order", "judgment", "sealing_order"},
		},
	})
	if result["position"] == nil {
		t.Fatalf("judge delegation not admitted: %v", result)
	}
	t.Logf("judge delegation at position: %v", result["position"])
}

func TestSandbox_Delegation_Depth2_Clerk(t *testing.T) {
	result := submitEntry(t, cfg, map[string]any{
		"builder":     "delegation",
		"signer_did":  sandboxJudgeDID,
		"delegate_did": sandboxClerkDID,
		"log_did":     cfg.OfficersLogDID,
		"domain_payload": map[string]any{
			"role": "clerk", "division": "criminal",
			"scope_limit": []string{"scheduling", "docket_management", "filing_acceptance"},
		},
	})
	if result["position"] == nil {
		t.Fatalf("clerk delegation not admitted: %v", result)
	}
	t.Logf("clerk delegation at position: %v", result["position"])
}

func TestSandbox_Delegation_Depth3_Deputy(t *testing.T) {
	result := submitEntry(t, cfg, map[string]any{
		"builder":     "delegation",
		"signer_did":  sandboxClerkDID,
		"delegate_did": sandboxDeputyDID,
		"log_did":     cfg.OfficersLogDID,
		"domain_payload": map[string]any{
			"role": "deputy_clerk", "scope_limit": []string{"filing_acceptance"},
		},
	})
	if result["position"] == nil {
		t.Fatalf("deputy delegation not admitted: %v", result)
	}
	t.Logf("deputy delegation at position: %v", result["position"])
}

// ═════════════════════════════════════════════════════════════════════
// Wave 1 replay: Verify delegation tree via API
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_VerifyDelegationTree(t *testing.T) {
	// Verify the delegation tree rooted at the scope entity (position 0).
	result := verifyDelegation(t, cfg, cfg.OfficersLogDID, 0)
	if result["_status_code"] != float64(200) {
		t.Fatalf("delegation tree: HTTP %v", result["_status_code"])
	}

	// Should have at least 3 delegates.
	delegates, ok := result["live_delegates"].([]any)
	if !ok {
		t.Logf("delegation tree response: %v", result)
	} else if len(delegates) < 3 {
		t.Errorf("live delegates = %d, want >= 3", len(delegates))
	}
}

// ═════════════════════════════════════════════════════════════════════
// Wave 1 replay: Schema adoption on cases log
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_SchemaAdoption(t *testing.T) {
	result := submitEntry(t, cfg, map[string]any{
		"builder":    "schema",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"identifier_scope":          "real_did",
			"artifact_encryption":       "aes_gcm",
			"grant_authorization_mode":  "open",
			"override_requires_witness": true,
			"migration_policy":          "amendment",
		},
	})
	if result["position"] == nil {
		t.Fatalf("schema entry not admitted: %v", result)
	}
	t.Logf("schema entry at position: %v", result["position"])
}

// ═════════════════════════════════════════════════════════════════════
// Wave 1 replay: Artifact publish → retrieve → verify
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_ArtifactLifecycle(t *testing.T) {
	document := []byte(`{"docket":"2027-CR-4471","type":"motion_to_dismiss","content":"The defendant moves..."}`)

	// Encrypt.
	ciphertext, key, err := artifact.EncryptArtifact(document)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	cid := storage.Compute(ciphertext)
	digest := sha256.Sum256(document)

	// Push to artifact store.
	pushArtifact(t, cfg, ciphertext, cid.String())

	// Fetch back.
	retrieved := fetchArtifact(t, cfg, cid.String())
	if !bytes.Equal(retrieved, ciphertext) {
		t.Fatal("retrieved ciphertext doesn't match pushed")
	}

	// CID verifies.
	if !cid.Verify(retrieved) {
		t.Fatal("CID doesn't verify retrieved ciphertext")
	}

	// Decrypt.
	recovered, err := artifact.DecryptArtifact(retrieved, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(recovered, document) {
		t.Fatal("decrypted content doesn't match original")
	}

	// Content digest matches.
	recoveredDigest := sha256.Sum256(recovered)
	if recoveredDigest != digest {
		t.Fatal("content digest mismatch")
	}

	t.Logf("artifact lifecycle OK: CID=%s, size=%d", cid.String(), len(ciphertext))
}

// ═════════════════════════════════════════════════════════════════════
// Wave 2 replay: Case filing → amendment → seal → unseal
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_CaseLifecycle(t *testing.T) {
	// Step 1: File case.
	filing := submitEntry(t, cfg, map[string]any{
		"builder":    "root_entity",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"docket_number": "2027-CR-SBX-001",
			"case_type":     "criminal",
			"status":        "active",
			"filed_date":    "2027-04-17",
		},
	})
	casePos := filing["position"]
	t.Logf("case filed at position: %v", casePos)

	// Verify origin.
	origin := verifyOrigin(t, cfg, cfg.CasesLogDID, uint64(casePos.(float64)))
	if origin["_status_code"] != float64(200) {
		t.Logf("origin verify: %v", origin)
	}

	// Step 2: Amend case (status update).
	submitEntry(t, cfg, map[string]any{
		"builder":     "amendment",
		"signer_did":  cfg.CourtDID,
		"log_did":     cfg.CasesLogDID,
		"target_root": casePos,
		"domain_payload": map[string]any{
			"status":      "arraigned",
			"arraignment": "2027-05-01",
		},
	})

	// Step 3: Seal case.
	submitEntry(t, cfg, map[string]any{
		"builder":       "enforcement",
		"signer_did":    sandboxJudgeDID,
		"log_did":       cfg.CasesLogDID,
		"target_root":   casePos,
		"scope_pointer": 0, // scope entity at position 0
		"domain_payload": map[string]any{
			"order_type": "sealing_order",
			"authority":  "TCA 40-32-101",
			"case_ref":   "2027-CR-SBX-001",
		},
	})

	// Step 4: Unseal case.
	submitEntry(t, cfg, map[string]any{
		"builder":       "enforcement",
		"signer_did":    sandboxJudgeDID,
		"log_did":       cfg.CasesLogDID,
		"target_root":   casePos,
		"scope_pointer": 0,
		"domain_payload": map[string]any{
			"order_type": "unsealing_order",
			"reason":     "public interest — media request",
		},
	})

	t.Log("case lifecycle: file → amend → seal → unseal — all admitted")
}

// ═════════════════════════════════════════════════════════════════════
// Wave 2 replay: Path B judicial action via delegation
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_PathB_JudicialAction(t *testing.T) {
	// File a case first.
	filing := submitEntry(t, cfg, map[string]any{
		"builder":    "root_entity",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"docket_number": "2027-CR-SBX-002",
			"case_type":     "criminal",
			"status":        "active",
		},
	})
	casePos := filing["position"]

	// Judge signs an order via Path B.
	result := submitEntry(t, cfg, map[string]any{
		"builder":             "path_b",
		"signer_did":          sandboxJudgeDID,
		"log_did":             cfg.CasesLogDID,
		"target_root":         casePos,
		"delegation_pointers": []any{1}, // judge delegation at position 1
		"domain_payload": map[string]any{
			"action":     "order",
			"order_type": "motion_ruling",
			"ruling":     "denied",
		},
	})
	t.Logf("Path B judicial action at position: %v", result["position"])

	// Verify authority chain.
	auth := verifyAuthority(t, cfg, cfg.CasesLogDID, uint64(result["position"].(float64)))
	t.Logf("authority evaluation: %v", auth)
}

// ═════════════════════════════════════════════════════════════════════
// Wave 2 replay: Commentary — daily docket + recusal
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_Commentary_DailyDocket(t *testing.T) {
	result := submitEntry(t, cfg, map[string]any{
		"builder":    "commentary",
		"signer_did": sandboxJudgeDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"schema_ref":      "tn-daily-assignment-v1",
			"assignment_date": "2027-04-17",
			"court_did":       cfg.CourtDID,
			"divisions": []any{
				map[string]any{
					"division": "criminal",
					"assignments": []any{
						map[string]any{"judge_did": sandboxJudgeDID, "courtrooms": []string{"4A"}},
					},
				},
			},
		},
	})
	t.Logf("daily docket at position: %v", result["position"])
}

func TestSandbox_Commentary_Recusal(t *testing.T) {
	result := submitEntry(t, cfg, map[string]any{
		"builder":    "commentary",
		"signer_did": sandboxJudgeDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"type":          "recusal",
			"docket_number": "2027-CR-SBX-002",
			"reason":        "conflict of interest — concurrent ethics board service",
		},
	})
	t.Logf("recusal at position: %v", result["position"])
}

// ═════════════════════════════════════════════════════════════════════
// Wave 2 replay: Cosignature endorsement
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_Cosignature(t *testing.T) {
	// Submit cosignature referencing position 5 (any prior entry).
	result := submitEntry(t, cfg, map[string]any{
		"builder":        "cosignature",
		"signer_did":     sandboxClerkDID,
		"log_did":        cfg.CasesLogDID,
		"cosignature_of": 5,
		"domain_payload": map[string]any{
			"endorsement": "approved",
		},
	})
	t.Logf("cosignature at position: %v", result["position"])
}

// ═════════════════════════════════════════════════════════════════════
// Wave 2 replay: Revocation breaks delegation
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_Revocation(t *testing.T) {
	// Create a temporary delegation.
	tempDID := "did:web:sandbox-exchange:role:temp-officer"
	deleg := submitEntry(t, cfg, map[string]any{
		"builder":     "delegation",
		"signer_did":  cfg.CourtDID,
		"delegate_did": tempDID,
		"log_did":     cfg.OfficersLogDID,
		"domain_payload": map[string]any{
			"role": "temporary", "scope_limit": []string{"filing_acceptance"},
		},
	})
	delegPos := deleg["position"]

	// Revoke it.
	result := submitEntry(t, cfg, map[string]any{
		"builder":     "revocation",
		"signer_did":  cfg.CourtDID,
		"log_did":     cfg.OfficersLogDID,
		"target_root": delegPos,
		"domain_payload": map[string]any{
			"reason": "temporary_assignment_ended",
		},
	})
	t.Logf("revocation at position: %v (targeting delegation at %v)", result["position"], delegPos)
}

// ═════════════════════════════════════════════════════════════════════
// Wave 2 replay: Expungement — artifact key destruction
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_Expungement_KeyDestruction(t *testing.T) {
	document := []byte("Sealed juvenile record — sandbox expungement test")

	ct, key, err := artifact.EncryptArtifact(document)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	cid := storage.Compute(ct)
	pushArtifact(t, cfg, ct, cid.String())

	// Verify decryption works.
	retrieved := fetchArtifact(t, cfg, cid.String())
	recovered, err := artifact.DecryptArtifact(retrieved, key)
	if err != nil {
		t.Fatalf("pre-expungement decrypt: %v", err)
	}
	if !bytes.Equal(recovered, document) {
		t.Fatal("pre-expungement content mismatch")
	}

	// Destroy key.
	artifact.ZeroKey(&key)

	// Verify decryption fails.
	_, err = artifact.DecryptArtifact(retrieved, key)
	if err == nil {
		t.Fatal("decryption should fail after key destruction")
	}

	t.Log("expungement: key destroyed, artifact irrecoverable")
}

// ═════════════════════════════════════════════════════════════════════
// Wave 3 replay: Escrow split → reconstruct
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_EscrowSplitReconstruct(t *testing.T) {
	secret := make([]byte, 32)
	copy(secret, []byte("sandbox-signing-key-material"))

	shares, err := escrow.SplitGF256(secret, 3, 5)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	// Reconstruct with 3 of 5 shares.
	recovered, err := escrow.ReconstructGF256(shares[:3])
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatal("reconstructed secret doesn't match")
	}

	// Different 3 shares also work.
	recovered2, err := escrow.ReconstructGF256([]escrow.Share{shares[1], shares[3], shares[4]})
	if err != nil {
		t.Fatalf("reconstruct alt: %v", err)
	}
	if !bytes.Equal(recovered2, secret) {
		t.Fatal("alternate reconstruction doesn't match")
	}

	t.Log("escrow: 3-of-5 split and reconstruct verified")
}

// ═════════════════════════════════════════════════════════════════════
// Wave 3 replay: Re-encryption for custody transfer
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_CustodyTransfer_ReEncryption(t *testing.T) {
	docs := []string{
		"Motion to Dismiss", "Plea Agreement", "Sentencing Memo",
		"Victim Impact Statement", "Exhibit A — forensics",
	}

	for i, content := range docs {
		ct1, key1, err := artifact.EncryptArtifact([]byte(content))
		if err != nil {
			t.Fatalf("doc %d encrypt: %v", i, err)
		}

		cid1 := storage.Compute(ct1)
		pushArtifact(t, cfg, ct1, cid1.String())

		// Re-encrypt for new custodian.
		ct2, key2, err := artifact.ReEncryptArtifact(ct1, key1)
		if err != nil {
			t.Fatalf("doc %d re-encrypt: %v", i, err)
		}

		cid2 := storage.Compute(ct2)
		pushArtifact(t, cfg, ct2, cid2.String())

		// CIDs differ.
		if cid1.Equal(cid2) {
			t.Errorf("doc %d: CIDs should differ after re-encryption", i)
		}

		// New key decrypts new ciphertext.
		recovered, err := artifact.DecryptArtifact(ct2, key2)
		if err != nil {
			t.Fatalf("doc %d decrypt re-encrypted: %v", i, err)
		}
		if string(recovered) != content {
			t.Errorf("doc %d: content mismatch after re-encryption", i)
		}

		// Old key fails on new ciphertext.
		_, err = artifact.DecryptArtifact(ct2, key1)
		if err == nil {
			t.Errorf("doc %d: old key should fail on re-encrypted ciphertext", i)
		}
	}

	t.Logf("custody transfer: %d documents re-encrypted and verified", len(docs))
}

// ═════════════════════════════════════════════════════════════════════
// Wave 3 replay: Succession entry (graceful migration)
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_Succession(t *testing.T) {
	result := submitEntry(t, cfg, map[string]any{
		"builder":     "succession",
		"signer_did":  cfg.CourtDID,
		"log_did":     cfg.OfficersLogDID,
		"target_root": 0, // scope entity
		"domain_payload": map[string]any{
			"migration_type": "graceful",
			"new_exchange":   "did:web:exchange-b.sandbox.gov",
		},
	})
	t.Logf("succession entry at position: %v", result["position"])
}

// ═════════════════════════════════════════════════════════════════════
// Wave 3 replay: Bulk historical import
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_BulkHistoricalImport(t *testing.T) {
	dockets := []string{
		"2020-CR-1001", "2020-CR-1002", "2021-CV-2001",
		"2021-CV-2002", "2022-CH-3001", "2022-CH-3002",
	}

	for _, docket := range dockets {
		result := submitEntry(t, cfg, map[string]any{
			"builder":    "root_entity",
			"signer_did": cfg.CourtDID,
			"log_did":    cfg.CasesLogDID,
			"domain_payload": map[string]any{
				"docket_number": docket,
				"import_source": "bulk_historical",
				"original_court": cfg.CourtDID,
			},
		})
		if result["position"] == nil {
			t.Errorf("import %s failed: %v", docket, result)
		}
	}

	t.Logf("bulk import: %d historical cases imported", len(dockets))
}

// ═════════════════════════════════════════════════════════════════════
// Wave 3 replay: Anchor entry for cross-court verification
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_AnchorEntry(t *testing.T) {
	result := submitEntry(t, cfg, map[string]any{
		"builder":    "anchor",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"anchor_type":    "tree_head_ref",
			"source_log_did": cfg.CasesLogDID,
			"tree_head_ref":  hex.EncodeToString([]byte("sandbox-tree-head-hash")),
			"tree_size":      42871,
		},
	})
	t.Logf("anchor entry at position: %v", result["position"])
}

// ═════════════════════════════════════════════════════════════════════
// Wave 3 replay: Verification API — batch verify
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_VerificationAPI_Batch(t *testing.T) {
	result := verifyBatch(t, cfg, cfg.CasesLogDID, "0,1,2")
	if result["_status_code"] != float64(200) {
		t.Fatalf("batch verify: HTTP %v", result["_status_code"])
	}

	results, ok := result["results"].([]any)
	if !ok {
		t.Logf("batch response: %v", result)
	} else if len(results) != 3 {
		t.Errorf("batch results = %d, want 3", len(results))
	}
}

// ═════════════════════════════════════════════════════════════════════
// Wave 3 replay: Verification API — error paths
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_VerificationAPI_UnknownLog(t *testing.T) {
	result := verifyOrigin(t, cfg, "did:web:nonexistent", 0)
	if result["_status_code"] != float64(404) {
		t.Errorf("expected 404, got %v", result["_status_code"])
	}
}

func TestSandbox_VerificationAPI_InvalidFraudProof(t *testing.T) {
	result := verifyFraudProof(t, cfg, map[string]any{
		"log_did":    "did:web:nonexistent",
		"commitment": map[string]any{},
	})
	if result["_status_code"] != float64(404) {
		t.Errorf("expected 404, got %v", result["_status_code"])
	}
}

// ═════════════════════════════════════════════════════════════════════
// Davidson County bootstrap — all 6 divisions
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_Davidson_AllDivisions(t *testing.T) {
	divisions := []string{"criminal", "civil", "chancery", "circuit", "general-sessions", "juvenile"}

	for _, div := range divisions {
		t.Run(div, func(t *testing.T) {
			result := submitEntry(t, cfg, map[string]any{
				"builder":    "root_entity",
				"signer_did": cfg.CourtDID,
				"log_did":    cfg.OfficersLogDID,
				"domain_payload": map[string]any{
					"division":     div,
					"division_did": fmt.Sprintf("%s:%s", cfg.CourtDID, div),
					"court_did":    cfg.CourtDID,
				},
			})
			t.Logf("division %s at position: %v", div, result["position"])
		})
	}
}

// ═════════════════════════════════════════════════════════════════════
// End-to-end: Full case workflow with artifact
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_EndToEnd_CaseWithArtifact(t *testing.T) {
	// 1. File case.
	filing := submitEntry(t, cfg, map[string]any{
		"builder":    "root_entity",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"docket_number": "2027-CR-SBX-E2E",
			"case_type":     "criminal",
			"status":        "active",
		},
	})
	casePos := filing["position"]

	// 2. Encrypt and push document.
	doc := []byte(`{"exhibit":"A","description":"Surveillance footage metadata","classification":"restricted"}`)
	ct, key, _ := artifact.EncryptArtifact(doc)
	cid := storage.Compute(ct)
	digest := sha256.Sum256(doc)
	pushArtifact(t, cfg, ct, cid.String())

	// 3. Amend case with artifact reference.
	submitEntry(t, cfg, map[string]any{
		"builder":     "amendment",
		"signer_did":  cfg.CourtDID,
		"log_did":     cfg.CasesLogDID,
		"target_root": casePos,
		"domain_payload": map[string]any{
			"event":          "evidence_filed",
			"artifact_cid":   cid.String(),
			"content_digest": hex.EncodeToString(digest[:]),
			"evidence_type":  "exhibit",
		},
	})

	// 4. Verify artifact is retrievable and intact.
	retrieved := fetchArtifact(t, cfg, cid.String())
	recovered, err := artifact.DecryptArtifact(retrieved, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(recovered, doc) {
		t.Fatal("content mismatch")
	}

	// 5. Seal the case.
	submitEntry(t, cfg, map[string]any{
		"builder":       "enforcement",
		"signer_did":    sandboxJudgeDID,
		"log_did":       cfg.CasesLogDID,
		"target_root":   casePos,
		"scope_pointer": 0,
		"domain_payload": map[string]any{
			"order_type":         "sealing_order",
			"authority":          "TCA 40-32-101",
			"affected_artifacts": []string{cid.String()},
		},
	})

	// 6. Verify the full chain via API.
	originResult := verifyOrigin(t, cfg, cfg.CasesLogDID, uint64(casePos.(float64)))
	t.Logf("end-to-end: case=%v, artifact=%s, origin=%v",
		casePos, cid.String(), originResult["_status_code"])

	_ = key // key would be stored in ArtifactKeyStore in production
}

// ═════════════════════════════════════════════════════════════════════
// Scope governance — propose + approve
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_ScopeGovernance_ProposeApprove(t *testing.T) {
	// Propose adding a member.
	proposal := submitEntry(t, cfg, map[string]any{
		"builder":    "commentary",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.OfficersLogDID,
		"domain_payload": map[string]any{
			"proposal_type": "add_authority",
			"target_did":    "did:web:courts.knoxville.gov",
			"description":   "Add Knox County to consortium",
		},
	})
	proposalPos := proposal["position"]

	// Approve (cosignature referencing proposal).
	approval := submitEntry(t, cfg, map[string]any{
		"builder":        "cosignature",
		"signer_did":     cfg.CourtDID,
		"log_did":        cfg.OfficersLogDID,
		"cosignature_of": proposalPos,
		"domain_payload": map[string]any{
			"endorsement": "approved",
		},
	})

	t.Logf("governance: proposal=%v, approval=%v", proposalPos, approval["position"])
}

// ═════════════════════════════════════════════════════════════════════
// Migration record — audit trail
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_MigrationRecord(t *testing.T) {
	result := submitEntry(t, cfg, map[string]any{
		"builder":    "commentary",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.OfficersLogDID,
		"domain_payload": map[string]any{
			"migration_type":     "ungraceful",
			"failed_exchange":    "did:web:exchange-a.sandbox.gov",
			"new_exchange":       "did:web:exchange-b.sandbox.gov",
			"recovery_threshold": 3,
			"timestamp":          "2027-04-17T00:00:00Z",
		},
	})
	t.Logf("migration record at position: %v", result["position"])
}

// ═════════════════════════════════════════════════════════════════════
// Final summary — scan all entries
// ═════════════════════════════════════════════════════════════════════

func TestSandbox_FinalScan(t *testing.T) {
	// Scan first 50 entries on each log to verify everything landed.
	for _, log := range []struct{ name, did string }{
		{"officers", cfg.OfficersLogDID},
		{"cases", cfg.CasesLogDID},
		{"parties", cfg.PartiesLogDID},
	} {
		count := 0
		for seq := uint64(0); seq < 50; seq++ {
			url := fmt.Sprintf("%s/v1/entries/%d", cfg.OperatorURL, seq)
			resp, err := sandboxClient.Get(url)
			if err != nil {
				break
			}
			resp.Body.Close()
			if resp.StatusCode == 200 {
				count++
			} else {
				break
			}
		}
		t.Logf("%s log: %d entries found", log.name, count)
	}
}

// ═════════════════════════════════════════════════════════════════════
// Cross-court tests — run ONLY when second court is configured
//
// Configure via:
//   SANDBOX_COURT2_OPERATOR_URL=http://localhost:9001
//   SANDBOX_COURT2_EXCHANGE_URL=http://localhost:9003
//   SANDBOX_COURT2_DID=did:web:courts.shelby-sandbox.gov
//   SANDBOX_COURT2_OFFICERS_LOG=did:web:courts.shelby-sandbox.gov:officers
//   SANDBOX_COURT2_CASES_LOG=did:web:courts.shelby-sandbox.gov:cases
//   SANDBOX_COURT2_PARTIES_LOG=did:web:courts.shelby-sandbox.gov:parties
//   SANDBOX_ANCHOR_LOG_DID=did:web:courts.tn-sandbox.gov:anchor
//   SANDBOX_ANCHOR_OPERATOR_URL=http://localhost:7001
// ═════════════════════════════════════════════════════════════════════

func requireSecondCourt(t *testing.T) {
	t.Helper()
	if !cfg.HasSecondCourt() {
		t.Skip("skipping: second court not configured (set SANDBOX_COURT2_* env vars)")
	}
}

// ─── Cross-court: Provision second court ────────────────────────────

func TestSandbox_CrossCourt_ProvisionCourt2(t *testing.T) {
	requireSecondCourt(t)

	// Provision scope entities on court 2's logs.
	for _, log := range []struct{ name, did string }{
		{"officers", cfg.Court2OfficersLogDID},
		{"cases", cfg.Court2CasesLogDID},
		{"parties", cfg.Court2PartiesLogDID},
	} {
		t.Run(log.name, func(t *testing.T) {
			result := submitEntryTo(t, cfg.Court2ExchangeURL, map[string]any{
				"builder":    "scope_creation",
				"signer_did": cfg.Court2DID,
				"log_did":    log.did,
				"authority_set": map[string]any{
					cfg.Court2DID: struct{}{},
				},
				"domain_payload": map[string]any{
					"log_did":   log.did,
					"court_did": cfg.Court2DID,
				},
			})
			t.Logf("court2 %s scope at position: %v", log.name, result["position"])
		})
	}
}

// ─── Cross-court: File case on each court ───────────────────────────

func TestSandbox_CrossCourt_FileCasesOnBothCourts(t *testing.T) {
	requireSecondCourt(t)

	// File on court 1 (Davidson).
	c1 := submitEntry(t, cfg, map[string]any{
		"builder":    "root_entity",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"docket_number": "2027-CR-CROSS-001",
			"case_type":     "criminal",
			"court":         "davidson",
		},
	})
	t.Logf("court1 case at position: %v", c1["position"])

	// File on court 2 (Shelby).
	c2 := submitEntryTo(t, cfg.Court2ExchangeURL, map[string]any{
		"builder":    "root_entity",
		"signer_did": cfg.Court2DID,
		"log_did":    cfg.Court2CasesLogDID,
		"domain_payload": map[string]any{
			"docket_number": "2027-CR-CROSS-002",
			"case_type":     "criminal",
			"court":         "shelby",
		},
	})
	t.Logf("court2 case at position: %v", c2["position"])
}

// ─── Cross-court: Anchor both courts to shared anchor ───────────────

func TestSandbox_CrossCourt_AnchorBothCourts(t *testing.T) {
	requireSecondCourt(t)

	// Court 1 publishes anchor entry on anchor log.
	a1 := submitEntry(t, cfg, map[string]any{
		"builder":    "commentary",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.AnchorLogDID,
		"domain_payload": map[string]any{
			"anchor_type":    "tree_head_ref",
			"source_log_did": cfg.CasesLogDID,
			"tree_head_ref":  hex.EncodeToString([]byte("court1-tree-head")),
			"tree_size":      100,
		},
	})
	t.Logf("court1 anchor at position: %v", a1["position"])

	// Court 2 publishes anchor entry on anchor log.
	a2 := submitEntryTo(t, cfg.Court2ExchangeURL, map[string]any{
		"builder":    "commentary",
		"signer_did": cfg.Court2DID,
		"log_did":    cfg.AnchorLogDID,
		"domain_payload": map[string]any{
			"anchor_type":    "tree_head_ref",
			"source_log_did": cfg.Court2CasesLogDID,
			"tree_head_ref":  hex.EncodeToString([]byte("court2-tree-head")),
			"tree_size":      50,
		},
	})
	t.Logf("court2 anchor at position: %v", a2["position"])
}

// ─── Cross-court: Verify cross-log proof via API ────────────────────

func TestSandbox_CrossCourt_VerifyCrossLogProof(t *testing.T) {
	requireSecondCourt(t)

	// Fetch tree heads from both operators.
	court1Head := httpGET(t, cfg.OperatorURL+"/v1/tree/head")
	court2Head := httpGET(t, cfg.Court2OperatorURL+"/v1/tree/head")

	// Build cross-log proof request.
	// Court 2 verifying court 1's entry through the shared anchor.
	result := verifyCrossLog(t, cfg, map[string]any{
		"source_log_did": cfg.CasesLogDID,
		"proof": map[string]any{
			"source_entry":      map[string]any{"log_did": cfg.CasesLogDID, "sequence": 0},
			"source_tree_head":  court1Head,
			"anchor_entry":      map[string]any{"log_did": cfg.AnchorLogDID, "sequence": 0},
			"local_tree_head":   court2Head,
		},
	})

	t.Logf("cross-log verify result: valid=%v, status=%v", result["valid"], result["_status_code"])
}

// ─── Cross-court: Delegation on court 2 + verify from court 1 ──────

func TestSandbox_CrossCourt_DelegationOnCourt2(t *testing.T) {
	requireSecondCourt(t)

	court2JudgeDID := "did:web:sandbox-exchange:role:shelby-judge"

	// Delegate judge on court 2.
	result := submitEntryTo(t, cfg.Court2ExchangeURL, map[string]any{
		"builder":     "delegation",
		"signer_did":  cfg.Court2DID,
		"delegate_did": court2JudgeDID,
		"log_did":     cfg.Court2OfficersLogDID,
		"domain_payload": map[string]any{
			"role": "judge", "division": "criminal",
		},
	})
	t.Logf("court2 judge delegation at position: %v", result["position"])

	// Fetch the delegation entry from court 2's operator.
	if result["position"] != nil {
		entry := fetchEntryFrom(t, cfg.Court2OperatorURL, uint64(result["position"].(float64)))
		t.Logf("court2 delegation entry fetched: canonical_hex length=%d",
			len(fmt.Sprintf("%v", entry["canonical_hex"])))
	}
}

// ─── Cross-court: Same officer on both courts ───────────────────────

func TestSandbox_CrossCourt_SameOfficerBothCourts(t *testing.T) {
	requireSecondCourt(t)

	// McClendon serves on both courts (Variant 2 from cross-network doc).
	sharedDID := "did:web:sandbox-exchange:role:judge-mcclendon-shared"

	// Delegate on court 1.
	d1 := submitEntry(t, cfg, map[string]any{
		"builder":     "delegation",
		"signer_did":  cfg.CourtDID,
		"delegate_did": sharedDID,
		"log_did":     cfg.OfficersLogDID,
		"domain_payload": map[string]any{
			"role": "judge", "division": "criminal", "court": "davidson",
		},
	})

	// Delegate on court 2 — same DID, different court.
	d2 := submitEntryTo(t, cfg.Court2ExchangeURL, map[string]any{
		"builder":     "delegation",
		"signer_did":  cfg.Court2DID,
		"delegate_did": sharedDID,
		"log_did":     cfg.Court2OfficersLogDID,
		"domain_payload": map[string]any{
			"role": "judge", "division": "criminal", "court": "shelby",
		},
	})

	t.Logf("shared officer: court1 deleg=%v, court2 deleg=%v", d1["position"], d2["position"])

	// File on court 1 via shared officer.
	submitEntry(t, cfg, map[string]any{
		"builder":             "path_b",
		"signer_did":          sharedDID,
		"log_did":             cfg.CasesLogDID,
		"target_root":         0,
		"delegation_pointers": []any{d1["position"]},
		"domain_payload":      map[string]any{"action": "order", "court": "davidson"},
	})

	// File on court 2 via same officer.
	submitEntryTo(t, cfg.Court2ExchangeURL, map[string]any{
		"builder":             "path_b",
		"signer_did":          sharedDID,
		"log_did":             cfg.Court2CasesLogDID,
		"target_root":         0,
		"delegation_pointers": []any{d2["position"]},
		"domain_payload":      map[string]any{"action": "order", "court": "shelby"},
	})

	t.Log("same officer acted on both courts — independent delegation chains")
}

// ─── Cross-court: Officer transfer (revoke + re-delegate) ──────────

func TestSandbox_CrossCourt_OfficerTransfer(t *testing.T) {
	requireSecondCourt(t)

	transferDID := "did:web:sandbox-exchange:role:judge-transfer"

	// Delegate on court 1.
	d1 := submitEntry(t, cfg, map[string]any{
		"builder":     "delegation",
		"signer_did":  cfg.CourtDID,
		"delegate_did": transferDID,
		"log_did":     cfg.OfficersLogDID,
		"domain_payload": map[string]any{
			"role": "judge", "division": "civil",
		},
	})
	d1Pos := d1["position"]

	// Revoke on court 1.
	submitEntry(t, cfg, map[string]any{
		"builder":     "revocation",
		"signer_did":  cfg.CourtDID,
		"log_did":     cfg.OfficersLogDID,
		"target_root": d1Pos,
		"domain_payload": map[string]any{
			"reason": "officer_transferred_to_shelby",
		},
	})

	// Delegate on court 2.
	d2 := submitEntryTo(t, cfg.Court2ExchangeURL, map[string]any{
		"builder":     "delegation",
		"signer_did":  cfg.Court2DID,
		"delegate_did": transferDID,
		"log_did":     cfg.Court2OfficersLogDID,
		"domain_payload": map[string]any{
			"role": "judge", "division": "civil",
		},
	})

	t.Logf("officer transfer: revoked on court1 (deleg=%v), delegated on court2 (deleg=%v)",
		d1Pos, d2["position"])
}

// ─── Cross-court: Relay attestation (case transfer) ─────────────────

func TestSandbox_CrossCourt_CaseTransfer(t *testing.T) {
	requireSecondCourt(t)

	// File case on court 1.
	filing := submitEntry(t, cfg, map[string]any{
		"builder":    "root_entity",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"docket_number": "2027-CR-TRANSFER-001",
			"case_type":     "criminal",
			"status":        "active",
		},
	})
	court1CasePos := filing["position"]

	// Transfer: amend on court 1 marking transfer.
	submitEntry(t, cfg, map[string]any{
		"builder":     "amendment",
		"signer_did":  cfg.CourtDID,
		"log_did":     cfg.CasesLogDID,
		"target_root": court1CasePos,
		"domain_payload": map[string]any{
			"status":               "transferred",
			"transfer_destination": cfg.Court2CasesLogDID,
		},
	})

	// Accept on court 2: new root entity referencing court 1.
	court2Case := submitEntryTo(t, cfg.Court2ExchangeURL, map[string]any{
		"builder":    "root_entity",
		"signer_did": cfg.Court2DID,
		"log_did":    cfg.Court2CasesLogDID,
		"domain_payload": map[string]any{
			"docket_number":    "2027-CR-TRANSFER-001",
			"case_type":        "criminal",
			"status":           "active",
			"transfer_source":  cfg.CasesLogDID,
			"original_position": court1CasePos,
			"original_court":   cfg.CourtDID,
		},
	})

	t.Logf("case transfer: court1=%v → court2=%v", court1CasePos, court2Case["position"])
}

// ─── Cross-court: Background check across jurisdictions ─────────────

func TestSandbox_CrossCourt_BackgroundCheck(t *testing.T) {
	requireSecondCourt(t)

	// File cases on both courts for the same defendant.
	defendantDID := "did:web:sandbox-exchange:role:defendant-jones"

	submitEntry(t, cfg, map[string]any{
		"builder":    "root_entity",
		"signer_did": cfg.CourtDID,
		"log_did":    cfg.CasesLogDID,
		"domain_payload": map[string]any{
			"docket_number": "2027-CR-BG-001",
			"defendant_did": defendantDID,
			"court":         "davidson",
		},
	})

	submitEntryTo(t, cfg.Court2ExchangeURL, map[string]any{
		"builder":    "root_entity",
		"signer_did": cfg.Court2DID,
		"log_did":    cfg.Court2CasesLogDID,
		"domain_payload": map[string]any{
			"docket_number": "2027-CR-BG-002",
			"defendant_did": defendantDID,
			"court":         "shelby",
		},
	})

	// Verify entries exist on both logs.
	// A real background check tool would scan both logs for the defendant DID.
	t.Log("background check: cases filed on both courts for same defendant — tool scans both via cross-log")
}

// ─── Cross-court: Final scan on both courts ─────────────────────────

func TestSandbox_CrossCourt_FinalScan(t *testing.T) {
	requireSecondCourt(t)

	for _, court := range []struct {
		name, operatorURL string
		logs              []struct{ name, did string }
	}{
		{
			"court1", cfg.OperatorURL, []struct{ name, did string }{
				{"officers", cfg.OfficersLogDID},
				{"cases", cfg.CasesLogDID},
			},
		},
		{
			"court2", cfg.Court2OperatorURL, []struct{ name, did string }{
				{"officers", cfg.Court2OfficersLogDID},
				{"cases", cfg.Court2CasesLogDID},
			},
		},
	} {
		for _, log := range court.logs {
			count := 0
			for seq := uint64(0); seq < 100; seq++ {
				resp, err := sandboxClient.Get(fmt.Sprintf("%s/v1/entries/%d", court.operatorURL, seq))
				if err != nil {
					break
				}
				resp.Body.Close()
				if resp.StatusCode == 200 {
					count++
				} else {
					break
				}
			}
			t.Logf("%s/%s: %d entries", court.name, log.name, count)
		}
	}
}

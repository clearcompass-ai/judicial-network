package main

import "testing"

// TestRequireLedgerMTLS pins the JN→ledger secure-by-default edge: an https
// endpoint demands a client cert UNLESS explicitly opted out — either mTLS
// material, or the open-HTTPS self-signed posture (CA required), or plaintext.
// http/empty endpoints impose nothing.
func TestRequireLedgerMTLS(t *testing.T) {
	cases := []struct {
		name            string
		endpoint        string
		cert, key       string
		allowPlaintext  bool
		allowSelfSigned bool
		caFile          string
		wantErr         bool
	}{
		{"https + cert/key → ok", "https://ledger:8080", "c", "k", false, false, "", false},
		{"https + no cert → fail closed", "https://ledger:8080", "", "", false, false, "", true},
		{"https + half-config (cert only) → fail closed", "https://ledger:8080", "c", "", false, false, "", true},
		{"https + no cert + allow-plaintext → ok", "https://ledger:8080", "", "", true, false, "", false},
		{"https + self-signed + CA → ok (open HTTPS)", "https://ledger:8080", "", "", false, true, "ca.pem", false},
		{"https + self-signed + NO CA → fail closed", "https://ledger:8080", "", "", false, true, "", true},
		{"http plaintext endpoint → ok (no requirement)", "http://localhost:8080", "", "", false, false, "", false},
		{"empty endpoint (ledger-less dev) → ok", "", "", "", false, false, "", false},
		{"HTTPS uppercase + no cert → fail closed", "HTTPS://ledger:8080", "", "", false, false, "", true},
	}
	for _, tc := range cases {
		err := requireLedgerMTLS(tc.endpoint, tc.cert, tc.key, tc.allowPlaintext, tc.allowSelfSigned, tc.caFile)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

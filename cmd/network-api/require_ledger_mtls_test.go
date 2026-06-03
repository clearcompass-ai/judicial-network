package main

import "testing"

// TestRequireLedgerMTLS pins the JN→ledger secure-by-default edge: an https
// endpoint demands a client cert unless explicitly opted out; http/empty
// endpoints impose nothing.
func TestRequireLedgerMTLS(t *testing.T) {
	cases := []struct {
		name           string
		endpoint       string
		cert, key      string
		allowPlaintext bool
		wantErr        bool
	}{
		{"https + cert/key → ok", "https://ledger:8080", "c", "k", false, false},
		{"https + no cert → fail closed", "https://ledger:8080", "", "", false, true},
		{"https + half-config (cert only) → fail closed", "https://ledger:8080", "c", "", false, true},
		{"https + no cert + allow → ok (opt-out)", "https://ledger:8080", "", "", true, false},
		{"http plaintext endpoint → ok (no requirement)", "http://localhost:8080", "", "", false, false},
		{"empty endpoint (ledger-less dev) → ok", "", "", "", false, false},
		{"HTTPS uppercase + no cert → fail closed", "HTTPS://ledger:8080", "", "", false, true},
	}
	for _, tc := range cases {
		err := requireLedgerMTLS(tc.endpoint, tc.cert, tc.key, tc.allowPlaintext)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

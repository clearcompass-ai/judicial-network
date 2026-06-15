package scenario

// Identity export: persist each principal's keypair to disk in the repo-standard
// KeyFile format (the same shape cmd/judicial-cli keygen and the ledger signer
// write). The population is deterministic in the master seed, so these files are
// reproducible — but materializing them makes every judge, clerk, and attorney a
// REAL, inspectable, reusable identity an external signing tool can load, rather
// than a key that only ever lived in-process.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyFile is the on-disk keypair format, byte-compatible with cmd/judicial-cli's
// KeyFile (did/did_method/private_key_hex/public_key_compressed_hex) plus a few
// human-facing population fields. did_method is "key" for the derived did:key
// signers (officers + attorneys); the institutional root carries its did:web DID
// with an empty method (its derived key is only the default depth-0 signer until
// a genesis key is bound — see cmd/scenario -institutional-key).
type KeyFile struct {
	DID                    string `json:"did"`
	DIDMethod              string `json:"did_method"`
	Kind                   string `json:"kind,omitempty"`
	Name                   string `json:"name,omitempty"`
	Role                   string `json:"role,omitempty"`
	Court                  string `json:"court,omitempty"`
	FilerRole              string `json:"filer_role,omitempty"`
	BPRNumber              string `json:"bpr_number,omitempty"`
	PrivateKeyHex          string `json:"private_key_hex"`
	PublicKeyCompressedHex string `json:"public_key_compressed_hex"`
}

// keyFile renders this principal's exportable keypair.
func (p *Principal) keyFile() KeyFile {
	method := "key"
	if !strings.HasPrefix(p.DID, "did:key:") {
		method = "" // the institutional did:web is not a self-certifying did:key
	}
	return KeyFile{
		DID:                    p.DID,
		DIDMethod:              method,
		Kind:                   string(p.Kind),
		Name:                   p.Name,
		Role:                   p.Role,
		Court:                  p.Court,
		FilerRole:              p.FilerRole,
		BPRNumber:              p.BPR,
		PrivateKeyHex:          hex.EncodeToString(p.priv.Serialize()),
		PublicKeyCompressedHex: hex.EncodeToString(p.priv.PubKey().SerializeCompressed()),
	}
}

// ExportIdentities writes one KeyFile per principal (the institutional root,
// every officer, every attorney) into dir, returning the number written. Files
// are 0600 (they hold private keys); filenames are <kind>-<slug>.json, made
// unique on collision.
func (r *Registry) ExportIdentities(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("scenario: mkdir %q: %w", dir, err)
	}
	all := make([]*Principal, 0, 1+len(r.Officers)+len(r.Attorneys))
	all = append(all, r.Institutional)
	all = append(all, r.Officers...)
	all = append(all, r.Attorneys...)

	used := map[string]int{}
	n := 0
	for _, p := range all {
		base := slug(string(p.Kind) + "-" + p.Name)
		used[base]++
		if used[base] > 1 {
			base = fmt.Sprintf("%s-%d", base, used[base])
		}
		body, err := json.MarshalIndent(p.keyFile(), "", "  ")
		if err != nil {
			return n, fmt.Errorf("scenario: marshal identity %q: %w", p.Name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, base+".json"), append(body, '\n'), 0o600); err != nil {
			return n, fmt.Errorf("scenario: write identity %q: %w", base, err)
		}
		n++
	}
	return n, nil
}

// slug lowercases s and collapses non-alphanumerics to single hyphens, for safe
// filenames ("Joseph P. Day #1" → "joseph-p-day-1").
func slug(s string) string {
	var b strings.Builder
	prevHyphen := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevHyphen = false
			continue
		}
		if !prevHyphen {
			b.WriteByte('-')
			prevHyphen = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "principal"
	}
	return out
}

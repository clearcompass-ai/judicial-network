package clients

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/httpx"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/types"
)

// Ledger is a typed client for a ledger node (L5–L7). All methods are thin
// wrappers over the embedded *httpx.Client so scenarios never hand-roll URLs.
type Ledger struct{ *httpx.Client }

// NewLedger returns a plain-HTTP ledger client rooted at base.
func NewLedger(base string) *Ledger { return &Ledger{httpx.New(base)} }

// NewLedgerMTLS returns a ledger client that presents a client cert and trusts
// caFile — for a ledger whose listener enforces mTLS (the e2e edge sets
// LEDGER_TLS_CERT_FILE + LEDGER_INBOUND_CLIENT_CA_FILE, so every caller must
// authenticate at the transport layer). The harness uses this whenever the
// resolved LedgerURL is https (see newNetworkStack).
func NewLedgerMTLS(base, caFile, certFile, keyFile string) (*Ledger, error) {
	c, err := httpx.NewMTLS(base, caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &Ledger{c}, nil
}

// --- tree / heads (L6, L7) ---

// TreeHead is GET /v1/tree/head (S1.1, T1). 404 = empty log (no cosigned head).
func (l *Ledger) TreeHead() (types.CosignedTreeHead, int, error) {
	var h types.CosignedTreeHead
	code, err := l.GetJSON("/v1/tree/head", &h)
	return h, code, err
}

// TreeHeadRaw returns the /v1/tree/head body for key-presence assertions
// (the receipt_root PR #92 guard, S1.1).
func (l *Ledger) TreeHeadRaw() (int, []byte, error) { return l.GetRaw("/v1/tree/head") }

// TreeHeadAtSize is GET /v1/tree/head?size=n.
func (l *Ledger) TreeHeadAtSize(n uint64) (types.CosignedTreeHead, int, error) {
	var h types.CosignedTreeHead
	code, err := l.GetJSON("/v1/tree/head?size="+strconv.FormatUint(n, 10), &h)
	return h, code, err
}

// Checkpoint is GET /checkpoint — the offline-verifiable signed note (S1.2).
func (l *Ledger) Checkpoint() (int, []byte, error) { return l.GetRaw("/checkpoint") }

// Tile is GET /tile/{level}/{rest} — hash-only tiles (S1.2).
func (l *Ledger) Tile(level int, rest string) (int, []byte, error) {
	return l.GetRaw(fmt.Sprintf("/tile/%d/%s", level, rest))
}

// Inclusion is GET /v1/tree/inclusion/{seq} (S1.3, RFC6962).
func (l *Ledger) Inclusion(seq uint64) (int, []byte, error) {
	return l.GetRaw(fmt.Sprintf("/v1/tree/inclusion/%d", seq))
}

// Consistency is GET /v1/tree/consistency/{old}/{new} (S1.4).
func (l *Ledger) Consistency(oldN, newN uint64) (int, []byte, error) {
	return l.GetRaw(fmt.Sprintf("/v1/tree/consistency/%d/%d", oldN, newN))
}

// --- SMT (L3) ---

// SMTRoot is GET /v1/smt/root (S1.5).
func (l *Ledger) SMTRoot() (int, []byte, error) { return l.GetRaw("/v1/smt/root") }

// SMTProof is GET /v1/smt/proof/{key} (S1.5).
func (l *Ledger) SMTProof(key string) (int, []byte, error) {
	return l.GetRaw("/v1/smt/proof/" + key)
}

// SMTBatchProof is POST /v1/smt/batch_proof (S1.6).
func (l *Ledger) SMTBatchProof(keys []string) (int, []byte, error) {
	body, _ := json.Marshal(map[string]any{"keys": keys})
	return l.PostRaw("/v1/smt/batch_proof", "application/json", body)
}

// --- admission (L5) ---

// AdmissionMMD is GET /v1/admission/mmd (S1.7).
func (l *Ledger) AdmissionMMD() (int, []byte, error) { return l.GetRaw("/v1/admission/mmd") }

// AdmissionDifficulty is GET /v1/admission/difficulty (S1.7, Mode B PoW).
func (l *Ledger) AdmissionDifficulty() (int, []byte, error) {
	return l.GetRaw("/v1/admission/difficulty")
}

// --- entries (L5, L7) ---

// SubmitEntry POSTs canonical wire bytes to /v1/entries (S6.2, S8.1); on a 2xx
// it returns the SCT.
func (l *Ledger) SubmitEntry(wire []byte) (types.SignedCertificateTimestamp, int, error) {
	var sct types.SignedCertificateTimestamp
	code, b, err := l.PostRaw("/v1/entries", "application/octet-stream", wire)
	if err == nil && code/100 == 2 {
		_ = json.Unmarshal(b, &sct)
	}
	return sct, code, err
}

// SubmitBatch is POST /v1/entries/batch (S8.3); raw so callers can craft
// mixed valid/invalid batches.
func (l *Ledger) SubmitBatch(body []byte) (int, []byte, error) {
	return l.PostRaw("/v1/entries/batch", "application/json", body)
}

// EntryBySeq is GET /v1/entries/{seq} (S1.8).
func (l *Ledger) EntryBySeq(seq uint64) (types.EntryResponse, int, error) {
	var e types.EntryResponse
	code, err := l.GetJSON(fmt.Sprintf("/v1/entries/%d", seq), &e)
	return e, code, err
}

// EntryRaw is GET /v1/entries/{seq}/raw (S1.8, S8.1) — canonical wire bytes
// (200) or a redirect the client follows.
func (l *Ledger) EntryRaw(seq uint64) (int, []byte, error) {
	return l.GetRaw(fmt.Sprintf("/v1/entries/%d/raw", seq))
}

// EntryByHash is GET /v1/entries-hash/{h} (S1.8, S6.2). State == "pending"
// until the entry is sequenced.
func (l *Ledger) EntryByHash(hash string) (types.EntryResponse, int, error) {
	var e types.EntryResponse
	code, err := l.GetJSON("/v1/entries-hash/"+hash, &e)
	return e, code, err
}

// --- queries / commitments (L7) ---

// Query is GET /v1/query/{index}/{value} (S1.9).
func (l *Ledger) Query(index, value string) (int, []byte, error) {
	return l.GetRaw("/v1/query/" + index + "/" + value)
}

// Commitments is GET /v1/commitments/by-split-id/{schema}/{hex} (S1.10):
// 1=normal, 2+=equivocation, 404=none.
func (l *Ledger) Commitments(schema, hexKey string) (int, []byte, error) {
	return l.GetRaw("/v1/commitments/by-split-id/" + schema + "/" + hexKey)
}

// DerivationCommitment is GET /v1/commitments?seq=N (S1.16): the SMT-derivation
// commitment whose range covers seq, or 404 if none. Since the #190 fix the
// response is a content-addressed ref (mutations_cid set, mutations off-log)
// rather than inline mutations.
func (l *Ledger) DerivationCommitment(seq uint64) (int, []byte, error) {
	return l.GetRaw("/v1/commitments?seq=" + strconv.FormatUint(seq, 10))
}

// --- gossip feed (L7) ---

// GossipSince is GET /v1/gossip/since (S6.3); raw until the feed shape is
// pinned (see types.SignedEvent note).
func (l *Ledger) GossipSince(cursor string, limit int) (int, []byte, error) {
	return l.GetRaw("/v1/gossip/since?cursor=" + cursor + "&limit=" + strconv.Itoa(limit))
}

// GossipSthLatest is GET /v1/gossip/sth/latest (S1.11).
func (l *Ledger) GossipSthLatest() (int, []byte, error) { return l.GetRaw("/v1/gossip/sth/latest") }

// GossipByKind is GET /v1/gossip/by-kind?kind= (S1.11).
func (l *Ledger) GossipByKind(kind string) (int, []byte, error) {
	return l.GetRaw("/v1/gossip/by-kind?kind=" + kind)
}

// --- escrow / misc ---

// EscrowOverride is POST /v1/escrow-override (S7.10).
func (l *Ledger) EscrowOverride(body []byte) (int, []byte, error) {
	return l.PostRaw("/v1/escrow-override", "application/json", body)
}

// Metrics is GET /metrics (S1.12).
func (l *Ledger) Metrics() (int, error) {
	code, _, err := l.GetRaw("/metrics")
	return code, err
}

// LogInfo is GET /v1/log-info (S0.3); shape varies, returned as a map.
func (l *Ledger) LogInfo() (map[string]any, int, error) { return l.getMap("/v1/log-info") }

// Version is GET /version (S0.3, S1.12).
func (l *Ledger) Version() (map[string]any, int, error) { return l.getMap("/version") }

func (l *Ledger) getMap(path string) (map[string]any, int, error) {
	m := map[string]any{}
	code, err := l.GetJSON(path, &m)
	return m, code, err
}

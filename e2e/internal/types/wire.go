// Package types holds the on-the-wire shapes the Clarity components serve,
// shared by the typed clients (../clients) and the e2e scenarios. Field tags
// match the JSON each component emits; evidence cites are in ../../SCENARIOS.md.
package types

import "encoding/json"

// BootstrapDocument is network-bootstrap.json — the shared trust root every
// component loads (baseproof/network/bootstrap.go).
type BootstrapDocument struct {
	ProtocolVersion   string   `json:"protocol_version"`
	ExchangeDID       string   `json:"exchange_did"`
	NetworkName       string   `json:"network_name"`
	GenesisWitnessSet []string `json:"genesis_witness_set"`
	GenesisTreeHead   struct {
		RootHash string `json:"root_hash"`
		TreeSize uint64 `json:"tree_size"`
	} `json:"genesis_tree_head"`

	// NetworkID is the cosign NetworkID = SHA-256(canonical bootstrap), computed
	// at load via the baseproof SDK (NOT a JSON field). It is the value the
	// witnesses bound their cosignatures to, so cosign verification needs it.
	NetworkID [32]byte `json:"-"`
}

// WitnessSignature is one cosignature on a tree head (ledger/api/tree.go).
type WitnessSignature struct {
	PubKeyID  string `json:"pub_key_id"`
	SchemeTag uint   `json:"scheme_tag"`
	SigBytes  string `json:"sig_bytes"`
}

// CosignedTreeHead is GET /v1/tree/head (ledger/api/tree.go:47).
type CosignedTreeHead struct {
	RootHash    string             `json:"root_hash"`
	SMTRoot     string             `json:"smt_root"`
	ReceiptRoot string             `json:"receipt_root"`
	TreeSize    uint64             `json:"tree_size"`
	HashAlgo    int                `json:"hash_algo"`
	Signatures  []WitnessSignature `json:"signatures"`
}

// SignedCertificateTimestamp is the 202 from POST /v1/entries (ledger/api/sct.go).
type SignedCertificateTimestamp struct {
	Version       int    `json:"version"`
	SignerDID     string `json:"signer_did"`
	SigAlgoID     int    `json:"sig_algo_id"`
	LogDID        string `json:"log_did"`
	CanonicalHash string `json:"canonical_hash"`
	LogTimeMicros int64  `json:"log_time_micros"`
	LogTime       string `json:"log_time"`
	Signature     string `json:"signature"`
}

// EntryResponse is GET /v1/entries/{seq} or /v1/entries-hash/{h}
// (ledger/api/queries.go). State == "pending" before sequencing.
type EntryResponse struct {
	SequenceNumber  uint64 `json:"sequence_number"`
	CanonicalHash   string `json:"canonical_hash"`
	LogTime         string `json:"log_time"`
	SignerDID       string `json:"signer_did"`
	ProtocolVersion int    `json:"protocol_version"`
	State           string `json:"state"`
}

// SignedEvent is one gossip event from /v1/gossip/since (auditor store.go /
// the SDK gossip feed). Bindings/Body stay raw; the body schema is per-Kind.
// NOTE: confirm field casing against the live feed when wiring S3.2 / S6.3.
type SignedEvent struct {
	Originator  string          `json:"originator"`
	Kind        string          `json:"kind"`
	LamportTime uint64          `json:"lamport_time"`
	PrevHash    string          `json:"prev_hash"`
	Bindings    json.RawMessage `json:"bindings"`
	Body        json.RawMessage `json:"body"`
}

/*
FILE PATH: verification/authority_fakes_test.go

Shared in-memory test doubles for the verification package's authority/gate
tests: a position-keyed entry fetcher and an OriginTip leaf reader. Relocated
here from the retired authority_resolver_*_test.go so the SMT gate tests
(smt_authority_test.go) keep them after the legacy resolver is deleted.
*/
package verification

import (
	"context"

	"github.com/baseproof/baseproof/types"
)

// ─── fakeFetcher: position-keyed entry store ────────────────────────

type fakeFetcher struct {
	entries map[string][]byte // keyed by "logDID|seq" → canonical bytes
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{entries: make(map[string][]byte)}
}

func (f *fakeFetcher) put(pos types.LogPosition, canonical []byte) {
	f.entries[posKey(pos)] = canonical
}

func (f *fakeFetcher) Fetch(ctx context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	by, ok := f.entries[posKey(pos)]
	if !ok {
		return nil, nil
	}
	return &types.EntryWithMetadata{CanonicalBytes: by}, nil
}

func posKey(pos types.LogPosition) string {
	return pos.LogDID + "|" + intToStr(pos.Sequence)
}

func intToStr(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ─── fakeLeafReader: synthetic OriginTip oracle ─────────────────────

type fakeLeafReader struct {
	originTipFor map[[32]byte]types.LogPosition
}

func (f *fakeLeafReader) Get(ctx context.Context, key [32]byte) (*types.SMTLeaf, error) {
	tip, ok := f.originTipFor[key]
	if !ok {
		return nil, nil
	}
	return &types.SMTLeaf{OriginTip: tip}, nil
}

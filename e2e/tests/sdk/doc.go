// Package sdk holds the e2e suite's SDK-tier captures (S6.16–S6.21, S5.17): the
// equivocation + witness-rotation use cases, exercised under the e2e build tag so
// `make test` reports them. The genuinely-offline math lives in the sibling
// packages tests/sdk/equivocation and tests/sdk/rotation (plain `go test`).
package sdk

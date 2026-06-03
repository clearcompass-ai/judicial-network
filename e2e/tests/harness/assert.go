//go:build e2e

package harness

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
)

// Itoa is strconv.Itoa, re-exported so phase tests share one int→string helper.
func Itoa(n int) string { return strconv.Itoa(n) }

// ErrStr renders an error for assertion messages ("<nil>" when nil).
func ErrStr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// eq fails the scenario (non-fatal) unless got == want.
func Eq[T comparable](t *testing.T, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

// Truthy fails the scenario (non-fatal) unless cond holds.
func Truthy(t *testing.T, cond bool, msg string) {
	t.Helper()
	if !cond {
		t.Error(msg)
	}
}

// NonEmpty fails the scenario (non-fatal) unless s is non-empty.
func NonEmpty(t *testing.T, s, what string) {
	t.Helper()
	if s == "" {
		t.Errorf("%s: empty", what)
	}
}

// HasKey fails unless m contains key (presence, distinct from empty value —
// e.g. the receipt_root PR #92 guard).
func HasKey(t *testing.T, m map[string]any, key, what string) {
	t.Helper()
	if _, ok := m[key]; !ok {
		t.Errorf("%s: missing key %q", what, key)
	}
}

// ValidJSON fails unless b parses as JSON.
func ValidJSON(t *testing.T, b []byte, what string) {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Errorf("%s: not valid JSON: %v", what, err)
	}
}

// StatusIn fails unless code is one of allowed.
func StatusIn(t *testing.T, code int, what string, allowed ...int) {
	t.Helper()
	for _, a := range allowed {
		if code == a {
			return
		}
	}
	t.Errorf("%s: status %d not in %v", what, code, allowed)
}

// SurfaceOK fails when a JN route is missing (404) or crashes (>=500) — the
// "route wired + input validated, not panicking" contract for the JN surface
// scenarios (S5.6, S5.8–5.13).
func SurfaceOK(t *testing.T, code int, what string) {
	t.Helper()
	if code == 404 {
		t.Errorf("%s: route not found (404)", what)
	}
	if code >= 500 {
		t.Errorf("%s: server error (%d) — input not validated?", what, code)
	}
}

// contains reports whether b contains sub (substring match on the raw body).
func Contains(b []byte, sub string) bool { return bytes.Contains(b, []byte(sub)) }
